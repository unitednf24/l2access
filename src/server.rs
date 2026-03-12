use anyhow::{bail, Result};
use std::collections::{HashMap, HashSet};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::auth;
use crate::crypto;
use crate::net;
use crate::protocol::*;
use crate::tunnel;

const DISCOVERY_INTERVAL: Duration = Duration::from_secs(5);

pub struct PeerSession {
    pub session_key: [u8; 32],
    pub peer_mac: [u8; 6],
    pub our_mac: [u8; 6],
    pub last_kr_rx: Arc<AtomicU64>,
    pub tx: Arc<Mutex<Box<dyn pnet::datalink::DataLinkSender>>>,
}

pub fn run(
    explicit_ifaces: Option<Vec<String>>,
    exclude_list: Vec<String>,
    subnet: crate::protocol::Subnet,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    // 1. Identify primary host details for the unified TUN Server IP address
    let mut initial_binds = Vec::new();
    if let Some(ref explicit) = explicit_ifaces {
        for i in explicit { initial_binds.push(i.clone()); }
    } else {
        for i in pnet::datalink::interfaces() {
            if i.is_up() && !i.is_loopback() && !exclude_list.contains(&i.name) {
                initial_binds.push(i.name.clone());
            }
        }
    }

    if initial_binds.is_empty() {
        bail!("No valid interfaces found for gateway Server!");
    }

    let primary_iface_name = &initial_binds[0];
    let primary_iface = net::find_interface(primary_iface_name)?;
    let our_master_mac = net::iface_mac(&primary_iface)?;
    let server_ip = subnet.mac_to_ip(&our_master_mac);

    let (server_secret, server_pubkey) = crypto::generate_keypair();
    let server_secret = Arc::new(server_secret);
    let hostname_str = hostname()?;

    println!("L2Access Multipath Server Routing Daemon");
    println!("Master Address: {}", server_ip);
    crate::vlog!("Master Server pubkey: {}", hex(&server_pubkey));

    // 2. Initialize the Singleton TUN device `l2access`
    let tun_dev = tunnel::create_tun(server_ip, subnet.netmask(), &subnet)?;
    let tun_fd = tun_dev.as_raw_fd();

    if crate::VERBOSE.load(std::sync::atomic::Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(100));
        print_routes(server_ip);
    }

    // 3. Shared State Map for Multipathing
    let peers: Arc<RwLock<HashMap<std::net::Ipv4Addr, Arc<PeerSession>>>> = 
        Arc::new(RwLock::new(HashMap::new()));
    
    // Track which interfaces have `eth_to_tun` read loops spanning over them natively
    let active_ifaces = Arc::new(Mutex::new(HashSet::new()));

    // 4. `tun_to_eth` background Multiplexer
    {
        let stop_tun = Arc::clone(&stop);
        let peers_tun = Arc::clone(&peers);
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            let mut last_keepalive_sent = 0u64;

            loop {
                if stop_tun.load(Ordering::Relaxed) { break; }

                let mut pfd = libc::pollfd {
                    fd: tun_fd,
                    events: libc::POLLIN,
                    revents: 0,
                };

                let rc = unsafe { libc::poll(&mut pfd, 1, 100) };
                
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

                if now.saturating_sub(last_keepalive_sent) >= 5 {
                    let mut dead = Vec::new();
                    
                    for (ip, peer) in peers_tun.read().unwrap().iter() {
                        if now.saturating_sub(peer.last_kr_rx.load(Ordering::Relaxed)) >= 15 {
                            dead.push(*ip);
                        } else {
                            let frame = build_eth_frame(&peer.peer_mac, &peer.our_mac, &build_keepalive_req());
                            let _ = peer.tx.lock().unwrap().send_to(&frame, None);
                        }
                    }

                    if !dead.is_empty() {
                        let mut w = peers_tun.write().unwrap();
                        for ip in dead {
                            println!("[Multiplexer] Dead connection timeout, cleanly tearing down client IP: {}", ip);
                            w.remove(&ip);
                        }
                    }
                    last_keepalive_sent = now;
                }

                if rc <= 0 { continue; } 

                let n = unsafe { libc::read(tun_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n <= 0 { continue; }
                let packet = &buf[..n as usize];
                if packet.len() >= 20 {
                    let dst_ip = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                    if let Some(peer) = peers_tun.read().unwrap().get(&dst_ip) {
                        let nonce = crypto::random_nonce();
                        if let Ok(ciphertext) = crypto::encrypt(&peer.session_key, &nonce, packet) {
                            let f = build_eth_frame(
                                &peer.peer_mac,
                                &peer.our_mac,
                                &build_tunnel(&nonce, &ciphertext)
                            );
                            let _ = peer.tx.lock().unwrap().send_to(&f, None);
                        }
                    }
                }
            }
        });
    }

    // Function to dynamically spin up a binding natively
    let spawn_interface_listener = |
        iface_name: String, 
        subnet: crate::protocol::Subnet,
        server_secret: Arc<x25519_dalek::StaticSecret>, 
        server_pubkey: [u8; 32], 
        hostname: String,
        stop_eth: Arc<AtomicBool>,
        peers_eth: Arc<RwLock<HashMap<std::net::Ipv4Addr, Arc<PeerSession>>>>
    | {
        std::thread::spawn(move || {
            let iface = match net::find_interface(&iface_name) {
                Ok(i) => i,
                Err(e) => { eprintln!("[{}] Failed: {}", iface_name, e); return; }
            };
            let our_mac = match net::iface_mac(&iface) {
                Ok(m) => m,
                Err(e) => { eprintln!("[{}] Failed MAC: {}", iface_name, e); return; }
            };

            let (raw_tx, mut rx) = match net::open_channel(&iface) {
                Ok(c) => c,
                Err(e) => { eprintln!("[{}] Channel Error: {}", iface_name, e); return; }
            };
            
            println!("Attached MultiPath local listener directly onto native interface {}", iface_name);
            let tx = Arc::new(Mutex::new(raw_tx));

            // Inner specific interface `Discovery` daemon
            {
                let tx2 = Arc::clone(&tx);
                let stop2 = Arc::clone(&stop_eth);
                let s_cidr = subnet.cidr();
                let discovery_payload = build_discovery(&hostname, APP_VERSION, &server_pubkey, &s_cidr);
                std::thread::spawn(move || {
                    let mut last = Instant::now() - DISCOVERY_INTERVAL;
                    loop {
                        if stop2.load(Ordering::Relaxed) { break; }
                        if last.elapsed() >= DISCOVERY_INTERVAL {
                            let frame = build_eth_frame(&DISCOVERY_MAC, &our_mac, &discovery_payload);
                            let _ = tx2.lock().unwrap().send_to(&frame, None);
                            last = Instant::now();
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                });
            }

            loop {
                if stop_eth.load(Ordering::Relaxed) { break; }
                
                let raw = match rx.next() {
                    Ok(r) => r.to_vec(),
                    Err(_) => continue,
                };

                let (_dst, src_mac, payload) = match parse_eth_frame(&raw) {
                    Some(f) => f,
                    None => continue,
                };

                let pkt = match parse_l2a_payload(payload) {
                    Some(p) => p,
                    None => continue,
                };

                let peer_ip = subnet.mac_to_ip(&src_mac);
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

                match pkt {
                    L2APacket::Connect(conn) => {
                        println!("\n[{}] Multipath Connection resolving from {}", iface_name, mac_str(&src_mac));
                        
                        let shared = crypto::diffie_hellman(&server_secret, &conn.client_pubkey);
                        let auth_key = crypto::derive_key(&shared, b"l2access-auth-v1");

                        let plaintext = match crypto::decrypt(&auth_key, &conn.nonce, &conn.encrypted_credentials) {
                            Ok(p) => p,
                            Err(_) => {
                                let f = build_eth_frame(&src_mac, &our_mac, &build_auth_fail(0x01));
                                let _ = tx.lock().unwrap().send_to(&f, None);
                                continue;
                            }
                        };

                        let (username, password) = match auth::decode_credentials(&plaintext) {
                            Ok(c) => c,
                            Err(_) => {
                                let f = build_eth_frame(&src_mac, &our_mac, &build_auth_fail(0x01));
                                let _ = tx.lock().unwrap().send_to(&f, None);
                                continue;
                            }
                        };

                        if let Err(e) = auth::verify_credentials(&username, &password) {
                            eprintln!("[{}] Auth failed for '{}': {}", iface_name, username, e);
                            let f = build_eth_frame(&src_mac, &our_mac, &build_auth_fail(0x01));
                            let _ = tx.lock().unwrap().send_to(&f, None);
                            continue;
                        }

                        println!("[{}] Validated seamlessly! Tunneling {} to unified IP {}", iface_name, username, peer_ip);

                        let session_key = crypto::random_key();
                        let nonce = crypto::random_nonce();
                        if let Ok(encrypted_key) = crypto::encrypt(&auth_key, &nonce, &session_key) {
                            let f = build_eth_frame(&src_mac, &our_mac, &build_auth_ok(&nonce, &encrypted_key));
                            let _ = tx.lock().unwrap().send_to(&f, None);
                            
                            let session = PeerSession {
                                session_key,
                                peer_mac: src_mac,
                                our_mac,
                                last_kr_rx: Arc::new(AtomicU64::new(now)),
                                tx: Arc::clone(&tx),
                            };
                            peers_eth.write().unwrap().insert(peer_ip, Arc::new(session));
                        }
                    }
                    L2APacket::Tunnel(t) => {
                        let valid_decrypted = {
                            let peers_map = peers_eth.read().unwrap();
                            if let Some(peer) = peers_map.get(&peer_ip) {
                                peer.last_kr_rx.store(now, Ordering::Relaxed);
                                match crypto::decrypt(&peer.session_key, &t.nonce, &t.ciphertext) {
                                    Ok(dec) => Some(dec),
                                    Err(_) => None,
                                }
                            } else { None }
                        };

                        if let Some(dec) = valid_decrypted {
                            unsafe { libc::write(tun_fd, dec.as_ptr() as *const libc::c_void, dec.len()) };
                        }
                    }
                    L2APacket::KeepaliveReq => {
                        if let Some(peer) = peers_eth.read().unwrap().get(&peer_ip) {
                            peer.last_kr_rx.store(now, Ordering::Relaxed);
                            let f = build_eth_frame(&src_mac, &our_mac, &build_keepalive_rep());
                            let _ = tx.lock().unwrap().send_to(&f, None);
                        }
                    }
                    L2APacket::KeepaliveRep => {
                        if let Some(peer) = peers_eth.read().unwrap().get(&peer_ip) {
                            peer.last_kr_rx.store(now, Ordering::Relaxed);
                        }
                    }
                    L2APacket::Disconnect => {
                        println!("\n[{}] Multipath Client physically disconnected: {}", iface_name, peer_ip);
                        peers_eth.write().unwrap().remove(&peer_ip);
                    }
                    _ => {}
                }
            }
        });
    };

    println!("Awaiting authentications securely...");
    for i in initial_binds {
        active_ifaces.lock().unwrap().insert(i.clone());
        spawn_interface_listener(
            i, 
            subnet.clone(), 
            Arc::clone(&server_secret), 
            server_pubkey, 
            hostname_str.clone(), 
            Arc::clone(&stop), 
            Arc::clone(&peers)
        );
    }

    if explicit_ifaces.is_none() {
        loop {
            if stop.load(Ordering::Relaxed) { break; }
            for i in pnet::datalink::interfaces() {
                if i.is_up() && !i.is_loopback() && !exclude_list.contains(&i.name) {
                    let mut ai = active_ifaces.lock().unwrap();
                    if !ai.contains(&i.name) {
                        println!("[Hot-Plug] Discovered new active physical interface natively: {}", i.name);
                        ai.insert(i.name.clone());
                        spawn_interface_listener(
                            i.name.clone(), 
                            subnet.clone(), 
                            Arc::clone(&server_secret), 
                            server_pubkey, 
                            hostname_str.clone(), 
                            Arc::clone(&stop), 
                            Arc::clone(&peers)
                        );
                    }
                }
            }
            
            for _ in 0..50 {
                if stop.load(Ordering::Relaxed) { break; }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    } else {
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    Ok(())
}

fn hostname() -> Result<String> {
    Ok(std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string())
}

fn mac_str(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn hex(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{:02x}", x))
        .collect::<Vec<_>>()
        .join("")
}

fn print_routes(tun_ip: std::net::Ipv4Addr) {
    crate::vlog!("TUN IP: {}", tun_ip);
    if let Ok(out) = std::process::Command::new("ip").args(["route", "show"]).output() {
        crate::vlog!("routes:\n{}", String::from_utf8_lossy(&out.stdout).trim_end());
    }
    if let Ok(out) = std::process::Command::new("ip").args(["addr", "show"]).output() {
        crate::vlog!("interfaces:\n{}", String::from_utf8_lossy(&out.stdout).trim_end());
    }
}
