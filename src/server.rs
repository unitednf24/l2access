use anyhow::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::auth;
use crate::crypto;
use crate::net;
use crate::protocol::*;
use crate::stats::Stats;
use crate::tunnel;

const DISCOVERY_INTERVAL: Duration = Duration::from_secs(5);

pub fn run(iface_name: &str, subnet: crate::protocol::Subnet) -> Result<()> {
    let iface = net::find_interface(iface_name)?;
    let our_mac = net::iface_mac(&iface)?;

    let (server_secret, server_pubkey) = crypto::generate_keypair();
    let server_secret = Arc::new(server_secret);

    let hostname = hostname()?;
    println!(
        "L2Access server  iface={}  mac={}  v{}",
        iface_name,
        mac_str(&our_mac),
        APP_VERSION
    );
    println!("Hostname: {}  subnet: {}", hostname, subnet);
    crate::vlog!("Server pubkey: {}", hex(&server_pubkey));

    let (raw_tx, raw_rx) = net::open_channel(&iface)?;
    let tx = Arc::new(Mutex::new(raw_tx));
    let rx = Arc::new(Mutex::new(raw_rx));
    let stop = Arc::new(AtomicBool::new(false));

    {
        let stop2 = Arc::clone(&stop);
        let _ = ctrlc::set_handler(move || {
            stop2.store(true, Ordering::Relaxed);
        });
    }

    // Discovery broadcast thread
    {
        let tx2 = Arc::clone(&tx);
        let stop2 = Arc::clone(&stop);
        let subnet_cidr = subnet.cidr();
        let discovery_payload =
            build_discovery(&hostname, APP_VERSION, &server_pubkey, &subnet_cidr);
        let our_mac2 = our_mac;
        std::thread::spawn(move || {
            let mut last = Instant::now() - DISCOVERY_INTERVAL;
            loop {
                if stop2.load(Ordering::Relaxed) {
                    break;
                }
                if last.elapsed() >= DISCOVERY_INTERVAL {
                    let frame = build_eth_frame(&DISCOVERY_MAC, &our_mac2, &discovery_payload);
                    crate::vlog!("discovery: broadcasting ({} bytes)", frame.len());
                    let _ = tx2.lock().unwrap().send_to(&frame, None);
                    last = Instant::now();
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
    }

    println!("Broadcasting discovery. Waiting for clients...");
    println!("Local tunnel IP will be: {}", subnet.mac_to_ip(&our_mac));

    loop {
        if stop.load(Ordering::Relaxed) {
            println!("\nServer shutting down.");
            break;
        }

        let raw = {
            let mut guard = rx.lock().unwrap();
            match guard.next() {
                Ok(f) => f.to_vec(),
                Err(_) => continue,
            }
        };

        let (_dst, src_mac, payload) = match parse_eth_frame(&raw) {
            Some(f) => f,
            None => continue,
        };

        crate::vlog!(
            "rx: {} bytes from {} (our EtherType matched)",
            raw.len(),
            mac_str(&src_mac)
        );

        let pkt = match parse_l2a_payload(payload) {
            Some(p) => p,
            None => {
                crate::vlog!("rx: L2A parse failed — ignoring");
                continue;
            }
        };

        if let L2APacket::Connect(conn) = pkt {
            println!("\nConnection request from {}", mac_str(&src_mac));
            match handle_connection(
                conn,
                src_mac,
                our_mac,
                subnet,
                &server_secret,
                Arc::clone(&tx),
                Arc::clone(&rx),
                Arc::clone(&stop),
            ) {
                Ok(()) => println!("Client disconnected."),
                Err(e) => eprintln!("Connection error: {}", e),
            }
            println!("Waiting for next client...");
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_connection(
    conn: crate::protocol::ConnectData,
    peer_mac: [u8; 6],
    our_mac: [u8; 6],
    subnet: crate::protocol::Subnet,
    server_secret: &x25519_dalek::StaticSecret,
    tx: Arc<Mutex<Box<dyn pnet::datalink::DataLinkSender>>>,
    rx: Arc<Mutex<Box<dyn pnet::datalink::DataLinkReceiver>>>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    crate::vlog!(
        "handle_connection: client_pubkey={}",
        hex(&conn.client_pubkey)
    );

    let shared = crypto::diffie_hellman(server_secret, &conn.client_pubkey);
    let auth_key = crypto::derive_key(&shared, b"l2access-auth-v1");
    crate::vlog!("DH shared secret derived");

    let plaintext = crypto::decrypt(&auth_key, &conn.nonce, &conn.encrypted_credentials)
        .map_err(|e| {
            crate::vlog!("credential decrypt failed: {}", e);
            e
        })
        .map_err(|_| anyhow::anyhow!("Failed to decrypt credentials"))?;

    let (username, password) = auth::decode_credentials(&plaintext)?;
    println!("Authenticating user '{}'...", username);
    crate::vlog!("credentials decoded, verifying...");

    if let Err(e) = auth::verify_credentials(&username, &password) {
        eprintln!("Auth failed for '{}': {}", username, e);
        let frame = build_eth_frame(&peer_mac, &our_mac, &build_auth_fail(0x01));
        let _ = tx.lock().unwrap().send_to(&frame, None);
        return Ok(());
    }

    println!("Authentication succeeded for '{}'.", username);

    let session_key = crypto::random_key();
    let nonce = crypto::random_nonce();
    let encrypted_key = crypto::encrypt(&auth_key, &nonce, &session_key)?;
    crate::vlog!("sending AuthOk with session key");

    let frame = build_eth_frame(&peer_mac, &our_mac, &build_auth_ok(&nonce, &encrypted_key));
    tx.lock().unwrap().send_to(&frame, None);

    let our_ip = subnet.mac_to_ip(&our_mac);
    let peer_ip = subnet.mac_to_ip(&peer_mac);
    println!(
        "Tunnel: local={} remote={} subnet={}",
        our_ip, peer_ip, subnet
    );
    crate::vlog!(
        "local mac={} peer mac={}",
        mac_str(&our_mac),
        mac_str(&peer_mac)
    );

    let tun_dev = tunnel::create_tun(our_ip, subnet.netmask(), &subnet)?;
    let stats = Arc::new(Stats::default());

    if crate::VERBOSE.load(std::sync::atomic::Ordering::Relaxed) {
        // Small delay so the TUN route is visible in `ip route show`
        std::thread::sleep(std::time::Duration::from_millis(100));
        print_routes(our_ip);
    }

    let session_stop = Arc::new(AtomicBool::new(false));
    let s_stop2 = Arc::clone(&session_stop);
    let g_stop = Arc::clone(&stop);
    std::thread::spawn(move || {
        while !s_stop2.load(Ordering::Relaxed) {
            if g_stop.load(Ordering::Relaxed) {
                s_stop2.store(true, Ordering::Relaxed);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    });

    tunnel::run_tunnel(
        tun_dev,
        tx,
        rx,
        session_key,
        our_mac,
        peer_mac,
        stats,
        session_stop,
    );
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

/// Print the current routing table to stderr (verbose only).
fn print_routes(tun_ip: std::net::Ipv4Addr) {
    crate::vlog!("TUN IP: {}", tun_ip);
    if let Ok(out) = std::process::Command::new("ip")
        .args(["route", "show"])
        .output()
    {
        crate::vlog!(
            "routes:\n{}",
            String::from_utf8_lossy(&out.stdout).trim_end()
        );
    }
    if let Ok(out) = std::process::Command::new("ip")
        .args(["addr", "show"])
        .output()
    {
        crate::vlog!(
            "interfaces:\n{}",
            String::from_utf8_lossy(&out.stdout).trim_end()
        );
    }
}
