/// TUN interface creation and bidirectional encrypted forwarding.
use anyhow::Result;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tun::Device as _; // brings .name() into scope

use crate::crypto;
use crate::protocol::{
    build_eth_frame, build_tunnel, parse_eth_frame, parse_l2a_payload, L2APacket,
};
use crate::stats::Stats;

pub const TUN_MTU: u32 = 1400;

/// Create a TUN device and install an explicit route so tunnel traffic is
/// preferred over any pre-existing route for the same subnet.
pub fn create_tun(
    local_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    subnet: &crate::protocol::Subnet,
) -> Result<tun::platform::Device> {
    let mut config = tun::Configuration::default();
    config
        .address(local_ip)
        .netmask(netmask)
        .mtu(TUN_MTU as i32)
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|c| {
        c.packet_information(false);
    });

    let dev = tun::create(&config).map_err(|e| anyhow::anyhow!("TUN create failed: {}", e))?;

    crate::vlog!(
        "TUN created: addr={} netmask={} mtu={}",
        local_ip,
        netmask,
        TUN_MTU
    );

    // Explicitly (re)install the subnet route via the new TUN interface.
    // This overrides any stale or lower-priority route for the same range
    // (e.g. an existing 169.254.0.0/16 route on the physical interface).
    install_route(&dev, subnet);

    Ok(dev)
}

fn install_route(dev: &tun::platform::Device, subnet: &crate::protocol::Subnet) {
    let cidr = subnet.cidr();
    let name = match dev.name() {
        Ok(n) => n,
        Err(e) => {
            crate::vlog!("could not get TUN name: {}", e);
            return;
        }
    };
    // `ip route replace` atomically replaces any existing route for this prefix.
    crate::vlog!("running: ip route replace {} dev {} metric 0", cidr, name);
    match std::process::Command::new("ip")
        .args(["route", "replace", &cidr, "dev", &name, "metric", "0"])
        .status()
    {
        Ok(s) if s.success() => crate::vlog!("route {} via {} installed", cidr, name),
        Ok(s) => crate::vlog!("ip route replace exited with {}", s),
        Err(e) => crate::vlog!("ip route replace failed: {}", e),
    }
}

/// Forward traffic between a TUN device and the raw Ethernet channel.
///
/// Spawns two threads:
///   1. TUN → Ethernet (encrypt + send)
///   2. Ethernet → TUN (receive + decrypt)
///
/// Blocks until `stop` is signalled or both threads exit.
#[allow(clippy::too_many_arguments)]
pub fn run_tunnel(
    tun_dev: tun::platform::Device,
    tx: Arc<Mutex<Box<dyn pnet::datalink::DataLinkSender>>>,
    rx: Arc<Mutex<Box<dyn pnet::datalink::DataLinkReceiver>>>,
    session_key: [u8; 32],
    our_mac: [u8; 6],
    peer_mac: [u8; 6],
    stats: Arc<Stats>,
    stop: Arc<AtomicBool>,
) {
    use std::thread;

    crate::vlog!(
        "Tunnel starting: our_mac={} peer_mac={}",
        mac_str(&our_mac),
        mac_str(&peer_mac)
    );

    let tun_fd = tun_dev.as_raw_fd();
    // We don't need a Mutex anymore! We can just drop tun_dev wrapper or keep it alive.
    // However tun_dev drops that interface if we let it, so we must keep it alive or pass ownership to a thread.
    // Let's pass Arc<Device> so both threads keep it alive.
    let tun_arc = Arc::new(tun_dev);
    let tun_rx = Arc::clone(&tun_arc);

    let stats_tx = Arc::clone(&stats);
    let stop_tx = Arc::clone(&stop);
    let tx_clone = Arc::clone(&tx);
    let key_tx = session_key;

    // ── Thread 1: TUN → Ethernet ──────────────────────────────────────────
    let tun_to_eth = thread::spawn(move || {
        let mut buf = vec![0u8; (TUN_MTU + 200) as usize];
        crate::vlog!("tun→eth thread started");
        loop {
            if stop_tx.load(Ordering::Relaxed) {
                crate::vlog!("tun→eth: stop signalled, exiting");
                break;
            }

            let mut pfd = libc::pollfd {
                fd: tun_fd,
                events: libc::POLLIN,
                revents: 0,
            };

            let rc = unsafe { libc::poll(&mut pfd, 1, 100) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue; // EINTR
                }
                crate::vlog!("tun→eth: poll error: {} — exiting", err);
                break;
            }
            if rc == 0 {
                // Timeout
                continue;
            }

            let n = unsafe { libc::read(tun_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::Interrupted
                {
                    continue;
                }
                crate::vlog!("tun→eth: TUN read error: {} — continuing", err);
                continue;
            }
            if n == 0 {
                // EOF? Shouldn't happen.
                thread::yield_now();
                continue;
            }
            let n = n as usize;

            crate::vlog!("tun→eth: read {} bytes from TUN", n);

            let nonce = crypto::random_nonce();
            let ciphertext = match crypto::encrypt(&key_tx, &nonce, &buf[..n]) {
                Ok(ct) => ct,
                Err(e) => {
                    crate::vlog!("tun→eth: encrypt error: {}", e);
                    continue;
                }
            };

            let payload = build_tunnel(&nonce, &ciphertext);
            let frame = build_eth_frame(&peer_mac, &our_mac, &payload);

            crate::vlog!(
                "tun→eth: sending eth frame {} bytes (payload {} bytes)",
                frame.len(),
                n
            );

            let _ = tx_clone.lock().unwrap().send_to(&frame, None);
            stats_tx.add_tx(n as u64);
        }
        crate::vlog!("tun→eth thread exited");
    });

    let stats_rx = Arc::clone(&stats);
    let stop_rx = Arc::clone(&stop);
    let key_rx = session_key;
    let our_mac_rx = our_mac;

    // ── Thread 2: Ethernet → TUN ──────────────────────────────────────────
    let eth_to_tun = thread::spawn(move || {
        crate::vlog!("eth→tun thread started");
        loop {
            if stop_rx.load(Ordering::Relaxed) {
                crate::vlog!("eth→tun: stop signalled, exiting");
                break;
            }

            let raw = {
                let mut guard = rx.lock().unwrap();
                match guard.next() {
                    Ok(f) => f.to_vec(),
                    // 100 ms read-timeout fires as WouldBlock or TimedOut — keep looping
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut =>
                    {
                        continue
                    }
                    Err(e) => {
                        crate::vlog!("eth→tun: rx error: {} — continuing", e);
                        continue;
                    }
                }
            };

            let (dst, src, payload) = match parse_eth_frame(&raw) {
                Some(f) => f,
                None => continue,
            };

            // Accept only unicast frames from our peer addressed to us
            if src != peer_mac {
                crate::vlog!(
                    "eth→tun: skipping frame from {} (expected {})",
                    mac_str(&src),
                    mac_str(&peer_mac)
                );
                continue;
            }
            if dst != our_mac_rx {
                crate::vlog!(
                    "eth→tun: skipping frame to {} (expected {})",
                    mac_str(&dst),
                    mac_str(&our_mac_rx)
                );
                continue;
            }

            let pkt = match parse_l2a_payload(payload) {
                Some(p) => p,
                None => {
                    crate::vlog!("eth→tun: frame from peer has unrecognised L2A payload");
                    continue;
                }
            };

            match pkt {
                L2APacket::Tunnel(t) => {
                    crate::vlog!(
                        "eth→tun: received tunnel frame, ciphertext {} bytes",
                        t.ciphertext.len()
                    );
                    let ip_pkt = match crypto::decrypt(&key_rx, &t.nonce, &t.ciphertext) {
                        Ok(p) => p,
                        Err(e) => {
                            crate::vlog!("eth→tun: decrypt error: {}", e);
                            continue;
                        }
                    };
                    let n = ip_pkt.len();
                    crate::vlog!("eth→tun: writing {} bytes to TUN", n);
                    let fd = tun_rx.as_raw_fd();
                    let written = unsafe {
                        libc::write(fd, ip_pkt.as_ptr() as *const libc::c_void, ip_pkt.len())
                    };
                    if written < 0 {
                        crate::vlog!("eth→tun: TUN write error: {}", io::Error::last_os_error());
                    }
                    stats_rx.add_rx(n as u64);
                }
                L2APacket::Disconnect => {
                    crate::vlog!("eth→tun: received Disconnect from peer");
                    stop_rx.store(true, Ordering::Relaxed);
                    break;
                }
                other => {
                    crate::vlog!(
                        "eth→tun: unexpected packet type from peer: {:?}",
                        std::mem::discriminant(&other)
                    );
                }
            }
        }
        crate::vlog!("eth→tun thread exited");
    });

    let _ = tun_to_eth.join();
    let _ = eth_to_tun.join();
    crate::vlog!("run_tunnel returned");
}

fn mac_str(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
