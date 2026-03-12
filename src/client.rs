use anyhow::{bail, Result};
use crossterm::{
    cursor,
    event::{poll, read, Event, KeyCode, KeyEvent, KeyModifiers},
    execute, queue,
    style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor},
    terminal::{
        disable_raw_mode, enable_raw_mode, Clear, ClearType, EnterAlternateScreen,
        LeaveAlternateScreen,
    },
};
use std::io::{self, Stdout, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::crypto;
use crate::net;
use crate::protocol::*;
use crate::stats::Stats;
use crate::tunnel;

#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub mac: [u8; 6],
    pub hostname: String,
    pub version: String,
    pub pubkey: [u8; 32],
    pub subnet_cidr: String,
}

pub fn run(iface_name: &str, subnet: crate::protocol::Subnet) -> Result<()> {
    let iface = net::find_interface(iface_name)?;
    let our_mac = net::iface_mac(&iface)?;

    // ── Phase 1: TUI discovery + selection ────────────────────────────────
    // The discovery thread opens its own channel; the main channel is opened
    // afterwards for auth and tunnel, avoiding any receiver contention.
    let server = discover_and_select(iface_name, our_mac)?;

    println!(
        "Connecting to {} ({})...",
        server.hostname,
        mac_str(&server.mac)
    );
    if !server.subnet_cidr.is_empty() {
        println!("Server advertises subnet: {}", server.subnet_cidr);
    }
    let negotiated_subnet = if server.subnet_cidr.is_empty() {
        subnet
    } else {
        match crate::protocol::Subnet::parse(&server.subnet_cidr) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "Warning: Server provided invalid subnet {}, falling back to local default",
                    e
                );
                subnet
            }
        }
    };

    // Open main channel now (after the TUI exits)
    let (raw_tx, raw_rx) = net::open_channel(&iface)?;
    let tx = Arc::new(Mutex::new(raw_tx));
    let rx = Arc::new(Mutex::new(raw_rx));

    // ── Phase 2: Authentication ────────────────────────────────────────────
    let (username, password) = prompt_credentials(&server.hostname)?;

    let (client_secret, client_pubkey) = crypto::generate_keypair();
    crate::vlog!("client pubkey: {}", hex(&client_pubkey));
    crate::vlog!("server pubkey: {}", hex(&server.pubkey));

    let shared = crypto::diffie_hellman(&client_secret, &server.pubkey);
    let auth_key = crypto::derive_key(&shared, b"l2access-auth-v1");
    crate::vlog!("DH shared secret derived");

    let creds = crate::auth::encode_credentials(&username, &password);
    let nonce = crypto::random_nonce();
    let encrypted_creds = crypto::encrypt(&auth_key, &nonce, &creds)?;

    let connect_payload = build_connect(&client_pubkey, &nonce, &encrypted_creds);
    let frame = build_eth_frame(&server.mac, &our_mac, &connect_payload);
    crate::vlog!(
        "sending Connect frame ({} bytes) to {}",
        frame.len(),
        mac_str(&server.mac)
    );
    tx.lock().unwrap().send_to(&frame, None);

    // ── Phase 3: Wait for auth result ─────────────────────────────────────
    let session_key = wait_for_auth(Arc::clone(&rx), &server.mac, &auth_key)?;

    // ── Phase 4: Tunnel ────────────────────────────────────────────────────
    let our_ip = negotiated_subnet.mac_to_ip(&our_mac);
    let peer_ip = negotiated_subnet.mac_to_ip(&server.mac);
    println!(
        "Tunnel: local={} remote={} subnet={}",
        our_ip, peer_ip, negotiated_subnet
    );
    crate::vlog!(
        "our mac={} peer mac={}",
        mac_str(&our_mac),
        mac_str(&server.mac)
    );
    let tun_dev = tunnel::create_tun(our_ip, negotiated_subnet.netmask(), &negotiated_subnet)?;

    if crate::VERBOSE.load(std::sync::atomic::Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(200));
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

    let stats = Arc::new(Stats::default());
    let stop = Arc::new(AtomicBool::new(false));

    {
        let stop2 = Arc::clone(&stop);
        let tx2 = Arc::clone(&tx);
        let our_mac2 = our_mac;
        let peer_mac = server.mac;
        let _ = ctrlc::set_handler(move || {
            stop2.store(true, Ordering::Relaxed);
            let disc = build_disconnect();
            let frame = build_eth_frame(&peer_mac, &our_mac2, &disc);
            let _ = tx2.lock().unwrap().send_to(&frame, None);
        });
    }

    {
        let stats2 = Arc::clone(&stats);
        let stop2 = Arc::clone(&stop);
        std::thread::spawn(move || {
            crate::stats::display_loop(stats2, peer_ip, stop2);
        });
    }

    tunnel::run_tunnel(
        tun_dev,
        tx,
        rx,
        session_key,
        our_mac,
        server.mac,
        stats,
        stop,
    );

    println!("Disconnected.");
    Ok(())
}

// ── TUI discovery + selection ─────────────────────────────────────────────────

fn discover_and_select(iface_name: &str, our_mac: [u8; 6]) -> Result<ServerInfo> {
    let iface = net::find_interface(iface_name)?;

    // The background thread opens its OWN dedicated channel so it has exclusive,
    // lock-free access to the receiver.  Two AF_PACKET sockets on the same
    // interface both receive all frames independently.
    let (_, disc_rx) = net::open_channel_discovery(&iface)?;

    let servers = Arc::new(Mutex::new(Vec::<ServerInfo>::new()));
    let servers_bg = Arc::clone(&servers);
    let stop_bg = Arc::new(AtomicBool::new(false));
    let stop_bg2 = Arc::clone(&stop_bg);

    // Background thread: owns disc_rx exclusively — no mutex on the receiver.
    std::thread::spawn(move || {
        let mut rx = disc_rx;
        loop {
            if stop_bg2.load(Ordering::Relaxed) {
                break;
            }
            let raw = match rx.next() {
                Ok(f) => f.to_vec(),
                Err(_) => continue, // 1 s timeout or transient error
            };
            let (_dst, src_mac, payload) = match parse_eth_frame(&raw) {
                Some(f) => f,
                None => continue,
            };
            if src_mac == our_mac {
                continue; // skip our own reflections
            }
            if let Some(L2APacket::Discovery(d)) = parse_l2a_payload(payload) {
                let mut list = servers_bg.lock().unwrap();
                if let Some(s) = list.iter_mut().find(|s| s.mac == src_mac) {
                    s.hostname = d.hostname;
                    s.version = d.version;
                    s.pubkey = d.server_pubkey;
                    s.subnet_cidr = d.subnet_cidr;
                } else {
                    list.push(ServerInfo {
                        mac: src_mac,
                        hostname: d.hostname,
                        version: d.version,
                        pubkey: d.server_pubkey,
                        subnet_cidr: d.subnet_cidr,
                    });
                }
            }
        }
    });

    let mut stdout = io::stdout();
    enable_raw_mode()?;
    execute!(stdout, EnterAlternateScreen, cursor::Hide)?;

    let mut selected = 0usize;
    let result = tui_loop(&mut stdout, &servers, &mut selected, iface_name);

    // Always restore terminal before returning
    let _ = execute!(stdout, cursor::Show, LeaveAlternateScreen);
    let _ = disable_raw_mode();
    stop_bg.store(true, Ordering::Relaxed);

    result
}

fn tui_loop(
    stdout: &mut Stdout,
    servers: &Arc<Mutex<Vec<ServerInfo>>>,
    selected: &mut usize,
    iface_name: &str,
) -> Result<ServerInfo> {
    loop {
        render(stdout, servers, *selected, iface_name)?;

        // poll with a short timeout so the list refreshes even with no input
        if !poll(Duration::from_millis(200))? {
            continue;
        }

        match read()? {
            Event::Key(KeyEvent {
                code: KeyCode::Up, ..
            }) => {
                if *selected > 0 {
                    *selected -= 1;
                }
            }
            Event::Key(KeyEvent {
                code: KeyCode::Down,
                ..
            }) => {
                let len = servers.lock().unwrap().len();
                if *selected + 1 < len {
                    *selected += 1;
                }
            }
            Event::Key(KeyEvent {
                code: KeyCode::Enter,
                ..
            }) => {
                let list = servers.lock().unwrap();
                if *selected < list.len() {
                    return Ok(list[*selected].clone());
                }
            }
            Event::Key(KeyEvent {
                code: KeyCode::Char('q'),
                ..
            })
            | Event::Key(KeyEvent {
                code: KeyCode::Esc, ..
            }) => {
                bail!("Cancelled");
            }
            Event::Key(KeyEvent {
                code: KeyCode::Char('c'),
                modifiers,
                ..
            }) if modifiers.contains(KeyModifiers::CONTROL) => {
                bail!("Interrupted");
            }
            _ => {}
        }
    }
}

fn render(
    stdout: &mut Stdout,
    servers: &Arc<Mutex<Vec<ServerInfo>>>,
    selected: usize,
    iface_name: &str,
) -> Result<()> {
    let list = servers.lock().unwrap().clone();

    queue!(stdout, cursor::MoveTo(0, 0), Clear(ClearType::All))?;

    // ── Header ─────────────────────────────────────────────────────────────
    queue!(
        stdout,
        SetAttribute(Attribute::Bold),
        SetForegroundColor(Color::Cyan),
        Print("  L2Access"),
        ResetColor,
        Print(format!(
            "  —  interface: {}  —  discovering...\r\n",
            iface_name
        )),
        Print(format!("  {}\r\n\r\n", "─".repeat(60))),
    )?;

    // ── Server list ────────────────────────────────────────────────────────
    if list.is_empty() {
        queue!(
            stdout,
            SetForegroundColor(Color::DarkGrey),
            Print("  No servers found yet. Waiting for broadcasts...\r\n"),
            ResetColor,
        )?;
    } else {
        queue!(
            stdout,
            SetAttribute(Attribute::Dim),
            Print(format!(
                "  {:<3}  {:<22}  {:<19}  {:<18}  {}\r\n",
                "#", "Hostname", "MAC", "Subnet", "Version"
            )),
            ResetColor,
        )?;

        for (i, s) in list.iter().enumerate() {
            if i == selected {
                queue!(
                    stdout,
                    SetForegroundColor(Color::Black),
                    crossterm::style::SetBackgroundColor(Color::Cyan),
                    Print(format!(
                        "  {:>2}  {:<22}  {:<19}  {:<18}  {}\r\n",
                        i + 1,
                        s.hostname,
                        mac_str(&s.mac),
                        s.subnet_cidr,
                        s.version
                    )),
                    ResetColor,
                )?;
            } else {
                queue!(
                    stdout,
                    SetForegroundColor(Color::White),
                    Print(format!(
                        "  {:>2}  {:<22}  {:<19}  {:<18}  {}\r\n",
                        i + 1,
                        s.hostname,
                        mac_str(&s.mac),
                        s.subnet_cidr,
                        s.version
                    )),
                    ResetColor,
                )?;
            }
        }
    }

    // ── Footer ─────────────────────────────────────────────────────────────
    queue!(
        stdout,
        Print(format!("\r\n  {}\r\n", "─".repeat(60))),
        SetAttribute(Attribute::Dim),
        Print("  ↑/↓ navigate    Enter select    q quit\r\n"),
        ResetColor,
    )?;

    stdout.flush()?;
    Ok(())
}

// ── Auth helpers ─────────────────────────────────────────────────────────────

fn wait_for_auth(
    rx: Arc<Mutex<Box<dyn pnet::datalink::DataLinkReceiver>>>,
    server_mac: &[u8; 6],
    auth_key: &[u8; 32],
) -> Result<[u8; 32]> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);

    while std::time::Instant::now() < deadline {
        let raw = {
            let mut guard = rx.lock().unwrap();
            match guard.next() {
                Ok(f) => f.to_vec(),
                Err(e)
                    if e.kind() == io::ErrorKind::TimedOut
                        || e.kind() == io::ErrorKind::WouldBlock =>
                {
                    continue
                }
                Err(_) => continue,
            }
        };
        let (_dst, src_mac, payload) = match parse_eth_frame(&raw) {
            Some(f) => f,
            None => continue,
        };
        if &src_mac != server_mac {
            continue;
        }
        match parse_l2a_payload(payload) {
            Some(L2APacket::AuthOk(ok)) => {
                let key_bytes = crypto::decrypt(auth_key, &ok.nonce, &ok.encrypted_session_key)?;
                if key_bytes.len() != 32 {
                    bail!("Invalid session key length");
                }
                let mut session_key = [0u8; 32];
                session_key.copy_from_slice(&key_bytes);
                println!("Authentication successful.");
                return Ok(session_key);
            }
            Some(L2APacket::AuthFail(reason)) => {
                bail!("Authentication rejected (reason: 0x{:02x})", reason);
            }
            _ => {}
        }
    }
    bail!("Authentication timed out")
}

fn prompt_credentials(hostname: &str) -> Result<(String, String)> {
    print!("Username for {}: ", hostname);
    let _ = io::stdout().flush();
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim().to_string();

    let password = prompt_password(&format!("Password for {}@{}: ", username, hostname))?;
    Ok((username, password))
}

fn prompt_password(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    let _ = io::stdout().flush();

    enable_raw_mode()?;
    let mut password = String::new();
    loop {
        match read()? {
            Event::Key(KeyEvent {
                code: KeyCode::Enter,
                ..
            }) => break,
            Event::Key(KeyEvent {
                code: KeyCode::Char('c'),
                modifiers,
                ..
            }) if modifiers.contains(KeyModifiers::CONTROL) => {
                disable_raw_mode()?;
                bail!("Interrupted");
            }
            Event::Key(KeyEvent {
                code: KeyCode::Backspace,
                ..
            }) => {
                password.pop();
            }
            Event::Key(KeyEvent {
                code: KeyCode::Char(c),
                ..
            }) => {
                password.push(c);
            }
            _ => {}
        }
    }
    disable_raw_mode()?;
    println!();
    Ok(password)
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
