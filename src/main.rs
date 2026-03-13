mod auth;
mod client;
mod crypto;
mod net;
mod protocol;
mod server;
mod stats;
mod tunnel;

use anyhow::Result;
use clap::{Parser, Subcommand};
use protocol::Subnet;
use std::sync::atomic::AtomicBool;

/// Set to true at startup when `-v` is passed; read by `vlog!` everywhere.
pub static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Print a dimmed debug line to stderr when verbose mode is active.
#[macro_export]
macro_rules! vlog {
    ($($arg:tt)*) => {
        if $crate::VERBOSE.load(::std::sync::atomic::Ordering::Relaxed) {
            eprintln!("\x1b[2m[v] {}\x1b[0m", format!($($arg)*));
        }
    };
}

#[derive(Parser)]
#[command(name = "l2access", about = "Secure L2-tunnelled IP connectivity")]
struct Cli {
    /// Enable verbose debug output on stderr
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run as server: broadcast discovery and accept connections
    Server {
        /// Network interface(s) to use (comma-separated). If omitted, binds to all active interfaces.
        #[arg(short, long)]
        iface: Option<String>,

        /// Network interface(s) to exclude if binding to all interfaces.
        #[arg(short = 'x', long, value_delimiter = ',')]
        exclude_iface: Option<Vec<String>>,

        /// Subnet for tunnel IPs in CIDR notation (default: 169.254.0.0/16).
        /// Must match the value used on the client side.
        #[arg(short, long, default_value = "169.254.0.0/16")]
        subnet: String,
    },
    /// Run as client: discover servers and connect
    Client {
        /// Network interface(s) to use (comma-separated). If omitted, binds to all active interfaces.
        #[arg(short, long)]
        iface: Option<String>,

        /// Network interface(s) to exclude if binding to all interfaces.
        #[arg(short = 'x', long, value_delimiter = ',')]
        exclude_iface: Option<Vec<String>>,

        /// Subnet for tunnel IPs in CIDR notation (default: 169.254.0.0/16).
        /// Must match the value used on the server side.
        #[arg(short, long, default_value = "169.254.0.0/16")]
        subnet: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.verbose {
        VERBOSE.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    let (iface_str, exclude_list, subnet_str, is_server) = match &cli.command {
        Command::Server {
            iface,
            exclude_iface,
            subnet,
        } => (
            iface.clone(),
            exclude_iface.clone().unwrap_or_default(),
            subnet.clone(),
            true,
        ),
        Command::Client {
            iface,
            exclude_iface,
            subnet,
        } => (
            iface.clone(),
            exclude_iface.clone().unwrap_or_default(),
            subnet.clone(),
            false,
        ),
    };

    let subnet = Subnet::parse(&subnet_str)?;

    let explicit_ifaces = iface_str.map(|s| {
        s.split(',')
            .map(|x| x.trim().to_string())
            .collect::<Vec<_>>()
    });

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_clone = std::sync::Arc::clone(&stop);
    let _ = ctrlc::set_handler(move || {
        if stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
            std::process::exit(1);
        }
        println!("\nInitiating graceful shutdown across all interfaces... (Ctrl+C again to force)");
        stop_clone.store(true, std::sync::atomic::Ordering::Relaxed);
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(1500));
            std::process::exit(0);
        });
    });

    if is_server {
        if let Err(e) = server::run(explicit_ifaces, exclude_list, subnet, stop) {
            eprintln!("Server error: {}", e);
        }
    } else {
        let mut bind_ifaces = Vec::new();
        if let Some(explicit) = explicit_ifaces {
            bind_ifaces = explicit;
        } else {
            let all = pnet::datalink::interfaces();
            for i in all {
                if i.is_up() && !i.is_loopback() && !exclude_list.contains(&i.name) && !is_slave(&i.name) {
                    bind_ifaces.push(i.name.clone());
                }
            }
        }

        if bind_ifaces.is_empty() {
            eprintln!("No valid network interfaces found to bind.");
            std::process::exit(1);
        }

        println!("Binding to interfaces: {:?}", bind_ifaces);

        if let Err(e) = client::run(bind_ifaces, subnet, stop) {
            eprintln!("Client error: {}", e);
        }
    }

    Ok(())
}

fn is_slave(iface_name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{}/master", iface_name)).exists()
}
