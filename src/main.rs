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
        /// Network interface to use (e.g. eth0)
        #[arg(short, long)]
        iface: String,

        /// Subnet for tunnel IPs in CIDR notation (default: 169.254.0.0/16).
        /// Must match the value used on the client side.
        #[arg(short, long, default_value = "169.254.0.0/16")]
        subnet: String,
    },
    /// Run as client: discover servers and connect
    Client {
        /// Network interface to use (e.g. eth0)
        #[arg(short, long)]
        iface: String,

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

    match cli.command {
        Command::Server { iface, subnet } => {
            let subnet = Subnet::parse(&subnet)?;
            server::run(&iface, subnet)
        }
        Command::Client { iface, subnet } => {
            let subnet = Subnet::parse(&subnet)?;
            client::run(&iface, subnet)
        }
    }
}
