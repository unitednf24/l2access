use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Default)]
pub struct Stats {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_packets: AtomicU64,
}

impl Stats {
    pub fn add_tx(&self, bytes: u64) {
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_rx(&self, bytes: u64) {
        self.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
    }
}

fn fmt_bytes(b: u64) -> String {
    if b < 1024 {
        format!("{} B", b)
    } else if b < 1024 * 1024 {
        format!("{:.1} KiB", b as f64 / 1024.0)
    } else if b < 1024 * 1024 * 1024 {
        format!("{:.2} MiB", b as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GiB", b as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Runs a stats display loop in the current thread, refreshing every second.
/// Blocks until `stop` is set to true (via Arc<AtomicBool>).
pub fn display_loop(
    stats: Arc<Stats>,
    remote_ip: std::net::Ipv4Addr,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    use std::io::Write;

    let start = Instant::now();
    println!("\nConnected. Remote tunnel IP: {}", remote_ip);
    println!("Press Ctrl-C to disconnect.\n");

    while !stop.load(Ordering::Relaxed) {
        let elapsed = start.elapsed().as_secs();
        let tx_b = stats.tx_bytes.load(Ordering::Relaxed);
        let rx_b = stats.rx_bytes.load(Ordering::Relaxed);
        let tx_p = stats.tx_packets.load(Ordering::Relaxed);
        let rx_p = stats.rx_packets.load(Ordering::Relaxed);

        print!(
            "\r  TX: {:>10}  ({} pkts)   RX: {:>10}  ({} pkts)   Up: {}s   ",
            fmt_bytes(tx_b),
            tx_p,
            fmt_bytes(rx_b),
            rx_p,
            elapsed
        );
        let _ = std::io::stdout().flush();
        // Check stop every 100 ms so shutdown is responsive.
        for _ in 0..10 {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    println!();
}
