/// Helpers for opening a raw pnet datalink channel.
use anyhow::{bail, Result};
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
use std::time::Duration;

pub fn find_interface(name: &str) -> Result<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|i| i.name == name)
        .ok_or_else(|| anyhow::anyhow!("Interface '{}' not found", name))
}

/// Open a channel with a 100 ms read timeout.
/// Used for auth and tunnel phases, where the stop flag must be checked regularly.
pub fn open_channel(
    iface: &NetworkInterface,
) -> Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
    open_channel_raw(iface, Some(Duration::from_millis(100)))
}

/// Open a channel with a 1 s read timeout, suitable for the discovery background thread.
pub fn open_channel_discovery(
    iface: &NetworkInterface,
) -> Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
    open_channel_raw(iface, Some(Duration::from_secs(1)))
}

fn open_channel_raw(
    iface: &NetworkInterface,
    timeout: Option<Duration>,
) -> Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>)> {
    let cfg = datalink::Config {
        promiscuous: true,
        read_timeout: timeout,
        ..Default::default()
    };
    match datalink::channel(iface, cfg) {
        Ok(Channel::Ethernet(tx, rx)) => Ok((tx, rx)),
        Ok(_) => bail!("Unsupported channel type on {}", iface.name),
        Err(e) => bail!("Failed to open channel on {}: {}", iface.name, e),
    }
}

pub fn iface_mac(iface: &NetworkInterface) -> Result<[u8; 6]> {
    let mac = iface
        .mac
        .ok_or_else(|| anyhow::anyhow!("Interface {} has no MAC address", iface.name))?;
    Ok([mac.0, mac.1, mac.2, mac.3, mac.4, mac.5])
}
