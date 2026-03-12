//! Wire protocol constants and packet types for L2Access.
//!
//! Ethernet payload layout:
//!   [0..4]  Magic "L2AC"
//!   [4]     Version (0x01)
//!   [5]     PacketType
//!   [6..]   Type-specific payload

pub const MAGIC: [u8; 4] = [0x4C, 0x32, 0x41, 0x43]; // "L2AC"
pub const VERSION: u8 = 0x01;
pub const ETHERTYPE: u16 = 0x88B5; // IEEE 802 local experimental
pub const DISCOVERY_MAC: [u8; 6] = [0x01, 0x00, 0x5E, 0x00, 0x6C, 0x32];

pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketType {
    Discovery = 0x01,
    Connect = 0x02,
    AuthOk = 0x03,
    AuthFail = 0x04,
    Tunnel = 0x05,
    Disconnect = 0x06,
    KeepaliveReq = 0x07,
    KeepaliveRep = 0x08,
}

impl PacketType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Discovery),
            0x02 => Some(Self::Connect),
            0x03 => Some(Self::AuthOk),
            0x04 => Some(Self::AuthFail),
            0x05 => Some(Self::Tunnel),
            0x06 => Some(Self::Disconnect),
            0x07 => Some(Self::KeepaliveReq),
            0x08 => Some(Self::KeepaliveRep),
            _ => None,
        }
    }
}

// ── Typed payloads ──────────────────────────────────────────────────────────

pub struct DiscoveryData {
    pub hostname: String,
    pub version: String,
    pub server_pubkey: [u8; 32],
    /// CIDR string for the tunnel subnet, e.g. "10.0.0.0/24".
    pub subnet_cidr: String,
}

pub struct ConnectData {
    pub client_pubkey: [u8; 32],
    pub nonce: [u8; 12],
    pub encrypted_credentials: Vec<u8>, // chacha20poly1305(username\0password)
}

pub struct AuthOkData {
    pub nonce: [u8; 12],
    pub encrypted_session_key: Vec<u8>, // chacha20poly1305(32-byte session key) → 48 bytes
}

pub struct TunnelData {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

pub enum L2APacket {
    Discovery(DiscoveryData),
    Connect(ConnectData),
    AuthOk(AuthOkData),
    AuthFail(u8),
    Tunnel(TunnelData),
    Disconnect,
    KeepaliveReq,
    KeepaliveRep,
}

// ── Parsing ─────────────────────────────────────────────────────────────────

pub fn parse_l2a_payload(data: &[u8]) -> Option<L2APacket> {
    if data.len() < 6 {
        return None;
    }
    if data[0..4] != MAGIC {
        return None;
    }
    if data[4] != VERSION {
        return None;
    }
    let pkt_type = PacketType::from_u8(data[5])?;
    let rest = &data[6..];

    match pkt_type {
        PacketType::Discovery => parse_discovery(rest),
        PacketType::Connect => parse_connect(rest),
        PacketType::AuthOk => parse_auth_ok(rest),
        PacketType::AuthFail => {
            if rest.is_empty() {
                return None;
            }
            Some(L2APacket::AuthFail(rest[0]))
        }
        PacketType::Tunnel => parse_tunnel(rest),
        PacketType::Disconnect => Some(L2APacket::Disconnect),
        PacketType::KeepaliveReq => Some(L2APacket::KeepaliveReq),
        PacketType::KeepaliveRep => Some(L2APacket::KeepaliveRep),
    }
}

fn parse_discovery(d: &[u8]) -> Option<L2APacket> {
    if d.is_empty() {
        return None;
    }
    let hl = d[0] as usize;
    if d.len() < 1 + hl + 1 {
        return None;
    }
    let hostname = String::from_utf8(d[1..1 + hl].to_vec()).ok()?;
    let rest = &d[1 + hl..];
    let vl = rest[0] as usize;
    if rest.len() < 1 + vl + 32 {
        return None;
    }
    let version = String::from_utf8(rest[1..1 + vl].to_vec()).ok()?;
    let mut server_pubkey = [0u8; 32];
    server_pubkey.copy_from_slice(&rest[1 + vl..1 + vl + 32]);
    // subnet_cidr is appended after pubkey (optional for wire compat)
    let after_key = &rest[1 + vl + 32..];
    let subnet_cidr = if after_key.len() >= 2 {
        let sl = after_key[0] as usize;
        if after_key.len() > sl {
            String::from_utf8(after_key[1..1 + sl].to_vec()).unwrap_or_default()
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    Some(L2APacket::Discovery(DiscoveryData {
        hostname,
        version,
        server_pubkey,
        subnet_cidr,
    }))
}

fn parse_connect(d: &[u8]) -> Option<L2APacket> {
    if d.len() < 32 + 12 + 1 {
        return None;
    }
    let mut client_pubkey = [0u8; 32];
    client_pubkey.copy_from_slice(&d[0..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&d[32..44]);
    let encrypted_credentials = d[44..].to_vec();
    Some(L2APacket::Connect(ConnectData {
        client_pubkey,
        nonce,
        encrypted_credentials,
    }))
}

fn parse_auth_ok(d: &[u8]) -> Option<L2APacket> {
    if d.len() < 12 + 48 {
        return None;
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&d[0..12]);
    let encrypted_session_key = d[12..].to_vec();
    Some(L2APacket::AuthOk(AuthOkData {
        nonce,
        encrypted_session_key,
    }))
}

fn parse_tunnel(d: &[u8]) -> Option<L2APacket> {
    if d.len() < 12 + 1 {
        return None;
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&d[0..12]);
    let ciphertext = d[12..].to_vec();
    Some(L2APacket::Tunnel(TunnelData { nonce, ciphertext }))
}

// ── Building ─────────────────────────────────────────────────────────────────

fn header(pt: PacketType) -> Vec<u8> {
    let mut v = Vec::with_capacity(6);
    v.extend_from_slice(&MAGIC);
    v.push(VERSION);
    v.push(pt as u8);
    v
}

pub fn build_discovery(
    hostname: &str,
    version: &str,
    server_pubkey: &[u8; 32],
    subnet_cidr: &str,
) -> Vec<u8> {
    let mut p = header(PacketType::Discovery);
    p.push(hostname.len() as u8);
    p.extend_from_slice(hostname.as_bytes());
    p.push(version.len() as u8);
    p.extend_from_slice(version.as_bytes());
    p.extend_from_slice(server_pubkey);
    p.push(subnet_cidr.len() as u8);
    p.extend_from_slice(subnet_cidr.as_bytes());
    p
}

pub fn build_connect(
    client_pubkey: &[u8; 32],
    nonce: &[u8; 12],
    encrypted_creds: &[u8],
) -> Vec<u8> {
    let mut p = header(PacketType::Connect);
    p.extend_from_slice(client_pubkey);
    p.extend_from_slice(nonce);
    p.extend_from_slice(encrypted_creds);
    p
}

pub fn build_auth_ok(nonce: &[u8; 12], encrypted_session_key: &[u8]) -> Vec<u8> {
    let mut p = header(PacketType::AuthOk);
    p.extend_from_slice(nonce);
    p.extend_from_slice(encrypted_session_key);
    p
}

pub fn build_auth_fail(reason: u8) -> Vec<u8> {
    let mut p = header(PacketType::AuthFail);
    p.push(reason);
    p
}

pub fn build_tunnel(nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
    let mut p = header(PacketType::Tunnel);
    p.extend_from_slice(nonce);
    p.extend_from_slice(ciphertext);
    p
}

pub fn build_disconnect() -> Vec<u8> {
    header(PacketType::Disconnect)
}

pub fn build_keepalive_req() -> Vec<u8> {
    header(PacketType::KeepaliveReq)
}

pub fn build_keepalive_rep() -> Vec<u8> {
    header(PacketType::KeepaliveRep)
}

// ── Ethernet frame helpers ───────────────────────────────────────────────────

pub fn build_eth_frame(dst: &[u8; 6], src: &[u8; 6], payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(dst);
    frame.extend_from_slice(src);
    frame.push((ETHERTYPE >> 8) as u8);
    frame.push((ETHERTYPE & 0xFF) as u8);
    frame.extend_from_slice(payload);
    frame
}

/// Returns (src_mac, payload) for frames matching our EtherType.
pub fn parse_eth_frame(frame: &[u8]) -> Option<([u8; 6], [u8; 6], &[u8])> {
    if frame.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETHERTYPE {
        return None;
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&frame[0..6]);
    src.copy_from_slice(&frame[6..12]);
    Some((dst, src, &frame[14..]))
}

// ── Subnet config ────────────────────────────────────────────────────────────

/// A parsed CIDR subnet, e.g. `10.0.0.0/24` or `169.254.0.0/16`.
#[derive(Clone, Copy, Debug)]
pub struct Subnet {
    /// Network base address (host bits zeroed).
    pub net: std::net::Ipv4Addr,
    /// Prefix length (1–30).
    pub prefix_len: u8,
}

impl Subnet {
    #[allow(dead_code)]
    pub const DEFAULT: Self = Self {
        net: std::net::Ipv4Addr::new(169, 254, 0, 0),
        prefix_len: 16,
    };

    /// Parse a CIDR string like `10.0.0.0/24`.
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let (addr_s, len_s) = s
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("subnet must be CIDR notation, e.g. 10.0.0.0/24"))?;
        let net: std::net::Ipv4Addr = addr_s
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid subnet address: {}", addr_s))?;
        let prefix_len: u8 = len_s
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid prefix length: {}", len_s))?;
        if !(1..=30).contains(&prefix_len) {
            anyhow::bail!("prefix length must be 1–30, got {}", prefix_len);
        }
        // Zero out any host bits the user left in
        let mask = !host_mask(prefix_len);
        let net = std::net::Ipv4Addr::from(u32::from(net) & mask);
        Ok(Self { net, prefix_len })
    }

    /// IPv4 netmask derived from prefix length.
    pub fn netmask(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(!host_mask(self.prefix_len))
    }

    /// CIDR string, e.g. `10.0.0.0/24`.
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.net, self.prefix_len)
    }

    /// Derive a unique TUN IP for a given MAC within this subnet.
    /// Uses FNV-1a-inspired hashing so the distribution is good across all prefix lengths.
    pub fn mac_to_ip(&self, mac: &[u8; 6]) -> std::net::Ipv4Addr {
        let hm = host_mask(self.prefix_len);
        let net = u32::from(self.net);
        let hash = mac_fnv(mac);
        // Spread hash across the available host bits (skip network=0 and broadcast)
        let available = hm.saturating_sub(1); // max usable host value
        let host = if available == 0 {
            1
        } else {
            1 + (hash % available) // range [1, available]
        };
        std::net::Ipv4Addr::from(net | host)
    }
}

impl std::fmt::Display for Subnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.cidr())
    }
}

fn host_mask(prefix_len: u8) -> u32 {
    if prefix_len >= 32 {
        0
    } else {
        (1u32 << (32 - prefix_len)) - 1
    }
}

/// FNV-1a 32-bit hash of a MAC address.
fn mac_fnv(mac: &[u8; 6]) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for &b in mac {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_subnet_parse() {
        let s = Subnet::parse("10.0.0.0/24").unwrap();
        assert_eq!(s.net, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(s.prefix_len, 24);

        // check masking
        let s2 = Subnet::parse("192.168.1.130/24").unwrap();
        assert_eq!(s2.net, Ipv4Addr::new(192, 168, 1, 0));
    }

    #[test]
    fn test_mac_to_ip_distribution() {
        let s = Subnet::parse("10.0.0.0/24").unwrap();
        let mac1 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mac2 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x56];

        let ip1 = s.mac_to_ip(&mac1);
        let ip2 = s.mac_to_ip(&mac2);

        // IPs should be in range and distinct
        let ip1_u32 = u32::from(ip1);
        let ip2_u32 = u32::from(ip2);
        let net_u32 = u32::from(s.net);

        assert!(ip1_u32 > net_u32);
        assert!(ip1_u32 <= net_u32 + 254);
        assert!(ip2_u32 > net_u32);
        assert!(ip2_u32 <= net_u32 + 254);
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn test_discovery_encode_decode() {
        let pubkey = [0xAB; 32];
        let payload = build_discovery("testhost", "1.0.0", &pubkey, "10.0.0.0/8");

        match parse_l2a_payload(&header(PacketType::Discovery)) {
            None => {} // Expected incomplete
            _ => panic!("Should be incomplete"),
        }

        match parse_l2a_payload(&payload).unwrap() {
            L2APacket::Discovery(d) => {
                assert_eq!(d.hostname, "testhost");
                assert_eq!(d.version, "1.0.0");
                assert_eq!(d.server_pubkey, pubkey);
                assert_eq!(d.subnet_cidr, "10.0.0.0/8");
            }
            _ => panic!("Wrong packet type"),
        }
    }
}
