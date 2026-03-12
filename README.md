<div align="center">
  <h1>L2Access 🚀</h1>
  <p><strong>Secure, Zero-Configuration Layer 2 VPN Tunnel for Linux and Embedded Systems</strong></p>

  [![OpenWrt Build](https://github.com/unitednf/l2access/actions/workflows/openwrt.yml/badge.svg)](https://github.com/unitednf/l2access/actions/workflows/openwrt.yml)
  [![Rust](https://img.shields.io/badge/rust-1.70%2B-blue.svg)](https://www.rust-lang.org/)
</div>

---

`l2access` is a fast, minimalist, user-space Layer 2 VPN tunnel written in Rust. It establishes secure, encrypted ethernet connectivity between machines across isolated or segmented networks. 

Designed with embedded systems like OpenWrt in mind, `l2access` functions as a single static binary. It heavily prioritizes ease-of-use with zero predefined configuration files—relying entirely on local UDP broadcasting for auto-discovery and native OS `.shadow` credentials for authentication.

## ✨ Key Features

- **Layer 2 Tunneling (TAP/TUN):** Transports pure, raw Ethernet frames via a standard `tun`/`tap` software interface, allowing bridged routing and complete IP protocol support.
- **Zero-Config Auto-Discovery:** Servers continuously announce their presence over the local network. Clients automatically locate available servers and present them in a clean Terminal UI (TUI).
- **Dynamic Subnet Negotiation:** The server dictates the VPN subnet. Clients implicitly parse the server's configuration and configure their TUN interfaces automatically upon connection.
- **Native OS Authentication (LuCI Compatible):** Integrates directly with the host's `/etc/passwd` and `/etc/shadow` files. It natively handles explicitly locked accounts and securely permits empty passwords, acting as a 1:1 replica of OpenWrt's `rpcd` / LuCI authorization behavior. No custom user databases needed.
- **Robust Cryptography:** 
  - Ephemeral **X25519 Diffie-Hellman** key exchanges.
  - State-of-the-art **ChaCha20-Poly1305** symmetric authenticated encryption for all transport packets.

---

## 🚀 Installation & Building

### Prerequisites
- Rust toolchain (`curl https://sh.rustup.rs -sSf | sh`)
- Development headers (`build-essential`, `libc-dev`)

### Compiling from Source
Clone the repository and build the release profile:
```bash
git clone https://github.com/unitednf/l2access.git
cd l2access
cargo build --release
```
The compiled static binary will be available at `target/release/l2access`.

---

## 🛠️ Usage

Both the Server and the Client are operated from the exact same binary. You must run the application with **root** privileges (`sudo`) to allow it to initialize `tun` adapters and query `/etc/shadow`.

### Running a Server
Launch the server daemon, binding it to your local physical network interface (`eth0`, `br-lan`, `wlan0`, etc.), and allocate the internal VPN subnet you want to use.

```bash
sudo ./l2access server --iface eth0 --subnet 10.8.0.0/24
```
*The server will immediately begin locally broadcasting its cryptographic public identity and subnet settings.*

### Running a Client
Launch the client, specifying the physical interface used to search for servers.

```bash
sudo ./l2access client --iface eth0
```
Upon launching, the interactive **TUI** will scan the network, display discovered servers, and seamlessly prompt for the server's standard Linux system credentials. 

*(Note: The `--subnet` argument on the client is optional and overridden by the server's broadcast).*

### Debugging
You can append the `-v` or `--verbose` flag globally to trace packets, cryptographic exchanges, and authentication diagnostics.
```bash
sudo ./l2access -v server --iface eth0 --subnet 10.8.0.0/24
```

---

## 📦 Packaging & Cross-Compilation

We provide automated scripts to comfortably package `l2access` for various distributions and architectures.

**Generate Native Packages:**
- **Debian (`.deb`):** `./scripts/build_deb.sh` (Requires `cargo-deb`)
- **RPM (`.rpm`):** `./scripts/build_rpm.sh` (Requires `cargo-generate-rpm`)

**Multi-Architecture Builds:**
- Automatically build sterile `musl` binaries for `x86_64`, `aarch64`, and `armv7` environments.
- Run `./scripts/build_multiarch.sh` (Requires Docker and [cross](https://github.com/cross-rs/cross)).

---

## 🌐 OpenWrt Integration

`l2access` provides native Makefile integration for the OpenWrt routing ecosystem. 

The `.github/workflows/openwrt.yml` GitHub Actions pipeline continuously verifies compilation and deploys `.ipk` packages leveraging the official OpenWrt SDK. 

### Manual SDK compilation:
1. Clone the OpenWrt SDK or Buildroot.
2. Ensure the `rust` package feed is updated (`./scripts/feeds install rust`).
3. Symlink this project's OpenWrt directory:  
   `ln -s /path/to/l2access/openwrt /path/to/openwrt/package/l2access`
4. Build the package:  
   `make package/l2access/compile V=s`

---
*Disclaimer: `l2access` utilizes `unsafe` blocks directly interfacing with Unix libc functions for shadow parsing and unlinked socket controls. Review the codebase before deploying on multi-tenant infrastructure.*
