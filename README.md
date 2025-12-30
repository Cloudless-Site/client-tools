# ☁️ Cloudless Client Tools

This repository contains the **open-source client tools** for the [Cloudless](https://github.com/Cloudless-Site/cloudless-docs) reverse proxy service.

These tools are designed to be lightweight, portable, and dependency-free, allowing you to connect to Cloudless tunnels and diagnose UDP connectivity from any environment (Linux, Windows, ARM/Raspberry Pi).

## 📂 Contents

| Tool | Description |
| :--- | :--- |
| **`kite`** | **UDP Bridge & Tunneler.** Adapts the TCP tunnel stream back into real UDP packets for local apps. |
| **`sendto`** | A simple CLI utility to send UDP packets (IPv4/IPv6). Useful for testing tunnels. |
| **`recvfrom`** | A simple CLI utility to receive and echo UDP packets. Useful for debugging connectivity. |

---

## 🪁 Kite: Modes of Operation

Standard SSH remote forwarding (`ssh -R`) converts everything to a TCP stream. **Kite is required** to handle real UDP applications like WireGuard or Game Servers.

Kite has two modes of operation:

### 1. SSH Adapter Mode (`udp@`)
Used when tunneling traffic via standard SSH (port 22).
Kite acts as a local TCP Server (`-L`), accepts the stream from the SSH client, and forwards packets to your target app.

**Command:**
```bash
# Listen on Local TCP Port 4000 and forward to Target
./kite -L 4000:192.168.1.50:5555
```
*Then point your `ssh -R 10000:localhost:4000` to this instance.*

### 2. Cloud Direct Mode (`rawudp@`)
Used for maximum performance. Kite connects directly to the Cloudless core via TCP (`-r`), authenticates with a token, and bridges to your local app (`-l`).

**Command:**
```bash
# Connect using the string provided by the server
./kite -r cloudless.site:10000:TOKEN -l 192.168.1.50:5555
```

---

## 🚀 Scenario Examples

**Goal:** Expose a WireGuard VPN server (`192.168.1.50` on UDP `5555`) via Cloudless public port `10000`. The "Gateway" is the machine where you run these commands.

### Method A: SSH Transport
*(Best for traversing corporate firewalls)*
```bash
# 1. Start Kite Bridge on Gateway (Exchange Port TCP 4000)
./kite -L 4000:192.168.1.50:5555

# 2. Start SSH Tunnel (Forward Public 10000 -> Local 4000)
ssh -R 10000:localhost:4000 udp@cloudless.site
```

### Method B: Direct Transport
*(Best for low latency and high bandwidth)*
```bash
# 1. Get Token from Cloudless
ssh -R 10000:192.168.1.50:5555 rawudp@cloudless.site
# Output: > Connect String: cloudless.site:10000:A1B2-SECRET-TOKEN

# 2. Connect Kite Directly
./kite -r cloudless.site:10000:A1B2-SECRET-TOKEN -l 192.168.1.50:5555
```

---

## 🛠️ Build from Source

This project adheres to a **Zero Dependency** philosophy.
- Written in **pure C**.
- Uses only standard system libraries (libc/winsock).
- **No third-party SDKs** required.

### Prerequisites
- **Linux:** `gcc`, `make`
- **Cross-compile (Optional):** `mingw-w64` (for Windows), `gcc-arm-linux-gnueabihf` (ARMv7), `gcc-aarch64-linux-gnu` (ARM64).

### Compilation
To build all binaries (static) for all supported architectures:
```bash
make
```

Binaries will be placed in `bin/`:
```text
bin/
├── linux-x64/
├── linux-arm/
├── linux-arm64/
└── windows-x64/
```

---

## 🛡️ License & Legal

### License
This project is licensed under the **Apache License, Version 2.0**.
See the [LICENSE](LICENSE) file for the full text.

### Third-Party Components
**None.**
This repository contains **no third-party code**. All source files are original works and depend only on standard operating system APIs.

### Copyright
Copyright 2026 Cloudless Site

---

*For documentation on server-side setup, refer to the [Cloudless Service Documentation](https://github.com/Cloudless-Site/docs).*
