# Armora - Quantum-Resistant Ethernet Bridge

A transparent Layer 2 encryption bridge using post-quantum cryptography (PQC) for industrial point-to-point communication.

## Overview

Armora provides quantum-resistant encryption for Ethernet traffic between two network interfaces. It's designed for:

- **Industrial environments** (trains, manufacturing, energy)
- **Low-latency operation** (< 1ms added latency)
- **Low-power embedded systems** (NanoPi, ARM-based devices)
- **Transparent integration** (no changes to existing devices)

### Cryptographic Approach

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Key Exchange | Kyber1024 (ML-KEM) | Quantum-resistant key encapsulation |
| Encryption | AES-256-GCM | High-speed authenticated encryption |
| Key Derivation | HKDF-SHA256 | Derive symmetric key from KEM shared secret |

## Architecture

### Layer 2 Bridge Mode

```
Device A <---> [eth0] ARMORA [eth1] <---> Device B
                      │
              ┌───────┴───────┐
              │ BridgeEngine  │
              │ ┌───────────┐ │
              │ │ Thread 1  │─┼─> eth0 → Encrypt → eth1
              │ │ Thread 2  │─┼─> eth1 → Decrypt → eth0
              │ └───────────┘ │
              │ CryptoHandler │
              │ (Kyber+AES)   │
              └───────────────┘
```

### IP Tunnel Mode

```
Site A                          Internet                         Site B
[Device] → [eth0] Armora [UDP:5000] ═══════════════▶ [UDP:5000] Armora [eth0] → [Device]
```

## Quick Start

### Testing Without Hardware

You can test Armora on your laptop using virtual network interfaces:

```bash
# Build
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
cd ..

# Create virtual interfaces
sudo ./scripts/setup_veth.sh create

# Run the bridge
sudo ./build/armora-bridge -i veth0 -o veth1 -k $(openssl rand -hex 32) -s

# In another terminal, watch encrypted traffic
sudo tcpdump -i veth1 -X
```

### Demo Web Interface

```bash
cd demo
npm install
DEMO_MODE=1 npm start
# Open http://localhost:3000
```

## Building

### Prerequisites

Install dependencies on Armbian/Ubuntu:

```bash
# Build tools
sudo apt update
sudo apt install -y build-essential cmake git

# Libraries
sudo apt install -y libpcap-dev libssl-dev

# liboqs (Open Quantum Safe)
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc)
sudo make install
sudo ldconfig
```

### Build Commands

```bash
# Clone and build
git clone <repository-url>
cd armora
mkdir build && cd build

# Release build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

# With tests
cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON ..
make -j$(nproc)
ctest --output-on-failure
```

## Usage

### Bridge Mode (Layer 2)

```bash
# Generate key
KEY=$(openssl rand -hex 32)

# Run bridge between two local interfaces
sudo ./armora-bridge -i eth0 -o eth1 -k $KEY -s
```

### Tunnel Mode (Over IP)

```bash
# Site A
sudo ./armora-tunnel -i eth0 -l 5000 -r 192.168.1.100:5000 -k $KEY

# Site B (same key)
sudo ./armora-tunnel -i eth0 -l 5000 -r 192.168.1.50:5000 -k $KEY
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-i, --input <iface>` | Input/local interface |
| `-o, --output <iface>` | Output interface (bridge mode) |
| `-l, --local-port` | Local UDP port (tunnel mode) |
| `-r, --remote` | Remote address:port (tunnel mode) |
| `-k, --key <hex>` | Pre-shared key (64 hex chars) |
| `-v, --verbose` | Verbose output |
| `-s, --stats [N]` | Show stats every N seconds |
| `-h, --help` | Show help |

## Testing

```bash
# Run unit tests
./scripts/run_tests.sh

# Run integration tests (requires root)
sudo ./scripts/run_tests.sh --all
```

## Library Integration

For integrating into hardware firmware:

```cmake
find_package(armora REQUIRED)
target_link_libraries(your_firmware armora::armora_static)
```

```cpp
#include <armora/Types.hpp>
#include "bridge/BridgeEngine.hpp"

armora::BridgeEngine bridge;
armora::BridgeConfig config;
config.inputInterface = "eth0";
config.outputInterface = "eth1";

bridge.configure(config);
bridge.setPreSharedKeyHex("your-64-char-hex-key");
bridge.start();
// ... bridge runs ...
bridge.stop();
```

## Performance

| Metric | Target | Typical |
|--------|--------|---------|
| Latency | < 1ms | ~200-500 µs |
| Throughput | > 100 Mbps | 200+ Mbps |
| Overhead | - | 28 bytes/packet |

### Optimizations

- Pre-allocated packet buffers (no malloc in hot path)
- Lock-free buffer pools
- AES-NI hardware acceleration
- Immediate mode pcap capture

## Project Structure

```
armora/
├── CMakeLists.txt
├── README.md
├── include/armora/Types.hpp    # Public API
├── src/
│   ├── main.cpp                # Bridge executable
│   ├── tunnel_main.cpp         # Tunnel executable
│   ├── bridge/                 # BridgeEngine, PacketBuffer
│   ├── crypto/                 # ICryptoProvider, HybridPQC
│   ├── network/                # NetworkInterface, PcapCapture
│   └── tunnel/                 # UdpTunnel, TunnelEngine
├── tests/                      # Unit & integration tests
├── demo/                       # Web demo (Node.js)
├── scripts/                    # Helper scripts
└── docs/                       # Documentation
    ├── HARDWARE_SETUP.md
    └── DEMO_GUIDE.md
```

## Documentation

- [Hardware Setup Guide](docs/HARDWARE_SETUP.md) - NanoPi setup instructions
- [Demo Guide](docs/DEMO_GUIDE.md) - How to run and present the demo
- [Demo README](demo/README.md) - Web demo details

## Security Notes

- **MVP**: Uses pre-shared keys. Production should implement Kyber KEM exchange.
- **Nonces**: Counter-based with random prefix to prevent reuse.
- **Authentication**: AES-GCM provides authenticated encryption.

## Future Enhancements

- [ ] Dynamic Kyber key exchange protocol
- [ ] Key rotation during operation
- [ ] Passthrough mode for non-encrypted traffic
- [ ] Hardware acceleration (ARM Crypto Extensions)
- [ ] VLAN and 802.1Q support
- [ ] Industrial protocol awareness (PROFINET, EtherCAT)

## License

[Your license here]

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/Projects/post-quantum-cryptography)
- [Open Quantum Safe (liboqs)](https://openquantumsafe.org/)
- [Kyber (ML-KEM) Specification](https://pq-crystals.org/kyber/)
