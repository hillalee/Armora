# Armora Demo Guide

Step-by-step guide for running and presenting the Armora demonstration.

## Overview

The demo showcases:
1. **Real-time encryption/decryption** of network traffic
2. **Quantum-resistant cryptography** (Kyber1024 + AES-256-GCM)
3. **Low-latency operation** (sub-millisecond overhead)
4. **Transparent bridging** (no changes to connected devices)

---

## Demo Setup Options

### Option 1: Simulation Mode (Easiest)

No hardware required - runs entirely on your laptop.

```bash
cd demo
npm install
DEMO_MODE=1 npm start
```

Open http://localhost:3000

### Option 2: Virtual Interfaces (Linux Only)

Uses virtual network interfaces to simulate two Ethernet ports.

```bash
# Create virtual interfaces
sudo ./scripts/setup_veth.sh create

# Build the bridge
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
cd ..

# Run demo server
cd demo
npm start
```

### Option 3: Full Hardware Demo

Two NanoPi devices with physical connections.

```
[Laptop A] ──eth──▶ [Armora 1] ══encrypted══▶ [Armora 2] ──eth──▶ [Laptop B]
```

---

## Demo Walkthrough

### 1. Dashboard Overview (2 min)

**Show:**
- Bridge status indicator
- Cryptographic configuration panel
- Real-time statistics

**Explain:**
- "Armora uses Kyber1024 for key exchange - this is NIST's chosen post-quantum algorithm"
- "Traffic is encrypted with AES-256-GCM for high-speed operation"
- "28 bytes overhead per packet (12 byte IV + 16 byte auth tag)"

### 2. Start the Bridge (1 min)

**Actions:**
1. Click "Generate" to create a random key
2. Click "Start Bridge"
3. Watch stats start updating

**Explain:**
- "The key is 256 bits - would take billions of years to crack"
- "Both ends need the same key for MVP; production would use Kyber KEM exchange"

### 3. Packet Viewer (3 min)

**Switch to Packet Viewer tab**

**Show:**
- Live packets appearing
- Hex dump of encrypted vs original
- Direction indicators

**Explain:**
- "Each packet shows timestamp, size, and direction"
- "Notice the encrypted packets are larger by 28 bytes (crypto overhead)"
- "The hex dump shows random-looking data - that's the encryption"

### 4. Chat Demo (3 min)

**Switch to Chat Demo tab**

**Actions:**
1. Type a message: "Secret industrial command: START_MOTOR_01"
2. Click Send
3. Watch the three columns

**Explain:**
- Left column: Original message
- Middle column: "What an attacker would see on the wire"
- Right column: "What the receiver gets after decryption"

**Point out:**
- "The middle column is completely unreadable"
- "Even with a quantum computer, this would take ages to crack"

### 5. File Transfer (2 min)

**Switch to File Transfer tab**

**Actions:**
1. Select a file (any small file)
2. Watch progress bar
3. See "Encrypted & Transferred" in history

**Explain:**
- "Files are chunked and each chunk is encrypted"
- "Integrity is verified with authentication tags"
- "If any bit is modified, decryption fails"

### 6. Benchmarks (2 min)

**Switch to Benchmarks tab**

**Actions:**
1. Click "Run Benchmark"
2. Wait 10 seconds
3. Show results table

**Explain:**
- "Latency: How much delay encryption adds (target: < 1ms)"
- "Throughput: Data rate (target: > 100 Mbps)"
- "Packets/sec: How many packets can be processed"

### 7. Q&A Talking Points

**"Why quantum-resistant?"**
- "Current encryption (RSA, ECDH) will be broken by quantum computers"
- "Kyber is NIST's chosen algorithm for post-quantum key exchange"
- "We're protecting data that needs to stay secret for 10+ years"

**"What about latency?"**
- "Sub-millisecond overhead - acceptable for most industrial protocols"
- "Real-time requirements (PROFINET, EtherCAT) may need hardware acceleration"

**"Power consumption?"**
- "ARM devices typically use < 5W"
- "Actual encryption operations use AES-NI (hardware acceleration)"

**"How does it compare to VPNs?"**
- "Layer 2 vs Layer 3 - works with non-IP protocols"
- "Transparent - no configuration on connected devices"
- "Quantum-resistant - future-proof security"

---

## Technical Deep Dive (Optional)

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        ARMORA BRIDGE                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────┐    ┌──────────────┐    ┌─────────────┐       │
│   │   eth0      │───▶│  BridgeEngine │───▶│   eth1      │       │
│   │  (input)    │    │              │    │  (output)   │       │
│   └─────────────┘    │  ┌────────┐  │    └─────────────┘       │
│                      │  │Thread 1│  │                          │
│                      │  │Encrypt │  │                          │
│                      │  └────────┘  │                          │
│                      │              │                          │
│                      │  ┌────────┐  │                          │
│                      │  │Thread 2│  │                          │
│                      │  │Decrypt │  │                          │
│                      │  └────────┘  │                          │
│                      └──────┬───────┘                          │
│                             │                                   │
│                      ┌──────▼───────┐                          │
│                      │CryptoHandler │                          │
│                      │              │                          │
│                      │ Kyber1024    │                          │
│                      │ AES-256-GCM  │                          │
│                      └──────────────┘                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Packet Format

```
Original Ethernet Frame:
┌────────────────┬────────────────┬──────────┬─────────────────┐
│  Dest MAC (6)  │  Src MAC (6)   │Type (2)  │  Payload (N)    │
└────────────────┴────────────────┴──────────┴─────────────────┘

After Encryption:
┌────────────────┬────────────────┬──────────┬─────────────────────────────────────────┐
│  Dest MAC (6)  │  Src MAC (6)   │Type (2)  │  IV (12) │ Encrypted Payload │ Tag (16) │
└────────────────┴────────────────┴──────────┴─────────────────────────────────────────┘
```

### Key Exchange (Production)

```
Device A                              Device B
   │                                     │
   │  1. Generate Kyber keypair         │
   │◀────────────────────────────────────│
   │     Public Key (1568 bytes)        │
   │                                     │
   │  2. Encapsulate shared secret       │
   │────────────────────────────────────▶│
   │     Ciphertext (1568 bytes)        │
   │                                     │
   │  3. Both derive AES-256 key        │
   │     using HKDF-SHA256              │
   │                                     │
   │  4. Begin encrypted communication   │
   │◀═══════════════════════════════════▶│
   │                                     │
```

---

## Troubleshooting Demo Issues

### "WebSocket disconnected"
- Check server is running: `npm start`
- Check console for errors
- Try refreshing the page

### "Bridge won't start"
- In simulation mode? Check `DEMO_MODE=1`
- Real mode? Run as root: `sudo npm start`
- Check veth interfaces exist: `ip link show`

### "No packets showing"
- Generate some traffic: `ping -I veth0 192.168.100.2`
- Check bridge is running in dashboard
- Look at activity log for errors

### "Stats not updating"
- Bridge might not be running
- Check browser console for WebSocket errors
- Try stopping and starting bridge

