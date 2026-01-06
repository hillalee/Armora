# Armora Demo

Web-based demonstration of the Armora Quantum-Resistant Ethernet Bridge.

## Features

- **Dashboard**: Real-time stats and bridge control
- **Packet Viewer**: Live hex dump of encrypted/decrypted packets
- **Chat Demo**: See messages encrypted and decrypted in real-time
- **File Transfer**: Upload files through the encrypted bridge
- **Benchmarks**: Measure latency, throughput, and performance

## Quick Start

### Simulation Mode (No Hardware Required)

```bash
# Install dependencies
cd demo
npm install

# Run in simulation mode
DEMO_MODE=1 npm start

# Open browser
open http://localhost:3000
```

### With Actual Bridge

```bash
# Build the bridge first
cd ..
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make

# Setup virtual interfaces
sudo ../scripts/setup_veth.sh create

# Run demo server
cd ../demo
npm start

# Open browser and configure bridge in the UI
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | 3000 |
| `BRIDGE_PATH` | Path to armora-bridge | ../build/armora-bridge |
| `DEMO_MODE` | Enable simulation (1/0) | 0 |

## Screenshots

### Dashboard
The main dashboard shows:
- Bridge status and controls
- Encryption/decryption statistics
- Cryptographic configuration
- Activity log

### Packet Viewer
Real-time display of:
- Packet timestamps
- Direction (encrypt/decrypt)
- MAC addresses
- Hex dump of packet contents

### Chat Demo
Three-column view showing:
- Original message (sender)
- Encrypted data (on the wire)
- Decrypted message (receiver)

### Benchmarks
Performance metrics:
- Latency (target: < 1ms)
- Throughput (target: > 100 Mbps)
- Packets per second
- CPU usage estimate

## Architecture

```
Browser <--> Express Server <--> armora-bridge
             (WebSocket)        (Child Process)
```

The server:
1. Serves static files (HTML/CSS/JS)
2. Manages WebSocket connections for real-time updates
3. Spawns and controls the armora-bridge process
4. Parses bridge output for statistics

