# Armora Hardware Setup Guide

Complete guide for setting up Armora on a NanoPi or similar ARM device with dual Ethernet ports.

## Table of Contents

1. [Hardware Requirements](#hardware-requirements)
2. [Preparing the SD Card](#preparing-the-sd-card)
3. [Initial Boot and Configuration](#initial-boot-and-configuration)
4. [Installing Dependencies](#installing-dependencies)
5. [Building Armora](#building-armora)
6. [Network Configuration](#network-configuration)
7. [Running the Bridge](#running-the-bridge)
8. [Auto-Start on Boot](#auto-start-on-boot)
9. [Physical Connections](#physical-connections)
10. [Troubleshooting](#troubleshooting)

---

## Hardware Requirements

### Recommended Hardware

| Component | Specification | Notes |
|-----------|--------------|-------|
| **Board** | NanoPi R2S or R4S | Dual Gigabit Ethernet |
| **CPU** | ARM Cortex-A55/A72 | Quad-core minimum |
| **RAM** | 1GB+ | 2GB+ recommended |
| **Storage** | microSD 8GB+ | Class 10 or better |
| **Power** | 5V/2A USB-C | Quality PSU recommended |

### Alternative Boards

- NanoPi R5S (faster, more expensive)
- Orange Pi R1 Plus LTS
- Raspberry Pi 4 + USB Ethernet adapter
- Any ARM board with 2+ Ethernet ports

### Additional Items

- microSD card reader
- Ethernet cables (Cat5e or better)
- USB-to-Serial adapter (for debugging, optional)
- Heatsink/case (recommended for production)

---

## Preparing the SD Card

### Step 1: Download Armbian

Download the appropriate Armbian image for your board:

```bash
# For NanoPi R2S
wget https://redirect.armbian.com/nanopiR2S/Bookworm_current

# For NanoPi R4S
wget https://redirect.armbian.com/nanopiR4S/Bookworm_current
```

Or visit: https://www.armbian.com/download/

### Step 2: Flash the Image

**On Linux/macOS:**
```bash
# Find your SD card device
lsblk

# Flash (replace /dev/sdX with your device!)
sudo dd if=Armbian_*.img of=/dev/sdX bs=4M status=progress
sync
```

**On Windows:**
- Use [Etcher](https://etcher.balena.io/) or [Rufus](https://rufus.ie/)
- Select the Armbian image
- Select your SD card
- Click Flash

### Step 3: First Boot Preparation

Eject the SD card safely and insert it into the NanoPi.

---

## Initial Boot and Configuration

### Step 1: Connect and Power On

1. Connect an Ethernet cable to the **LAN port** (usually the one closer to the USB ports)
2. Connect to your router/switch
3. Connect power via USB-C

### Step 2: Find the Device IP

**Option A: Check your router's DHCP leases**

Look for a device named "armbian" or similar.

**Option B: Use nmap**
```bash
# Scan your network
nmap -sn 192.168.1.0/24 | grep -B2 "NanoPi\|armbian"
```

**Option C: Use serial console**
```bash
# Connect USB-to-Serial adapter
screen /dev/ttyUSB0 1500000
```

### Step 3: SSH Into the Device

```bash
ssh root@<device-ip>
# Default password: 1234
```

### Step 4: Initial Setup Wizard

On first login, Armbian will prompt you to:

1. Change root password → **Use a strong password!**
2. Create a normal user → Create user `armora` (or your choice)
3. Set timezone → Select your timezone
4. Choose shell → bash is fine

---

## Installing Dependencies

### Step 1: Update System

```bash
apt update && apt upgrade -y
```

### Step 2: Install Build Tools

```bash
apt install -y \
    build-essential \
    cmake \
    git \
    pkg-config
```

### Step 3: Install Libraries

```bash
# Network capture
apt install -y libpcap-dev

# Cryptography
apt install -y libssl-dev

# For liboqs (may need to build from source)
apt install -y astyle cmake gcc ninja-build libssl-dev python3-pytest \
    python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml
```

### Step 4: Install liboqs

liboqs may not be in your distro's repositories. Build from source:

```bash
cd /tmp
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja
sudo ninja install
sudo ldconfig
```

Verify installation:
```bash
ls /usr/local/lib/liboqs*
# Should show: liboqs.a liboqs.so liboqs.so.5 etc.
```

---

## Building Armora

### Step 1: Clone the Repository

```bash
cd /home/armora  # Or your user's home
git clone <repository-url> armora
cd armora
```

### Step 2: Build

```bash
mkdir build && cd build

# Configure
cmake -DCMAKE_BUILD_TYPE=Release ..

# Build
make -j$(nproc)

# Verify
./armora-bridge --help
```

### Step 3: Install (Optional)

```bash
sudo make install
# Installs to /usr/local/bin/
```

---

## Network Configuration

### Understanding the Interfaces

On NanoPi R2S/R4S:
- `eth0` = WAN port (usually the one near USB)
- `eth1` = LAN port

Check with:
```bash
ip link show
```

### Disable NetworkManager for Bridge Interfaces

The bridge needs raw access to interfaces. Disable management:

```bash
# Create configuration to ignore bridge interfaces
cat > /etc/NetworkManager/conf.d/99-unmanaged-bridge.conf << 'EOF'
[keyfile]
unmanaged-devices=interface-name:eth0;interface-name:eth1
EOF

# Restart NetworkManager
systemctl restart NetworkManager
```

### Configure Static IP for Management (Optional)

If you want to keep one interface for SSH access:

```bash
# Keep eth0 for management with static IP
cat > /etc/network/interfaces.d/eth0 << 'EOF'
auto eth0
iface eth0 inet static
    address 192.168.1.100
    netmask 255.255.255.0
    gateway 192.168.1.1
EOF
```

---

## Running the Bridge

### Generate a Pre-Shared Key

```bash
# Generate and save a key
openssl rand -hex 32 > /etc/armora/bridge.key
chmod 600 /etc/armora/bridge.key

# View the key (for the other device)
cat /etc/armora/bridge.key
```

### Test Run

```bash
# Run with stats display
sudo armora-bridge \
    -i eth0 \
    -o eth1 \
    -k $(cat /etc/armora/bridge.key) \
    -v -s

# You should see:
# Bridge running. Press Ctrl+C to stop.
# Enc: 0 pkts | Dec: 0 pkts | ...
```

### Verify Traffic Flow

On another machine, ping through the bridge:

```bash
# Connect Device A to eth0, Device B to eth1
# From Device A:
ping <Device B IP>
```

---

## Auto-Start on Boot

### Create Systemd Service

```bash
cat > /etc/systemd/system/armora-bridge.service << 'EOF'
[Unit]
Description=Armora Quantum-Resistant Ethernet Bridge
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/armora-bridge -i eth0 -o eth1 -k /etc/armora/bridge.key
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
```

### Enable and Start

```bash
# Create config directory
mkdir -p /etc/armora

# Reload systemd
systemctl daemon-reload

# Enable auto-start
systemctl enable armora-bridge

# Start now
systemctl start armora-bridge

# Check status
systemctl status armora-bridge

# View logs
journalctl -u armora-bridge -f
```

---

## Physical Connections

### Basic Setup

```
┌─────────────────┐
│   Device A      │
│  (Unencrypted)  │
└────────┬────────┘
         │ Ethernet
         ▼
┌─────────────────┐
│   eth0          │
│                 │
│   NanoPi        │
│   (Armora)      │
│                 │
│   eth1          │
└────────┬────────┘
         │ Ethernet (Encrypted)
         ▼
┌─────────────────┐
│   Device B      │
│  (or second     │
│   Armora box)   │
└─────────────────┘
```

### Point-to-Point Encrypted Link

```
┌──────────┐     ┌──────────┐              ┌──────────┐     ┌──────────┐
│ Device A │────▶│ Armora 1 │═════════════▶│ Armora 2 │────▶│ Device B │
└──────────┘     └──────────┘  Encrypted   └──────────┘     └──────────┘
                               Link
```

Both Armora devices must use the **same pre-shared key**.

---

## Troubleshooting

### Bridge Won't Start

**Error: "Permission denied"**
```bash
# Run as root
sudo armora-bridge ...

# Or add capability
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/armora-bridge
```

**Error: "Interface not found"**
```bash
# List interfaces
ip link show

# Check interface names (might be enp0s0, etc.)
```

**Error: "liboqs not found"**
```bash
# Rebuild with correct path
sudo ldconfig
cmake -DOQS_INCLUDE_DIR=/usr/local/include ..
```

### No Traffic Passing

1. Check interfaces are up:
```bash
ip link set eth0 up
ip link set eth1 up
```

2. Check promiscuous mode:
```bash
ip link set eth0 promisc on
ip link set eth1 promisc on
```

3. Check bridge is running:
```bash
systemctl status armora-bridge
```

4. Check logs:
```bash
journalctl -u armora-bridge --since "5 minutes ago"
```

### Poor Performance

1. Disable offloading:
```bash
ethtool -K eth0 tx off rx off gso off gro off tso off
ethtool -K eth1 tx off rx off gso off gro off tso off
```

2. Increase buffer sizes:
```bash
sysctl -w net.core.rmem_max=26214400
sysctl -w net.core.wmem_max=26214400
```

3. Pin to CPU cores (for consistent latency):
```bash
taskset -c 0,1 armora-bridge ...
```

### Key Mismatch

Both devices must have exactly the same key:
```bash
# Compare keys (should be identical)
cat /etc/armora/bridge.key
```

---

## Performance Tuning

### CPU Governor

```bash
# Set to performance mode
echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

### IRQ Affinity

```bash
# Find network IRQs
cat /proc/interrupts | grep eth

# Pin to specific CPU
echo 1 > /proc/irq/<eth0-irq>/smp_affinity
echo 2 > /proc/irq/<eth1-irq>/smp_affinity
```

### Disable Unnecessary Services

```bash
systemctl disable bluetooth
systemctl disable cups
systemctl disable avahi-daemon
```

---

## Security Considerations

1. **Physical Security**: The device bridges unencrypted traffic on one side
2. **Key Storage**: Consider using encrypted storage for keys
3. **Firmware Updates**: Keep Armbian and liboqs updated
4. **Monitoring**: Set up logging and alerting for bridge failures

---

## Next Steps

- [Run the Demo](../demo/README.md) - Web-based demonstration
- [IP Tunnel Mode](../README.md#ip-tunnel-mode) - Use over IP networks
- [API Documentation](API.md) - Integrate into your own applications

