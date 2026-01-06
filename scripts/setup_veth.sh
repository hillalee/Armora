#!/bin/bash
# ============================================================================
# setup_veth.sh - Create virtual Ethernet pairs for testing
# ============================================================================
#
# This script creates virtual network interfaces (veth pairs) for testing
# the Armora bridge without physical hardware.
#
# Usage:
#   sudo ./setup_veth.sh create    # Create veth pairs
#   sudo ./setup_veth.sh destroy   # Remove veth pairs
#   sudo ./setup_veth.sh status    # Show status
#
# The script creates:
#   - veth0 <-> veth1 (main bridge pair)
#   - veth2 <-> veth3 (secondary pair for testing)
#
# After running 'create', you can:
#   1. Run the bridge: sudo ./armora-bridge -i veth0 -o veth1 -k <key>
#   2. Send test traffic: sudo tcpdump -i veth1
#   3. Generate traffic: ping -I veth0 192.168.100.2
#
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check for root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        echo "Usage: sudo $0 {create|destroy|status}"
        exit 1
    fi
}

# Create veth pairs
create_veth() {
    echo -e "${GREEN}Creating virtual Ethernet pairs...${NC}"
    
    # Primary pair: veth0 <-> veth1
    if ip link show veth0 &>/dev/null; then
        echo -e "${YELLOW}veth0 already exists, skipping...${NC}"
    else
        echo "  Creating veth0 <-> veth1..."
        ip link add veth0 type veth peer name veth1
        ip link set veth0 up
        ip link set veth1 up
        
        # Optional: Assign IP addresses for testing
        ip addr add 192.168.100.1/24 dev veth0 2>/dev/null || true
        ip addr add 192.168.100.2/24 dev veth1 2>/dev/null || true
    fi

    # Secondary pair: veth2 <-> veth3
    if ip link show veth2 &>/dev/null; then
        echo -e "${YELLOW}veth2 already exists, skipping...${NC}"
    else
        echo "  Creating veth2 <-> veth3..."
        ip link add veth2 type veth peer name veth3
        ip link set veth2 up
        ip link set veth3 up
        
        ip addr add 192.168.101.1/24 dev veth2 2>/dev/null || true
        ip addr add 192.168.101.2/24 dev veth3 2>/dev/null || true
    fi

    # Enable promiscuous mode (needed for raw packet capture)
    echo "  Enabling promiscuous mode..."
    ip link set veth0 promisc on
    ip link set veth1 promisc on
    ip link set veth2 promisc on
    ip link set veth3 promisc on

    # Disable checksum offloading (important for raw packet testing)
    echo "  Disabling checksum offloading..."
    ethtool -K veth0 tx off rx off gso off gro off tso off 2>/dev/null || true
    ethtool -K veth1 tx off rx off gso off gro off tso off 2>/dev/null || true
    ethtool -K veth2 tx off rx off gso off gro off tso off 2>/dev/null || true
    ethtool -K veth3 tx off rx off gso off gro off tso off 2>/dev/null || true

    echo ""
    echo -e "${GREEN}Virtual interfaces created successfully!${NC}"
    echo ""
    echo "You can now run the bridge:"
    echo "  sudo ./armora-bridge -i veth0 -o veth1 -k \$(openssl rand -hex 32)"
    echo ""
    echo "To test, open another terminal and run:"
    echo "  sudo tcpdump -i veth1 -X"
    echo ""
    echo "Generate test traffic with:"
    echo "  ping -I veth0 192.168.100.2"
    echo ""
}

# Destroy veth pairs
destroy_veth() {
    echo -e "${YELLOW}Removing virtual Ethernet pairs...${NC}"
    
    if ip link show veth0 &>/dev/null; then
        echo "  Removing veth0 (and veth1)..."
        ip link delete veth0 2>/dev/null || true
    fi
    
    if ip link show veth2 &>/dev/null; then
        echo "  Removing veth2 (and veth3)..."
        ip link delete veth2 2>/dev/null || true
    fi
    
    echo -e "${GREEN}Virtual interfaces removed.${NC}"
}

# Show status
show_status() {
    echo -e "${GREEN}Virtual Interface Status:${NC}"
    echo ""
    
    for iface in veth0 veth1 veth2 veth3; do
        if ip link show $iface &>/dev/null; then
            echo -e "  ${GREEN}$iface${NC}: UP"
            ip addr show $iface | grep -E "inet |link/ether" | sed 's/^/    /'
        else
            echo -e "  ${RED}$iface${NC}: NOT FOUND"
        fi
    done
    echo ""
}

# Show usage
show_usage() {
    echo "Usage: sudo $0 {create|destroy|status}"
    echo ""
    echo "Commands:"
    echo "  create   - Create virtual Ethernet pairs for testing"
    echo "  destroy  - Remove virtual Ethernet pairs"
    echo "  status   - Show current status of virtual interfaces"
    echo ""
}

# Main
case "${1:-}" in
    create)
        check_root
        create_veth
        ;;
    destroy)
        check_root
        destroy_veth
        ;;
    status)
        show_status
        ;;
    *)
        show_usage
        exit 1
        ;;
esac

