/**
 * @file tunnel_main.cpp
 * @brief Entry point for Armora IP Tunnel mode
 * 
 * This executable provides encrypted point-to-point communication over UDP,
 * allowing Armora devices to communicate across IP networks (like a VPN).
 * 
 * Usage:
 *   sudo ./armora-tunnel -i eth0 -l 5000 -r 192.168.1.100:5000 -k <hex-key>
 */

#include "tunnel/TunnelEngine.hpp"
#include "network/NetworkInterface.hpp"
#include "armora/Types.hpp"

#include <csignal>
#include <cstdlib>
#include <iostream>
#include <iomanip>
#include <atomic>
#include <chrono>
#include <thread>
#include <cstring>

// ============================================================================
// Global State
// ============================================================================

static std::atomic<bool> g_running{true};
static armora::TunnelEngine* g_tunnel = nullptr;

static void signalHandler(int signum) {
    std::cout << "\nReceived signal " << signum << ", shutting down..." << std::endl;
    g_running = false;
    if (g_tunnel) {
        g_tunnel->stop();
    }
}

// ============================================================================
// Command Line Parsing
// ============================================================================

struct TunnelOptions {
    std::string localInterface = "eth0";
    uint16_t localPort = 5000;
    std::string remoteAddress;
    uint16_t remotePort = 5000;
    std::string keyHex;
    bool verbose = false;
    bool showStats = false;
    int statsIntervalSec = 5;
    bool help = false;
};

static void printUsage(const char* programName) {
    std::cout << R"(
Armora IP Tunnel - Encrypted Point-to-Point Communication
==========================================================

Usage: )" << programName << R"( [OPTIONS]

Options:
  -i, --interface <iface>   Local network interface (default: eth0)
  -l, --local-port <port>   Local UDP port to bind (default: 5000)
  -r, --remote <addr:port>  Remote peer address and port (required)
  -k, --key <hex>           Pre-shared key (64 hex characters)
  -v, --verbose             Enable verbose output
  -s, --stats [interval]    Show statistics every N seconds (default: 5)
  -h, --help                Show this help message

Example:
  # Site A: Listen on port 5000, connect to Site B
  sudo ./armora-tunnel -i eth0 -l 5000 -r 192.168.1.100:5000 -k $(openssl rand -hex 32)

  # Site B: Listen on port 5000, connect to Site A
  sudo ./armora-tunnel -i eth0 -l 5000 -r 192.168.1.50:5000 -k <same-key>

How it works:
  1. Captures Ethernet frames from local interface
  2. Encrypts with AES-256-GCM (key from Kyber1024 or PSK)
  3. Sends encrypted packets via UDP to remote peer
  4. Receives encrypted UDP from peer, decrypts, injects locally

)" << std::endl;
}

static bool parseRemoteAddress(const std::string& input, 
                                std::string& address, uint16_t& port) {
    size_t colonPos = input.rfind(':');
    if (colonPos == std::string::npos) {
        return false;
    }
    
    address = input.substr(0, colonPos);
    try {
        port = static_cast<uint16_t>(std::stoul(input.substr(colonPos + 1)));
    } catch (...) {
        return false;
    }
    
    return !address.empty() && port > 0;
}

static TunnelOptions parseArgs(int argc, char* argv[]) {
    TunnelOptions opts;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            opts.help = true;
        } else if (arg == "-v" || arg == "--verbose") {
            opts.verbose = true;
        } else if (arg == "-s" || arg == "--stats") {
            opts.showStats = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                opts.statsIntervalSec = std::atoi(argv[++i]);
                if (opts.statsIntervalSec < 1) opts.statsIntervalSec = 1;
            }
        } else if ((arg == "-i" || arg == "--interface") && i + 1 < argc) {
            opts.localInterface = argv[++i];
        } else if ((arg == "-l" || arg == "--local-port") && i + 1 < argc) {
            opts.localPort = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if ((arg == "-r" || arg == "--remote") && i + 1 < argc) {
            if (!parseRemoteAddress(argv[++i], opts.remoteAddress, opts.remotePort)) {
                std::cerr << "Invalid remote address format. Use: address:port" << std::endl;
                opts.help = true;
            }
        } else if ((arg == "-k" || arg == "--key") && i + 1 < argc) {
            opts.keyHex = argv[++i];
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            opts.help = true;
        }
    }

    return opts;
}

// ============================================================================
// Statistics Display
// ============================================================================

static void printStats(const armora::TunnelStats& stats) {
    std::cout << "\r"
              << "Out: " << std::setw(8) << stats.packetsOut.load() << " pkts "
              << "(" << std::setw(10) << stats.bytesOut.load() << " B) | "
              << "In: " << std::setw(8) << stats.packetsIn.load() << " pkts "
              << "(" << std::setw(10) << stats.bytesIn.load() << " B) | "
              << "Err: " << stats.encryptErrors.load() + stats.decryptErrors.load()
              << std::flush;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    TunnelOptions opts = parseArgs(argc, argv);

    if (opts.help) {
        printUsage(argv[0]);
        return 0;
    }

    // Validate required options
    if (opts.remoteAddress.empty()) {
        std::cerr << "Error: Remote address required. Use -r <address:port>" << std::endl;
        return 1;
    }

    if (opts.keyHex.empty()) {
        std::cerr << "Error: Pre-shared key required. Use -k <hex-key>" << std::endl;
        std::cerr << "Generate a key with: openssl rand -hex 32" << std::endl;
        return 1;
    }

    if (opts.keyHex.length() != 64) {
        std::cerr << "Error: Key must be 64 hex characters (32 bytes)" << std::endl;
        return 1;
    }

    // Check for root
    if (geteuid() != 0) {
        std::cerr << "Warning: Not running as root. Raw socket access may fail." << std::endl;
    }

    // Setup signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    // Print banner
    std::cout << "========================================" << std::endl;
    std::cout << "  Armora IP Tunnel v"
              << armora::VERSION_MAJOR << "."
              << armora::VERSION_MINOR << "."
              << armora::VERSION_PATCH << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    // Create tunnel engine
    armora::TunnelEngine tunnel;
    g_tunnel = &tunnel;

    armora::TunnelConfig config;
    config.localInterface = opts.localInterface.c_str();
    config.localPort = opts.localPort;
    config.remoteAddress = opts.remoteAddress.c_str();
    config.remotePort = opts.remotePort;
    config.promiscuousMode = true;

    // Configure
    armora::ErrorCode err = tunnel.configure(config);
    if (err != armora::ErrorCode::Success) {
        std::cerr << "Failed to configure tunnel (error: " 
                  << static_cast<int>(err) << ")" << std::endl;
        return 1;
    }

    // Set key
    err = tunnel.setPreSharedKeyHex(opts.keyHex);
    if (err != armora::ErrorCode::Success) {
        std::cerr << "Failed to set key (error: " 
                  << static_cast<int>(err) << ")" << std::endl;
        return 1;
    }

    // Print configuration
    std::cout << "Configuration:" << std::endl;
    std::cout << "  Interface: " << opts.localInterface << std::endl;
    std::cout << "  Local:     UDP port " << opts.localPort << std::endl;
    std::cout << "  Remote:    " << opts.remoteAddress << ":" << opts.remotePort << std::endl;
    std::cout << "  Crypto:    " << tunnel.getCryptoInfo() << std::endl;
    std::cout << std::endl;

    // Initialize
    std::cout << "Initializing tunnel..." << std::endl;
    err = tunnel.initialize();
    if (err != armora::ErrorCode::Success) {
        std::cerr << "Failed to initialize (error: " 
                  << static_cast<int>(err) << ")" << std::endl;
        return 1;
    }

    // Start
    std::cout << "Starting tunnel..." << std::endl;
    err = tunnel.start();
    if (err != armora::ErrorCode::Success) {
        std::cerr << "Failed to start (error: " 
                  << static_cast<int>(err) << ")" << std::endl;
        return 1;
    }

    std::cout << "Tunnel running. Press Ctrl+C to stop." << std::endl;
    if (opts.showStats) {
        std::cout << std::endl;
    }

    // Main loop
    while (g_running && tunnel.isRunning()) {
        if (opts.showStats) {
            printStats(tunnel.getStats());
        }
        std::this_thread::sleep_for(
            std::chrono::seconds(opts.showStats ? opts.statsIntervalSec : 1));
    }

    // Cleanup
    std::cout << std::endl;
    std::cout << "Stopping tunnel..." << std::endl;
    tunnel.stop();

    // Final stats
    const auto& stats = tunnel.getStats();
    std::cout << std::endl;
    std::cout << "Final Statistics:" << std::endl;
    std::cout << "  Packets out:     " << stats.packetsOut.load() << std::endl;
    std::cout << "  Packets in:      " << stats.packetsIn.load() << std::endl;
    std::cout << "  Bytes out:       " << stats.bytesOut.load() << std::endl;
    std::cout << "  Bytes in:        " << stats.bytesIn.load() << std::endl;
    std::cout << "  Encrypt errors:  " << stats.encryptErrors.load() << std::endl;
    std::cout << "  Decrypt errors:  " << stats.decryptErrors.load() << std::endl;
    std::cout << "  Network errors:  " << stats.networkErrors.load() << std::endl;

    std::cout << std::endl;
    std::cout << "Tunnel stopped." << std::endl;

    g_tunnel = nullptr;
    return 0;
}

