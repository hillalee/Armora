/**
 * @file main.cpp
 * @brief Entry point for the Armora Quantum-Resistant Ethernet Bridge
 * 
 * This executable provides a command-line interface for running the bridge
 * on a NanoPi or similar Linux device with two Ethernet interfaces.
 * 
 * Usage:
 *   sudo ./armora-bridge -i eth0 -o eth1 -k <hex-key>
 */

#include "bridge/BridgeEngine.hpp"
#include "network/NetworkInterface.hpp"
#include "armora/Types.hpp"

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <atomic>
#include <chrono>
#include <thread>
#include <climits>

// ============================================================================
// Global State for Signal Handling
// ============================================================================

static std::atomic<bool> g_running{true};
static armora::BridgeEngine* g_bridge = nullptr;

static void signalHandler(int signum) {
    std::cout << "\nReceived signal " << signum << ", shutting down..." << std::endl;
    g_running = false;
    if (g_bridge) {
        g_bridge->stop();
    }
}

// ============================================================================
// Command Line Parsing
// ============================================================================

struct Options {
    std::string inputInterface = "eth0";
    std::string outputInterface = "eth1";
    std::string keyHex;
    bool verbose = false;
    bool showStats = false;
    int statsIntervalSec = 5;
    bool listInterfaces = false;
    bool help = false;
};

static void printUsage(const char* programName) {
    std::cout << R"(
Armora - Quantum-Resistant Ethernet Bridge
============================================

Usage: )" << programName << R"( [OPTIONS]

Options:
  -i, --input <iface>     Input interface (default: eth0)
  -o, --output <iface>    Output interface (default: eth1)
  -k, --key <hex>         Pre-shared key (64 hex characters = 32 bytes)
  -v, --verbose           Enable verbose output
  -s, --stats [interval]  Show statistics every N seconds (default: 5)
  -l, --list              List available network interfaces
  -h, --help              Show this help message

Example:
  # Generate a random 32-byte key:
  openssl rand -hex 32

  # Run the bridge:
  sudo ./armora-bridge -i eth0 -o eth1 -k $(openssl rand -hex 32) -s

Note: This program requires root privileges for raw socket access.

)" << std::endl;
}

static Options parseArgs(int argc, char* argv[]) {
    Options opts;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            opts.help = true;
        } else if (arg == "-l" || arg == "--list") {
            opts.listInterfaces = true;
        } else if (arg == "-v" || arg == "--verbose") {
            opts.verbose = true;
        } else if (arg == "-s" || arg == "--stats") {
            opts.showStats = true;
            // Check for optional interval argument
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                opts.statsIntervalSec = std::atoi(argv[++i]);
                if (opts.statsIntervalSec < 1) opts.statsIntervalSec = 1;
            }
        } else if ((arg == "-i" || arg == "--input") && i + 1 < argc) {
            opts.inputInterface = argv[++i];
        } else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            opts.outputInterface = argv[++i];
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

static void printStats(const armora::BridgeStats& stats) {
    std::cout << "\r"
              << "Enc: " << std::setw(8) << stats.packetsEncrypted.load() << " pkts "
              << "(" << std::setw(10) << stats.bytesEncrypted.load() << " B) | "
              << "Dec: " << std::setw(8) << stats.packetsDecrypted.load() << " pkts "
              << "(" << std::setw(10) << stats.bytesDecrypted.load() << " B) | "
              << "Err: " << stats.encryptErrors.load() + stats.decryptErrors.load()
              << std::flush;
}

// ============================================================================
// Main Entry Point
// ============================================================================

int main(int argc, char* argv[]) {
    // Parse command line
    Options opts = parseArgs(argc, argv);

    if (opts.help) {
        printUsage(argv[0]);
        return 0;
    }

    // List interfaces mode
    if (opts.listInterfaces) {
        std::cout << "Available network interfaces:" << std::endl;
        auto interfaces = armora::listNetworkInterfaces();
        for (const auto& iface : interfaces) {
            std::cout << "  - " << iface << std::endl;
        }
        return 0;
    }

    // Validate key
    if (opts.keyHex.empty()) {
        std::cerr << "Error: Pre-shared key required. Use -k <hex-key>" << std::endl;
        std::cerr << "Generate a key with: openssl rand -hex 32" << std::endl;
        return 1;
    }

    if (opts.keyHex.length() != 64) {
        std::cerr << "Error: Key must be 64 hex characters (32 bytes)" << std::endl;
        return 1;
    }

    // Check for root privileges
    if (geteuid() != 0) {
        std::cerr << "Warning: Not running as root. Raw socket access may fail." << std::endl;
    }

    // Setup signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    // Print startup banner
    std::cout << "========================================" << std::endl;
    std::cout << "  Armora Quantum-Resistant Bridge v"
              << armora::VERSION_MAJOR << "."
              << armora::VERSION_MINOR << "."
              << armora::VERSION_PATCH << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    // Create and configure bridge
    armora::BridgeEngine bridge;
    g_bridge = &bridge;

    armora::BridgeConfig config;
    config.inputInterface = opts.inputInterface.c_str();
    config.outputInterface = opts.outputInterface.c_str();
    config.promiscuousMode = true;

    // Status callback
    config.onStatusChange = [&opts](armora::BridgeStatus status, armora::ErrorCode error) {
        if (opts.verbose) {
            const char* statusStr = "Unknown";
            switch (status) {
                case armora::BridgeStatus::Stopped: statusStr = "Stopped"; break;
                case armora::BridgeStatus::Starting: statusStr = "Starting"; break;
                case armora::BridgeStatus::Running: statusStr = "Running"; break;
                case armora::BridgeStatus::Stopping: statusStr = "Stopping"; break;
                case armora::BridgeStatus::Error: statusStr = "Error"; break;
            }
            std::cout << "[Status] " << statusStr;
            if (error != armora::ErrorCode::Success) {
                std::cout << " (error code: " << static_cast<int>(error) << ")";
            }
            std::cout << std::endl;
        }
    };

    // Configure bridge
    armora::ErrorCode err = bridge.configure(config);
    if (err != armora::ErrorCode::Success) {
        std::cerr << "Failed to configure bridge (error: " 
                  << static_cast<int>(err) << ")" << std::endl;
        return 1;
    }

    // Set pre-shared key
    err = bridge.setPreSharedKeyHex(opts.keyHex);
    if (err != armora::ErrorCode::Success) {
        std::cerr << "Failed to set key (error: " 
                  << static_cast<int>(err) << ")" << std::endl;
        return 1;
    }

    // Print configuration
    std::cout << "Configuration:" << std::endl;
    std::cout << "  Input:  " << opts.inputInterface << std::endl;
    std::cout << "  Output: " << opts.outputInterface << std::endl;
    std::cout << "  Crypto: " << bridge.getCryptoInfo() << std::endl;
    std::cout << std::endl;

    // Initialize bridge
    std::cout << "Initializing interfaces..." << std::endl;
    err = bridge.initialize();
    if (err != armora::ErrorCode::Success) {
        std::cerr << "Failed to initialize (error: " 
                  << static_cast<int>(err) << ")" << std::endl;
        
        if (err == armora::ErrorCode::NetworkPermissionDenied) {
            std::cerr << "Permission denied. Try running with sudo." << std::endl;
        } else if (err == armora::ErrorCode::NetworkInterfaceNotFound) {
            std::cerr << "Interface not found. Use -l to list available interfaces." << std::endl;
        }
        return 1;
    }

    // Start bridge
    std::cout << "Starting bridge..." << std::endl;
    err = bridge.start();
    if (err != armora::ErrorCode::Success) {
        std::cerr << "Failed to start (error: " 
                  << static_cast<int>(err) << ")" << std::endl;
        return 1;
    }

    std::cout << "Bridge running. Press Ctrl+C to stop." << std::endl;
    if (opts.showStats) {
        std::cout << std::endl;
    }

    // Main loop - show stats if enabled
    while (g_running && bridge.isRunning()) {
        if (opts.showStats) {
            printStats(bridge.getStats());
        }
        std::this_thread::sleep_for(
            std::chrono::seconds(opts.showStats ? opts.statsIntervalSec : 1));
    }

    // Cleanup
    std::cout << std::endl;
    std::cout << "Stopping bridge..." << std::endl;
    bridge.stop();

    // Final stats
    const auto& stats = bridge.getStats();
    std::cout << std::endl;
    std::cout << "Final Statistics:" << std::endl;
    std::cout << "  Packets encrypted: " << stats.packetsEncrypted.load() << std::endl;
    std::cout << "  Packets decrypted: " << stats.packetsDecrypted.load() << std::endl;
    std::cout << "  Bytes encrypted:   " << stats.bytesEncrypted.load() << std::endl;
    std::cout << "  Bytes decrypted:   " << stats.bytesDecrypted.load() << std::endl;
    std::cout << "  Encrypt errors:    " << stats.encryptErrors.load() << std::endl;
    std::cout << "  Decrypt errors:    " << stats.decryptErrors.load() << std::endl;
    std::cout << "  Capture errors:    " << stats.captureErrors.load() << std::endl;
    std::cout << "  Send errors:       " << stats.sendErrors.load() << std::endl;
    
    std::cout << std::endl;
    std::cout << "Performance:" << std::endl;
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "  Avg encrypt latency: " << stats.avgEncryptLatencyUs() << " us" << std::endl;
    std::cout << "  Avg decrypt latency: " << stats.avgDecryptLatencyUs() << " us" << std::endl;
    if (stats.minEncryptLatencyUs.load() != UINT64_MAX) {
        std::cout << "  Min/Max encrypt:     " << stats.minEncryptLatencyUs.load() 
                  << "/" << stats.maxEncryptLatencyUs.load() << " us" << std::endl;
    }
    if (stats.minDecryptLatencyUs.load() != UINT64_MAX) {
        std::cout << "  Min/Max decrypt:     " << stats.minDecryptLatencyUs.load()
                  << "/" << stats.maxDecryptLatencyUs.load() << " us" << std::endl;
    }
    std::cout << "  Throughput:          " << stats.throughputMbps() << " Mbps" << std::endl;
    std::cout << "  Packets/sec:         " << stats.packetsPerSecond() << " pps" << std::endl;

    std::cout << std::endl;
    std::cout << "Bridge stopped." << std::endl;

    g_bridge = nullptr;
    return 0;
}

