#pragma once

/**
 * @file TunnelEngine.hpp
 * @brief Tunnel engine for IP-based encrypted communication
 * 
 * Unlike BridgeEngine which works at Layer 2 between two local interfaces,
 * TunnelEngine captures from a local interface and sends encrypted packets
 * over UDP to a remote peer.
 */

#include "armora/Types.hpp"
#include "UdpTunnel.hpp"
#include "../crypto/CryptoHandler.hpp"
#include "../network/NetworkInterface.hpp"
#include "../bridge/PacketBuffer.hpp"

#include <thread>
#include <atomic>
#include <memory>

namespace armora {

/**
 * @brief Configuration for tunnel engine
 */
struct TunnelConfig {
    /// Local network interface to capture from (e.g., "eth0")
    const char* localInterface = "eth0";
    
    /// Local UDP port to bind
    uint16_t localPort = 5000;
    
    /// Remote peer IP address
    const char* remoteAddress = nullptr;
    
    /// Remote peer UDP port
    uint16_t remotePort = 5000;
    
    /// Pre-shared key (optional, if not using KEM)
    const uint8_t* preSharedKey = nullptr;
    size_t preSharedKeyLength = 0;
    
    /// Enable promiscuous mode on local interface
    bool promiscuousMode = true;
    
    /// Packet capture timeout in milliseconds
    int captureTimeoutMs = 1;
    
    /// Number of pre-allocated packet buffers
    size_t bufferCount = DEFAULT_BUFFER_COUNT;
};

/**
 * @brief Statistics for tunnel operations
 */
struct TunnelStats {
    std::atomic<uint64_t> packetsOut{0};      // Local -> Tunnel
    std::atomic<uint64_t> packetsIn{0};       // Tunnel -> Local
    std::atomic<uint64_t> bytesOut{0};
    std::atomic<uint64_t> bytesIn{0};
    std::atomic<uint64_t> encryptErrors{0};
    std::atomic<uint64_t> decryptErrors{0};
    std::atomic<uint64_t> networkErrors{0};
    
    void reset() {
        packetsOut = 0;
        packetsIn = 0;
        bytesOut = 0;
        bytesIn = 0;
        encryptErrors = 0;
        decryptErrors = 0;
        networkErrors = 0;
    }
};

/**
 * @brief Tunnel engine for encrypted point-to-point communication over IP
 * 
 * Architecture:
 * ```
 * Local Device <-> [eth0] TunnelEngine [UDP:5000] <-> Internet <-> Remote Armora
 * ```
 * 
 * Thread model:
 * - Outbound thread: Captures from local interface, encrypts, sends via UDP
 * - Inbound thread: Receives from UDP, decrypts, injects to local interface
 */
class TunnelEngine {
public:
    TunnelEngine();
    ~TunnelEngine();

    // Non-copyable
    TunnelEngine(const TunnelEngine&) = delete;
    TunnelEngine& operator=(const TunnelEngine&) = delete;

    // ========================================================================
    // Configuration
    // ========================================================================

    /**
     * @brief Configure the tunnel
     * @param config Tunnel configuration
     * @return Success or error code
     */
    ErrorCode configure(const TunnelConfig& config);

    /**
     * @brief Set pre-shared key
     * @param key 32-byte AES-256 key
     * @return Success or error code
     */
    ErrorCode setPreSharedKey(ByteSpan key);

    /**
     * @brief Set pre-shared key from hex string
     * @param hexKey 64-character hex string
     * @return Success or error code
     */
    ErrorCode setPreSharedKeyHex(const std::string& hexKey);

    // ========================================================================
    // Lifecycle
    // ========================================================================

    /**
     * @brief Initialize the tunnel
     * @return Success or error code
     */
    ErrorCode initialize();

    /**
     * @brief Start the tunnel threads
     * @return Success or error code
     */
    ErrorCode start();

    /**
     * @brief Stop the tunnel
     */
    void stop();

    /**
     * @brief Check if tunnel is running
     */
    bool isRunning() const;

    /**
     * @brief Get current status
     */
    BridgeStatus getStatus() const;

    // ========================================================================
    // Statistics
    // ========================================================================

    const TunnelStats& getStats() const;
    void resetStats();

    // ========================================================================
    // Information
    // ========================================================================

    std::string getCryptoInfo() const;
    std::string getLocalInterface() const;
    std::string getRemotePeer() const;

private:
    /**
     * @brief Outbound thread: local interface -> encrypt -> UDP
     */
    void outboundThreadFunc();

    /**
     * @brief Inbound thread: UDP -> decrypt -> local interface
     */
    void inboundThreadFunc();

    void setStatus(BridgeStatus status);

    // Configuration
    TunnelConfig m_config;
    std::atomic<BridgeStatus> m_status{BridgeStatus::Stopped};
    std::atomic<bool> m_shouldStop{false};

    // Components
    std::unique_ptr<NetworkInterface> m_localInterface;
    std::unique_ptr<UdpTunnel> m_tunnel;
    std::unique_ptr<CryptoHandler> m_crypto;

    // Threads
    std::thread m_outboundThread;
    std::thread m_inboundThread;

    // Buffers
    std::unique_ptr<PacketBufferPool> m_outboundBuffers;
    std::unique_ptr<PacketBufferPool> m_inboundBuffers;

    // Stats
    TunnelStats m_stats;
};

} // namespace armora

