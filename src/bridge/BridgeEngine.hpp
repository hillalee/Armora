#pragma once

/**
 * @file BridgeEngine.hpp
 * @brief Main bridge engine managing packet forwarding between interfaces
 * 
 * The BridgeEngine creates two threads:
 * - Thread 1: Captures from input interface, encrypts, sends to output
 * - Thread 2: Captures from output interface, decrypts, sends to input
 */

#include "armora/Types.hpp"
#include "PacketBuffer.hpp"
#include "../crypto/CryptoHandler.hpp"
#include "../network/NetworkInterface.hpp"
#include <thread>
#include <atomic>
#include <memory>
#include <chrono>

namespace armora {

/**
 * @brief Statistics for bridge operations
 */
struct BridgeStats {
    // Packet counters
    std::atomic<uint64_t> packetsEncrypted{0};
    std::atomic<uint64_t> packetsDecrypted{0};
    std::atomic<uint64_t> bytesEncrypted{0};
    std::atomic<uint64_t> bytesDecrypted{0};
    
    // Error counters
    std::atomic<uint64_t> encryptErrors{0};
    std::atomic<uint64_t> decryptErrors{0};
    std::atomic<uint64_t> captureErrors{0};
    std::atomic<uint64_t> sendErrors{0};
    
    // Latency tracking (microseconds)
    std::atomic<uint64_t> totalEncryptLatencyUs{0};
    std::atomic<uint64_t> totalDecryptLatencyUs{0};
    std::atomic<uint64_t> minEncryptLatencyUs{UINT64_MAX};
    std::atomic<uint64_t> maxEncryptLatencyUs{0};
    std::atomic<uint64_t> minDecryptLatencyUs{UINT64_MAX};
    std::atomic<uint64_t> maxDecryptLatencyUs{0};
    
    // Timing
    std::atomic<uint64_t> startTimeMs{0};

    void reset() {
        packetsEncrypted = 0;
        packetsDecrypted = 0;
        bytesEncrypted = 0;
        bytesDecrypted = 0;
        encryptErrors = 0;
        decryptErrors = 0;
        captureErrors = 0;
        sendErrors = 0;
        totalEncryptLatencyUs = 0;
        totalDecryptLatencyUs = 0;
        minEncryptLatencyUs = UINT64_MAX;
        maxEncryptLatencyUs = 0;
        minDecryptLatencyUs = UINT64_MAX;
        maxDecryptLatencyUs = 0;
    }
    
    // Helper methods
    double avgEncryptLatencyUs() const {
        uint64_t count = packetsEncrypted.load();
        return count > 0 ? static_cast<double>(totalEncryptLatencyUs.load()) / count : 0.0;
    }
    
    double avgDecryptLatencyUs() const {
        uint64_t count = packetsDecrypted.load();
        return count > 0 ? static_cast<double>(totalDecryptLatencyUs.load()) / count : 0.0;
    }
    
    double throughputMbps() const {
        uint64_t start = startTimeMs.load();
        if (start == 0) return 0.0;
        uint64_t now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()
            ).count()
        );
        uint64_t elapsedMs = now - start;
        if (elapsedMs == 0) return 0.0;
        uint64_t totalBytes = bytesEncrypted.load() + bytesDecrypted.load();
        return (totalBytes * 8.0 / 1000000.0) / (elapsedMs / 1000.0);
    }
    
    double packetsPerSecond() const {
        uint64_t start = startTimeMs.load();
        if (start == 0) return 0.0;
        uint64_t now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()
            ).count()
        );
        uint64_t elapsedMs = now - start;
        if (elapsedMs == 0) return 0.0;
        uint64_t totalPackets = packetsEncrypted.load() + packetsDecrypted.load();
        return totalPackets / (elapsedMs / 1000.0);
    }
};

/**
 * @brief Main bridge engine for transparent encryption/decryption
 * 
 * Manages two network interfaces and provides bidirectional packet
 * forwarding with encryption/decryption.
 * 
 * Usage:
 * @code
 * BridgeConfig config;
 * config.inputInterface = "eth0";
 * config.outputInterface = "eth1";
 * 
 * BridgeEngine bridge;
 * bridge.configure(config);
 * bridge.setPreSharedKey(key);
 * bridge.start();
 * // ... bridge runs until stop() is called
 * bridge.stop();
 * @endcode
 */
class BridgeEngine {
public:
    BridgeEngine();
    ~BridgeEngine();

    // Non-copyable, non-movable
    BridgeEngine(const BridgeEngine&) = delete;
    BridgeEngine& operator=(const BridgeEngine&) = delete;

    // ========================================================================
    // Configuration
    // ========================================================================

    /**
     * @brief Configure the bridge
     * @param config Bridge configuration
     * @return Success or error code
     */
    ErrorCode configure(const BridgeConfig& config);

    /**
     * @brief Set pre-shared key for encryption
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
     * @brief Initialize the bridge (open interfaces, init crypto)
     * @return Success or error code
     */
    ErrorCode initialize();

    /**
     * @brief Start the bridge threads
     * @return Success or error code
     */
    ErrorCode start();

    /**
     * @brief Stop the bridge threads
     */
    void stop();

    /**
     * @brief Check if bridge is running
     */
    bool isRunning() const;

    /**
     * @brief Get current status
     */
    BridgeStatus getStatus() const;

    // ========================================================================
    // Statistics
    // ========================================================================

    /**
     * @brief Get current statistics
     */
    const BridgeStats& getStats() const;

    /**
     * @brief Reset statistics
     */
    void resetStats();

    // ========================================================================
    // Information
    // ========================================================================

    /**
     * @brief Get crypto provider info
     */
    std::string getCryptoInfo() const;

    /**
     * @brief Get input interface name
     */
    std::string getInputInterface() const;

    /**
     * @brief Get output interface name
     */
    std::string getOutputInterface() const;

private:
    // ========================================================================
    // Thread Functions
    // ========================================================================

    /**
     * @brief Encrypt thread: input -> encrypt -> output
     */
    void encryptThreadFunc();

    /**
     * @brief Decrypt thread: output -> decrypt -> input
     */
    void decryptThreadFunc();

    /**
     * @brief Process a single packet for encryption
     */
    void processEncryptPacket(const uint8_t* data, size_t length);

    /**
     * @brief Process a single packet for decryption
     */
    void processDecryptPacket(const uint8_t* data, size_t length);

    // ========================================================================
    // State
    // ========================================================================

    BridgeConfig m_config;
    std::atomic<BridgeStatus> m_status{BridgeStatus::Stopped};
    std::atomic<bool> m_shouldStop{false};

    // Network interfaces
    std::unique_ptr<NetworkInterface> m_inputInterface;
    std::unique_ptr<NetworkInterface> m_outputInterface;

    // Crypto handler
    std::unique_ptr<CryptoHandler> m_crypto;

    // Worker threads
    std::thread m_encryptThread;
    std::thread m_decryptThread;

    // Buffer pools (one per thread to avoid contention)
    std::unique_ptr<PacketBufferPool> m_encryptBuffers;
    std::unique_ptr<PacketBufferPool> m_decryptBuffers;

    // Statistics
    BridgeStats m_stats;

    // Callbacks
    PacketCallback m_onPacketReceived;
    StatusCallback m_onStatusChange;
    StatsCallback m_onStats;

    // ========================================================================
    // Internal Helpers
    // ========================================================================

    void setStatus(BridgeStatus status, ErrorCode error = ErrorCode::Success);
};

} // namespace armora

