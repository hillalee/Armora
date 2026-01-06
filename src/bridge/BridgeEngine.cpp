/**
 * @file BridgeEngine.cpp
 * @brief Implementation of the main bridge engine
 */

#include "BridgeEngine.hpp"
#include "../network/PcapCapture.hpp"
#include <algorithm>
#include <chrono>

namespace armora {

// ============================================================================
// Construction / Destruction
// ============================================================================

BridgeEngine::BridgeEngine()
    : m_crypto(std::make_unique<CryptoHandler>()) {
}

BridgeEngine::~BridgeEngine() {
    stop();
}

// ============================================================================
// Configuration
// ============================================================================

ErrorCode BridgeEngine::configure(const BridgeConfig& config) {
    if (m_status != BridgeStatus::Stopped) {
        return ErrorCode::BridgeAlreadyRunning;
    }

    m_config = config;

    // Store callbacks
    m_onPacketReceived = config.onPacketReceived;
    m_onStatusChange = config.onStatusChange;
    m_onStats = config.onStats;

    // Create network interfaces
    m_inputInterface = std::make_unique<NetworkInterface>(config.inputInterface);
    m_outputInterface = std::make_unique<NetworkInterface>(config.outputInterface);

    // Configure interfaces
    m_inputInterface->setCaptureTimeout(config.captureTimeoutMs);
    m_inputInterface->setPromiscuousMode(config.promiscuousMode);
    m_outputInterface->setCaptureTimeout(config.captureTimeoutMs);
    m_outputInterface->setPromiscuousMode(config.promiscuousMode);

    // Create buffer pools
    m_encryptBuffers = std::make_unique<PacketBufferPool>(config.bufferCount);
    m_decryptBuffers = std::make_unique<PacketBufferPool>(config.bufferCount);

    // Handle pre-shared key if provided
    if (config.preSharedKey && config.preSharedKeyLength == AES_KEY_SIZE) {
        return setPreSharedKey(ByteSpan(config.preSharedKey, config.preSharedKeyLength));
    }

    return ErrorCode::Success;
}

ErrorCode BridgeEngine::setPreSharedKey(ByteSpan key) {
    if (key.size() != AES_KEY_SIZE) {
        return ErrorCode::InvalidArgument;
    }

    // Initialize crypto if needed
    ErrorCode err = m_crypto->initialize();
    if (err != ErrorCode::Success) {
        return err;
    }

    return m_crypto->setPreSharedKey(key);
}

ErrorCode BridgeEngine::setPreSharedKeyHex(const std::string& hexKey) {
    if (hexKey.length() != AES_KEY_SIZE * 2) {
        return ErrorCode::InvalidArgument;
    }

    AESKey key;
    for (size_t i = 0; i < AES_KEY_SIZE; ++i) {
        std::string byteStr = hexKey.substr(i * 2, 2);
        try {
            key[i] = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
        } catch (...) {
            return ErrorCode::InvalidArgument;
        }
    }

    return setPreSharedKey(ByteSpan(key.data(), key.size()));
}

// ============================================================================
// Lifecycle
// ============================================================================

ErrorCode BridgeEngine::initialize() {
    if (m_status != BridgeStatus::Stopped) {
        return ErrorCode::BridgeAlreadyRunning;
    }

    setStatus(BridgeStatus::Starting);

    // Initialize crypto
    ErrorCode err = m_crypto->initialize();
    if (err != ErrorCode::Success) {
        setStatus(BridgeStatus::Error, err);
        return err;
    }

    // Open input interface
    err = m_inputInterface->open();
    if (err != ErrorCode::Success) {
        setStatus(BridgeStatus::Error, err);
        return err;
    }

    // Open output interface
    err = m_outputInterface->open();
    if (err != ErrorCode::Success) {
        m_inputInterface->close();
        setStatus(BridgeStatus::Error, err);
        return err;
    }

    setStatus(BridgeStatus::Stopped);
    return ErrorCode::Success;
}

ErrorCode BridgeEngine::start() {
    if (m_status == BridgeStatus::Running) {
        return ErrorCode::BridgeAlreadyRunning;
    }

    // Make sure we're initialized
    if (!m_inputInterface || !m_inputInterface->isOpen()) {
        ErrorCode err = initialize();
        if (err != ErrorCode::Success) {
            return err;
        }
    }

    // Check crypto is ready
    if (!m_crypto->isReady()) {
        setStatus(BridgeStatus::Error, ErrorCode::CryptoInitError);
        return ErrorCode::CryptoInitError;
    }

    m_shouldStop = false;
    setStatus(BridgeStatus::Starting);

    // Record start time for throughput calculations
    m_stats.startTimeMs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        ).count()
    );

    // Start worker threads
    m_encryptThread = std::thread(&BridgeEngine::encryptThreadFunc, this);
    m_decryptThread = std::thread(&BridgeEngine::decryptThreadFunc, this);

    setStatus(BridgeStatus::Running);
    return ErrorCode::Success;
}

void BridgeEngine::stop() {
    if (m_status != BridgeStatus::Running && m_status != BridgeStatus::Starting) {
        return;
    }

    setStatus(BridgeStatus::Stopping);
    m_shouldStop = true;

    // Break capture loops
    if (m_inputInterface) {
        m_inputInterface->breakLoop();
    }
    if (m_outputInterface) {
        m_outputInterface->breakLoop();
    }

    // Wait for threads to finish
    if (m_encryptThread.joinable()) {
        m_encryptThread.join();
    }
    if (m_decryptThread.joinable()) {
        m_decryptThread.join();
    }

    // Close interfaces
    if (m_inputInterface) {
        m_inputInterface->close();
    }
    if (m_outputInterface) {
        m_outputInterface->close();
    }

    setStatus(BridgeStatus::Stopped);
}

bool BridgeEngine::isRunning() const {
    return m_status == BridgeStatus::Running;
}

BridgeStatus BridgeEngine::getStatus() const {
    return m_status;
}

// ============================================================================
// Statistics
// ============================================================================

const BridgeStats& BridgeEngine::getStats() const {
    return m_stats;
}

void BridgeEngine::resetStats() {
    m_stats.reset();
}

// ============================================================================
// Information
// ============================================================================

std::string BridgeEngine::getCryptoInfo() const {
    return m_crypto ? m_crypto->getProviderInfo() : "Not initialized";
}

std::string BridgeEngine::getInputInterface() const {
    return m_inputInterface ? m_inputInterface->getName() : "";
}

std::string BridgeEngine::getOutputInterface() const {
    return m_outputInterface ? m_outputInterface->getName() : "";
}

// ============================================================================
// Thread Functions
// ============================================================================

void BridgeEngine::encryptThreadFunc() {
    uint8_t captureBuffer[PacketBuffer::BUFFER_SIZE];
    uint64_t timestamp;

    while (!m_shouldStop) {
        size_t packetLen = 0;
        
        ErrorCode err = m_inputInterface->capturePacket(
            captureBuffer, sizeof(captureBuffer), packetLen, timestamp);

        if (err == ErrorCode::Success && packetLen > 0) {
            processEncryptPacket(captureBuffer, packetLen);
        } else if (err != ErrorCode::Success && !m_shouldStop) {
            m_stats.captureErrors++;
        }
    }
}

void BridgeEngine::decryptThreadFunc() {
    uint8_t captureBuffer[PacketBuffer::BUFFER_SIZE];
    uint64_t timestamp;

    while (!m_shouldStop) {
        size_t packetLen = 0;
        
        ErrorCode err = m_outputInterface->capturePacket(
            captureBuffer, sizeof(captureBuffer), packetLen, timestamp);

        if (err == ErrorCode::Success && packetLen > 0) {
            processDecryptPacket(captureBuffer, packetLen);
        } else if (err != ErrorCode::Success && !m_shouldStop) {
            m_stats.captureErrors++;
        }
    }
}

void BridgeEngine::processEncryptPacket(const uint8_t* data, size_t length) {
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Callback for inspection if set
    if (m_onPacketReceived && !m_onPacketReceived(data, length)) {
        return;  // Packet dropped by callback
    }

    // Get buffer from pool
    ScopedBuffer buffer(*m_encryptBuffers);
    if (!buffer) {
        m_stats.encryptErrors++;
        return;
    }

    // For transparent bridging, we encrypt the entire Ethernet payload
    // keeping the Ethernet header intact
    if (length < ETH_HEADER_SIZE) {
        return;  // Too small, ignore
    }

    // Copy Ethernet header to output
    std::memcpy(buffer->data(), data, ETH_HEADER_SIZE);

    // Encrypt payload
    const uint8_t* payload = data + ETH_HEADER_SIZE;
    size_t payloadLen = length - ETH_HEADER_SIZE;
    
    uint8_t* encryptedPayload = buffer->data() + ETH_HEADER_SIZE;
    size_t encryptedLen = 0;

    ErrorCode err = m_crypto->encryptPacket(payload, payloadLen,
                                             encryptedPayload, encryptedLen);
    if (err != ErrorCode::Success) {
        m_stats.encryptErrors++;
        return;
    }

    size_t totalLen = ETH_HEADER_SIZE + encryptedLen;
    buffer->setLength(totalLen);

    // Send encrypted packet
    err = m_outputInterface->sendPacket(buffer->data(), totalLen);
    if (err != ErrorCode::Success) {
        m_stats.sendErrors++;
        return;
    }

    // Calculate and record latency
    auto endTime = std::chrono::high_resolution_clock::now();
    uint64_t latencyUs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count()
    );
    
    m_stats.totalEncryptLatencyUs += latencyUs;
    
    // Update min/max (using compare-exchange for thread safety)
    uint64_t currentMin = m_stats.minEncryptLatencyUs.load();
    while (latencyUs < currentMin && 
           !m_stats.minEncryptLatencyUs.compare_exchange_weak(currentMin, latencyUs)) {}
    
    uint64_t currentMax = m_stats.maxEncryptLatencyUs.load();
    while (latencyUs > currentMax &&
           !m_stats.maxEncryptLatencyUs.compare_exchange_weak(currentMax, latencyUs)) {}

    // Update stats
    m_stats.packetsEncrypted++;
    m_stats.bytesEncrypted += length;
}

void BridgeEngine::processDecryptPacket(const uint8_t* data, size_t length) {
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Callback for inspection if set
    if (m_onPacketReceived && !m_onPacketReceived(data, length)) {
        return;  // Packet dropped by callback
    }

    // Get buffer from pool
    ScopedBuffer buffer(*m_decryptBuffers);
    if (!buffer) {
        m_stats.decryptErrors++;
        return;
    }

    // Check minimum size (header + crypto overhead)
    if (length < ETH_HEADER_SIZE + CRYPTO_OVERHEAD) {
        return;  // Too small, likely not an encrypted packet - pass through?
    }

    // Copy Ethernet header to output
    std::memcpy(buffer->data(), data, ETH_HEADER_SIZE);

    // Decrypt payload
    const uint8_t* encryptedPayload = data + ETH_HEADER_SIZE;
    size_t encryptedLen = length - ETH_HEADER_SIZE;

    uint8_t* decryptedPayload = buffer->data() + ETH_HEADER_SIZE;
    size_t decryptedLen = 0;

    ErrorCode err = m_crypto->decryptPacket(encryptedPayload, encryptedLen,
                                             decryptedPayload, decryptedLen);
    if (err != ErrorCode::Success) {
        // Decryption failed - this might be a non-encrypted packet
        // For MVP, we just drop it. In production, might want passthrough mode.
        m_stats.decryptErrors++;
        return;
    }

    size_t totalLen = ETH_HEADER_SIZE + decryptedLen;
    buffer->setLength(totalLen);

    // Send decrypted packet
    err = m_inputInterface->sendPacket(buffer->data(), totalLen);
    if (err != ErrorCode::Success) {
        m_stats.sendErrors++;
        return;
    }

    // Calculate and record latency
    auto endTime = std::chrono::high_resolution_clock::now();
    uint64_t latencyUs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime).count()
    );
    
    m_stats.totalDecryptLatencyUs += latencyUs;
    
    // Update min/max (using compare-exchange for thread safety)
    uint64_t currentMin = m_stats.minDecryptLatencyUs.load();
    while (latencyUs < currentMin && 
           !m_stats.minDecryptLatencyUs.compare_exchange_weak(currentMin, latencyUs)) {}
    
    uint64_t currentMax = m_stats.maxDecryptLatencyUs.load();
    while (latencyUs > currentMax &&
           !m_stats.maxDecryptLatencyUs.compare_exchange_weak(currentMax, latencyUs)) {}

    // Update stats
    m_stats.packetsDecrypted++;
    m_stats.bytesDecrypted += totalLen;
}

// ============================================================================
// Internal Helpers
// ============================================================================

void BridgeEngine::setStatus(BridgeStatus status, ErrorCode error) {
    m_status = status;
    
    if (m_onStatusChange) {
        m_onStatusChange(status, error);
    }
}

} // namespace armora

