/**
 * @file TunnelEngine.cpp
 * @brief Implementation of tunnel engine for IP-based communication
 */

#include "TunnelEngine.hpp"
#include "../network/PcapCapture.hpp"
#include <cstring>

namespace armora {

// ============================================================================
// Construction / Destruction
// ============================================================================

TunnelEngine::TunnelEngine()
    : m_crypto(std::make_unique<CryptoHandler>()) {
}

TunnelEngine::~TunnelEngine() {
    stop();
}

// ============================================================================
// Configuration
// ============================================================================

ErrorCode TunnelEngine::configure(const TunnelConfig& config) {
    if (m_status != BridgeStatus::Stopped) {
        return ErrorCode::BridgeAlreadyRunning;
    }

    m_config = config;

    // Create network interface
    m_localInterface = std::make_unique<NetworkInterface>(config.localInterface);
    m_localInterface->setCaptureTimeout(config.captureTimeoutMs);
    m_localInterface->setPromiscuousMode(config.promiscuousMode);

    // Create UDP tunnel
    m_tunnel = std::make_unique<UdpTunnel>(config.localPort);
    if (config.remoteAddress && config.remotePort > 0) {
        m_tunnel->setRemotePeer(config.remoteAddress, config.remotePort);
    }
    m_tunnel->setReceiveTimeout(100);  // 100ms receive timeout

    // Create buffer pools
    m_outboundBuffers = std::make_unique<PacketBufferPool>(config.bufferCount);
    m_inboundBuffers = std::make_unique<PacketBufferPool>(config.bufferCount);

    // Handle pre-shared key if provided
    if (config.preSharedKey && config.preSharedKeyLength == AES_KEY_SIZE) {
        return setPreSharedKey(ByteSpan(config.preSharedKey, config.preSharedKeyLength));
    }

    return ErrorCode::Success;
}

ErrorCode TunnelEngine::setPreSharedKey(ByteSpan key) {
    if (key.size() != AES_KEY_SIZE) {
        return ErrorCode::InvalidArgument;
    }

    ErrorCode err = m_crypto->initialize();
    if (err != ErrorCode::Success) {
        return err;
    }

    return m_crypto->setPreSharedKey(key);
}

ErrorCode TunnelEngine::setPreSharedKeyHex(const std::string& hexKey) {
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

ErrorCode TunnelEngine::initialize() {
    if (m_status != BridgeStatus::Stopped) {
        return ErrorCode::BridgeAlreadyRunning;
    }

    setStatus(BridgeStatus::Starting);

    // Initialize crypto
    ErrorCode err = m_crypto->initialize();
    if (err != ErrorCode::Success) {
        setStatus(BridgeStatus::Error);
        return err;
    }

    // Open local network interface
    err = m_localInterface->open();
    if (err != ErrorCode::Success) {
        setStatus(BridgeStatus::Error);
        return err;
    }

    // Open UDP tunnel
    err = m_tunnel->open();
    if (err != ErrorCode::Success) {
        m_localInterface->close();
        setStatus(BridgeStatus::Error);
        return err;
    }

    setStatus(BridgeStatus::Stopped);
    return ErrorCode::Success;
}

ErrorCode TunnelEngine::start() {
    if (m_status == BridgeStatus::Running) {
        return ErrorCode::BridgeAlreadyRunning;
    }

    // Ensure initialized
    if (!m_localInterface || !m_localInterface->isOpen()) {
        ErrorCode err = initialize();
        if (err != ErrorCode::Success) {
            return err;
        }
    }

    // Check crypto is ready
    if (!m_crypto->isReady()) {
        setStatus(BridgeStatus::Error);
        return ErrorCode::CryptoInitError;
    }

    // Check remote peer is configured
    if (m_tunnel->getRemoteAddress().empty()) {
        setStatus(BridgeStatus::Error);
        return ErrorCode::InvalidArgument;
    }

    m_shouldStop = false;
    setStatus(BridgeStatus::Starting);

    // Start threads
    m_outboundThread = std::thread(&TunnelEngine::outboundThreadFunc, this);
    m_inboundThread = std::thread(&TunnelEngine::inboundThreadFunc, this);

    setStatus(BridgeStatus::Running);
    return ErrorCode::Success;
}

void TunnelEngine::stop() {
    if (m_status != BridgeStatus::Running && m_status != BridgeStatus::Starting) {
        return;
    }

    setStatus(BridgeStatus::Stopping);
    m_shouldStop = true;

    // Break loops
    if (m_localInterface) {
        m_localInterface->breakLoop();
    }
    if (m_tunnel) {
        m_tunnel->stopReceiveLoop();
    }

    // Wait for threads
    if (m_outboundThread.joinable()) {
        m_outboundThread.join();
    }
    if (m_inboundThread.joinable()) {
        m_inboundThread.join();
    }

    // Close resources
    if (m_localInterface) {
        m_localInterface->close();
    }
    if (m_tunnel) {
        m_tunnel->close();
    }

    setStatus(BridgeStatus::Stopped);
}

bool TunnelEngine::isRunning() const {
    return m_status == BridgeStatus::Running;
}

BridgeStatus TunnelEngine::getStatus() const {
    return m_status;
}

// ============================================================================
// Statistics
// ============================================================================

const TunnelStats& TunnelEngine::getStats() const {
    return m_stats;
}

void TunnelEngine::resetStats() {
    m_stats.reset();
}

// ============================================================================
// Information
// ============================================================================

std::string TunnelEngine::getCryptoInfo() const {
    return m_crypto ? m_crypto->getProviderInfo() : "Not initialized";
}

std::string TunnelEngine::getLocalInterface() const {
    return m_localInterface ? m_localInterface->getName() : "";
}

std::string TunnelEngine::getRemotePeer() const {
    if (!m_tunnel) return "";
    return m_tunnel->getRemoteAddress() + ":" + std::to_string(m_tunnel->getRemotePort());
}

// ============================================================================
// Thread Functions
// ============================================================================

void TunnelEngine::outboundThreadFunc() {
    uint8_t captureBuffer[PacketBuffer::BUFFER_SIZE];
    uint8_t encryptBuffer[PacketBuffer::BUFFER_SIZE];
    uint64_t timestamp;

    while (!m_shouldStop) {
        size_t packetLen = 0;
        
        ErrorCode err = m_localInterface->capturePacket(
            captureBuffer, sizeof(captureBuffer), packetLen, timestamp);

        if (err != ErrorCode::Success || packetLen == 0) {
            continue;
        }

        // Encrypt the entire Ethernet frame
        size_t encryptedLen = 0;
        err = m_crypto->encryptPacket(captureBuffer, packetLen,
                                       encryptBuffer, encryptedLen);
        
        if (err != ErrorCode::Success) {
            m_stats.encryptErrors++;
            continue;
        }

        // Send via UDP tunnel
        err = m_tunnel->send(encryptBuffer, encryptedLen);
        if (err != ErrorCode::Success) {
            m_stats.networkErrors++;
            continue;
        }

        m_stats.packetsOut++;
        m_stats.bytesOut += packetLen;
    }
}

void TunnelEngine::inboundThreadFunc() {
    uint8_t receiveBuffer[PacketBuffer::BUFFER_SIZE];
    uint8_t decryptBuffer[PacketBuffer::BUFFER_SIZE];

    while (!m_shouldStop) {
        size_t receivedLen = 0;
        
        ErrorCode err = m_tunnel->receive(receiveBuffer, sizeof(receiveBuffer),
                                           receivedLen, nullptr, nullptr);

        if (err != ErrorCode::Success || receivedLen == 0) {
            continue;
        }

        // Decrypt the packet
        size_t decryptedLen = 0;
        err = m_crypto->decryptPacket(receiveBuffer, receivedLen,
                                       decryptBuffer, decryptedLen);
        
        if (err != ErrorCode::Success) {
            m_stats.decryptErrors++;
            continue;
        }

        // Inject to local interface
        err = m_localInterface->sendPacket(decryptBuffer, decryptedLen);
        if (err != ErrorCode::Success) {
            m_stats.networkErrors++;
            continue;
        }

        m_stats.packetsIn++;
        m_stats.bytesIn += decryptedLen;
    }
}

void TunnelEngine::setStatus(BridgeStatus status) {
    m_status = status;
}

} // namespace armora

