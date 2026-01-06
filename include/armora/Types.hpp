#pragma once

/**
 * @file Types.hpp
 * @brief Common types and constants for the Armora Quantum-Resistant Ethernet Bridge
 * 
 * This header defines the public API types that hardware vendors will use
 * when integrating the library into their firmware.
 */

#include <cstdint>
#include <cstddef>
#include <array>
#include <span>
#include <functional>

namespace armora {

// ============================================================================
// Version Information
// ============================================================================
constexpr uint32_t VERSION_MAJOR = 0;
constexpr uint32_t VERSION_MINOR = 1;
constexpr uint32_t VERSION_PATCH = 0;

// ============================================================================
// Network Constants
// ============================================================================

/// Maximum Ethernet frame size (standard MTU + headers)
constexpr size_t MAX_FRAME_SIZE = 1522;

/// Minimum Ethernet frame size
constexpr size_t MIN_FRAME_SIZE = 64;

/// Ethernet header size
constexpr size_t ETH_HEADER_SIZE = 14;

/// Maximum payload size after encryption overhead
constexpr size_t MAX_PAYLOAD_SIZE = MAX_FRAME_SIZE - ETH_HEADER_SIZE;

/// Default packet capture timeout (milliseconds)
constexpr int DEFAULT_CAPTURE_TIMEOUT_MS = 1;

/// Default packet buffer count for pre-allocation
constexpr size_t DEFAULT_BUFFER_COUNT = 256;

// ============================================================================
// Cryptographic Constants
// ============================================================================

/// AES-256-GCM key size in bytes
constexpr size_t AES_KEY_SIZE = 32;

/// AES-256-GCM IV/nonce size in bytes
constexpr size_t AES_IV_SIZE = 12;

/// AES-256-GCM authentication tag size in bytes
constexpr size_t AES_TAG_SIZE = 16;

/// Total encryption overhead per packet (IV + Tag)
constexpr size_t CRYPTO_OVERHEAD = AES_IV_SIZE + AES_TAG_SIZE;

/// Kyber1024 public key size
constexpr size_t KYBER1024_PUBLIC_KEY_SIZE = 1568;

/// Kyber1024 secret key size
constexpr size_t KYBER1024_SECRET_KEY_SIZE = 3168;

/// Kyber1024 ciphertext size
constexpr size_t KYBER1024_CIPHERTEXT_SIZE = 1568;

/// Kyber1024 shared secret size
constexpr size_t KYBER1024_SHARED_SECRET_SIZE = 32;

// ============================================================================
// Type Aliases
// ============================================================================

/// Fixed-size key type for AES-256
using AESKey = std::array<uint8_t, AES_KEY_SIZE>;

/// Fixed-size IV/nonce type
using AESIV = std::array<uint8_t, AES_IV_SIZE>;

/// Fixed-size authentication tag
using AESTag = std::array<uint8_t, AES_TAG_SIZE>;

/// Kyber1024 public key
using KyberPublicKey = std::array<uint8_t, KYBER1024_PUBLIC_KEY_SIZE>;

/// Kyber1024 secret key  
using KyberSecretKey = std::array<uint8_t, KYBER1024_SECRET_KEY_SIZE>;

/// Kyber1024 ciphertext
using KyberCiphertext = std::array<uint8_t, KYBER1024_CIPHERTEXT_SIZE>;

/// Shared secret from KEM
using SharedSecret = std::array<uint8_t, KYBER1024_SHARED_SECRET_SIZE>;

/// Byte span for zero-copy operations
using ByteSpan = std::span<const uint8_t>;
using MutableByteSpan = std::span<uint8_t>;

// ============================================================================
// Enumerations
// ============================================================================

/**
 * @brief Bridge operation mode
 */
enum class BridgeMode {
    /// Encrypt traffic from eth0 to eth1, decrypt from eth1 to eth0
    Encrypt,
    /// Decrypt traffic from eth0 to eth1, encrypt from eth1 to eth0
    Decrypt,
    /// Bidirectional encryption (both directions encrypted)
    Bidirectional
};

/**
 * @brief Bridge operational status
 */
enum class BridgeStatus {
    Stopped,
    Starting,
    Running,
    Stopping,
    Error
};

/**
 * @brief Error codes for operations
 */
enum class ErrorCode {
    Success = 0,
    
    // Network errors (100-199)
    NetworkInterfaceNotFound = 100,
    NetworkCaptureError = 101,
    NetworkSendError = 102,
    NetworkPermissionDenied = 103,
    
    // Crypto errors (200-299)
    CryptoInitError = 200,
    CryptoKeyExchangeError = 201,
    CryptoEncryptError = 202,
    CryptoDecryptError = 203,
    CryptoAuthError = 204,
    
    // Bridge errors (300-399)
    BridgeAlreadyRunning = 300,
    BridgeNotRunning = 301,
    BridgeConfigError = 302,
    
    // General errors (900-999)
    InvalidArgument = 900,
    OutOfMemory = 901,
    Unknown = 999
};

/**
 * @brief Result type for operations that can fail
 */
template<typename T>
struct Result {
    T value;
    ErrorCode error;
    
    bool ok() const { return error == ErrorCode::Success; }
    explicit operator bool() const { return ok(); }
};

// ============================================================================
// Callback Types
// ============================================================================

/**
 * @brief Callback for packet processing (before encryption/after decryption)
 * @param data Packet data
 * @param length Packet length
 * @return true to forward packet, false to drop
 */
using PacketCallback = std::function<bool(const uint8_t* data, size_t length)>;

/**
 * @brief Callback for status changes
 * @param status New bridge status
 * @param error Error code if status is Error
 */
using StatusCallback = std::function<void(BridgeStatus status, ErrorCode error)>;

/**
 * @brief Callback for statistics updates
 * @param packetsForwarded Total packets forwarded
 * @param bytesForwarded Total bytes forwarded
 * @param packetsDropped Total packets dropped
 */
using StatsCallback = std::function<void(uint64_t packetsForwarded, 
                                         uint64_t bytesForwarded,
                                         uint64_t packetsDropped)>;

// ============================================================================
// Configuration Structure
// ============================================================================

/**
 * @brief Bridge configuration
 */
struct BridgeConfig {
    /// Input interface name (e.g., "eth0")
    const char* inputInterface = "eth0";
    
    /// Output interface name (e.g., "eth1")
    const char* outputInterface = "eth1";
    
    /// Operation mode
    BridgeMode mode = BridgeMode::Encrypt;
    
    /// Pre-shared key (optional, if not using KEM)
    const uint8_t* preSharedKey = nullptr;
    size_t preSharedKeyLength = 0;
    
    /// Packet capture timeout in milliseconds
    int captureTimeoutMs = DEFAULT_CAPTURE_TIMEOUT_MS;
    
    /// Number of pre-allocated packet buffers
    size_t bufferCount = DEFAULT_BUFFER_COUNT;
    
    /// Enable promiscuous mode
    bool promiscuousMode = true;
    
    /// Optional callbacks
    PacketCallback onPacketReceived = nullptr;
    StatusCallback onStatusChange = nullptr;
    StatsCallback onStats = nullptr;
};

} // namespace armora

