#pragma once

/**
 * @file CryptoHandler.hpp
 * @brief High-level crypto handler for the bridge
 * 
 * This class wraps an ICryptoProvider and provides convenient methods
 * for the BridgeEngine to use. It handles provider lifecycle and
 * provides pre-allocated buffers for low-latency operation.
 */

#include "ICryptoProvider.hpp"
#include <memory>

namespace armora {

/**
 * @brief High-level crypto handler for bridge operations
 * 
 * Manages the crypto provider lifecycle and provides optimized
 * encrypt/decrypt methods with pre-allocated buffers.
 */
class CryptoHandler {
public:
    /**
     * @brief Construct with default crypto provider (Kyber1024 + AES-256-GCM)
     */
    CryptoHandler();

    /**
     * @brief Construct with custom crypto provider
     * @param provider Custom provider implementation
     */
    explicit CryptoHandler(std::unique_ptr<ICryptoProvider> provider);

    ~CryptoHandler();

    // Non-copyable
    CryptoHandler(const CryptoHandler&) = delete;
    CryptoHandler& operator=(const CryptoHandler&) = delete;

    // Movable
    CryptoHandler(CryptoHandler&&) noexcept;
    CryptoHandler& operator=(CryptoHandler&&) noexcept;

    // ========================================================================
    // Lifecycle
    // ========================================================================

    /**
     * @brief Initialize the crypto handler
     * @return Success or error code
     */
    ErrorCode initialize();

    /**
     * @brief Check if handler is ready for encryption/decryption
     */
    bool isReady() const;

    // ========================================================================
    // Key Setup
    // ========================================================================

    /**
     * @brief Set pre-shared key for symmetric encryption
     * @param key 32-byte AES-256 key
     * @return Success or error code
     */
    ErrorCode setPreSharedKey(ByteSpan key);

    /**
     * @brief Generate key pair for KEM exchange
     * @return Success or error code
     */
    ErrorCode generateKeyPair();

    /**
     * @brief Get our public key for sharing with peer
     * @param[out] publicKey Buffer to receive public key
     * @return Success or error code
     */
    ErrorCode getPublicKey(std::vector<uint8_t>& publicKey) const;

    /**
     * @brief Perform key encapsulation (initiator side)
     * @param peerPublicKey Peer's public key
     * @param[out] ciphertext KEM ciphertext to send to peer
     * @return Success or error code
     */
    ErrorCode encapsulateKey(ByteSpan peerPublicKey,
                              std::vector<uint8_t>& ciphertext);

    /**
     * @brief Perform key decapsulation (responder side)
     * @param ciphertext KEM ciphertext from initiator
     * @return Success or error code
     */
    ErrorCode decapsulateKey(ByteSpan ciphertext);

    // ========================================================================
    // Packet Operations
    // ========================================================================

    /**
     * @brief Encrypt a packet payload
     * 
     * @param plaintext Packet data to encrypt
     * @param plaintextLen Length of plaintext
     * @param[out] ciphertext Output buffer (must be at least plaintextLen + getOverhead())
     * @param[out] ciphertextLen Actual ciphertext length
     * @return Success or error code
     */
    ErrorCode encryptPacket(const uint8_t* plaintext, size_t plaintextLen,
                            uint8_t* ciphertext, size_t& ciphertextLen);

    /**
     * @brief Decrypt a packet payload
     * 
     * @param ciphertext Encrypted packet data
     * @param ciphertextLen Length of ciphertext
     * @param[out] plaintext Output buffer (must be at least ciphertextLen - getOverhead())
     * @param[out] plaintextLen Actual plaintext length
     * @return Success or error code
     */
    ErrorCode decryptPacket(const uint8_t* ciphertext, size_t ciphertextLen,
                            uint8_t* plaintext, size_t& plaintextLen);

    // ========================================================================
    // Information
    // ========================================================================

    /**
     * @brief Get encryption overhead in bytes
     */
    size_t getOverhead() const;

    /**
     * @brief Get provider information string
     */
    std::string getProviderInfo() const;

private:
    std::unique_ptr<ICryptoProvider> m_provider;
};

} // namespace armora

