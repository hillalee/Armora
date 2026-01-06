#pragma once

/**
 * @file ICryptoProvider.hpp
 * @brief Abstract interface for cryptographic providers
 * 
 * This interface allows swapping cryptographic algorithms without changing
 * the bridge logic. Implementations can use different PQC algorithms or
 * symmetric ciphers as needed.
 */

#include "armora/Types.hpp"
#include <vector>
#include <memory>
#include <string>

namespace armora {

/**
 * @brief Abstract interface for cryptographic operations
 * 
 * Implementations of this interface handle:
 * - Key generation and exchange (using PQC KEMs)
 * - Symmetric encryption/decryption (using AES-GCM or similar)
 * - Nonce/IV management for replay protection
 */
class ICryptoProvider {
public:
    virtual ~ICryptoProvider() = default;

    // ========================================================================
    // Lifecycle
    // ========================================================================

    /**
     * @brief Initialize the crypto provider
     * @return Success or error code
     */
    virtual ErrorCode initialize() = 0;

    /**
     * @brief Shutdown and cleanup resources
     */
    virtual void shutdown() = 0;

    /**
     * @brief Check if provider is initialized and ready
     */
    virtual bool isReady() const = 0;

    // ========================================================================
    // Key Management
    // ========================================================================

    /**
     * @brief Generate a new key pair for key exchange
     * @return Success or error code
     */
    virtual ErrorCode generateKeyPair() = 0;

    /**
     * @brief Get the public key for sharing with peer
     * @param[out] publicKey Buffer to receive public key
     * @return Success or error code
     */
    virtual ErrorCode getPublicKey(std::vector<uint8_t>& publicKey) const = 0;

    /**
     * @brief Encapsulate a shared secret using peer's public key (initiator side)
     * @param peerPublicKey Peer's public key
     * @param[out] ciphertext Ciphertext to send to peer
     * @return Success or error code
     */
    virtual ErrorCode encapsulate(ByteSpan peerPublicKey,
                                   std::vector<uint8_t>& ciphertext) = 0;

    /**
     * @brief Decapsulate shared secret from ciphertext (responder side)
     * @param ciphertext Ciphertext from initiator
     * @return Success or error code
     */
    virtual ErrorCode decapsulate(ByteSpan ciphertext) = 0;

    /**
     * @brief Set a pre-shared key directly (bypassing KEM)
     * @param key Pre-shared symmetric key
     * @return Success or error code
     */
    virtual ErrorCode setPreSharedKey(ByteSpan key) = 0;

    /**
     * @brief Check if a session key has been established
     */
    virtual bool hasSessionKey() const = 0;

    // ========================================================================
    // Encryption/Decryption
    // ========================================================================

    /**
     * @brief Encrypt plaintext data
     * 
     * Output format: [IV (12 bytes)][ciphertext][tag (16 bytes)]
     * 
     * @param plaintext Data to encrypt
     * @param[out] ciphertext Encrypted output (pre-allocated for performance)
     * @return Success or error code
     */
    virtual ErrorCode encrypt(ByteSpan plaintext,
                              std::vector<uint8_t>& ciphertext) = 0;

    /**
     * @brief Encrypt plaintext data (zero-copy variant)
     * 
     * @param plaintext Data to encrypt
     * @param ciphertext Pre-allocated output buffer
     * @param[out] ciphertextLen Actual ciphertext length
     * @return Success or error code
     */
    virtual ErrorCode encrypt(ByteSpan plaintext,
                              MutableByteSpan ciphertext,
                              size_t& ciphertextLen) = 0;

    /**
     * @brief Decrypt ciphertext data
     * 
     * Input format: [IV (12 bytes)][ciphertext][tag (16 bytes)]
     * 
     * @param ciphertext Data to decrypt (includes IV and tag)
     * @param[out] plaintext Decrypted output
     * @return Success or error code (CryptoAuthError if authentication fails)
     */
    virtual ErrorCode decrypt(ByteSpan ciphertext,
                              std::vector<uint8_t>& plaintext) = 0;

    /**
     * @brief Decrypt ciphertext data (zero-copy variant)
     * 
     * @param ciphertext Data to decrypt (includes IV and tag)
     * @param plaintext Pre-allocated output buffer
     * @param[out] plaintextLen Actual plaintext length
     * @return Success or error code
     */
    virtual ErrorCode decrypt(ByteSpan ciphertext,
                              MutableByteSpan plaintext,
                              size_t& plaintextLen) = 0;

    // ========================================================================
    // Information
    // ========================================================================

    /**
     * @brief Get the name of this crypto provider
     */
    virtual std::string getName() const = 0;

    /**
     * @brief Get the KEM algorithm name
     */
    virtual std::string getKEMAlgorithm() const = 0;

    /**
     * @brief Get the symmetric cipher name
     */
    virtual std::string getCipherAlgorithm() const = 0;

    /**
     * @brief Get encryption overhead (bytes added to plaintext)
     */
    virtual size_t getOverhead() const = 0;
};

/**
 * @brief Factory function to create the default crypto provider
 * @return Unique pointer to a HybridPQCProvider (Kyber1024 + AES-256-GCM)
 */
std::unique_ptr<ICryptoProvider> createDefaultCryptoProvider();

} // namespace armora

