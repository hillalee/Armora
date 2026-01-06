#pragma once

/**
 * @file HybridPQCProvider.hpp
 * @brief Hybrid PQC crypto provider using Kyber1024 + AES-256-GCM
 * 
 * This implementation uses:
 * - Kyber1024 (ML-KEM) for quantum-resistant key encapsulation
 * - AES-256-GCM for high-speed authenticated encryption
 * - HKDF-SHA256 for key derivation from shared secret
 */

#include "ICryptoProvider.hpp"
#include <atomic>
#include <mutex>

// Forward declarations for liboqs and OpenSSL types
struct OQS_KEM;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

namespace armora {

/**
 * @brief Hybrid crypto provider combining Kyber1024 KEM with AES-256-GCM
 * 
 * Thread-safety:
 * - Key generation/exchange operations are NOT thread-safe
 * - Encrypt/decrypt operations ARE thread-safe (use separate nonce counters)
 */
class HybridPQCProvider : public ICryptoProvider {
public:
    HybridPQCProvider();
    ~HybridPQCProvider() override;

    // Non-copyable, non-movable (owns crypto state)
    HybridPQCProvider(const HybridPQCProvider&) = delete;
    HybridPQCProvider& operator=(const HybridPQCProvider&) = delete;
    HybridPQCProvider(HybridPQCProvider&&) = delete;
    HybridPQCProvider& operator=(HybridPQCProvider&&) = delete;

    // ========================================================================
    // ICryptoProvider Implementation
    // ========================================================================

    ErrorCode initialize() override;
    void shutdown() override;
    bool isReady() const override;

    ErrorCode generateKeyPair() override;
    ErrorCode getPublicKey(std::vector<uint8_t>& publicKey) const override;
    ErrorCode encapsulate(ByteSpan peerPublicKey,
                          std::vector<uint8_t>& ciphertext) override;
    ErrorCode decapsulate(ByteSpan ciphertext) override;
    ErrorCode setPreSharedKey(ByteSpan key) override;
    bool hasSessionKey() const override;

    ErrorCode encrypt(ByteSpan plaintext,
                      std::vector<uint8_t>& ciphertext) override;
    ErrorCode encrypt(ByteSpan plaintext,
                      MutableByteSpan ciphertext,
                      size_t& ciphertextLen) override;

    ErrorCode decrypt(ByteSpan ciphertext,
                      std::vector<uint8_t>& plaintext) override;
    ErrorCode decrypt(ByteSpan ciphertext,
                      MutableByteSpan plaintext,
                      size_t& plaintextLen) override;

    std::string getName() const override;
    std::string getKEMAlgorithm() const override;
    std::string getCipherAlgorithm() const override;
    size_t getOverhead() const override;

private:
    // ========================================================================
    // Internal Methods
    // ========================================================================

    /**
     * @brief Derive AES key from shared secret using HKDF
     */
    ErrorCode deriveSessionKey(const uint8_t* sharedSecret, size_t secretLen);

    /**
     * @brief Generate a unique nonce for encryption
     */
    void generateNonce(uint8_t* nonce);

    /**
     * @brief Perform AES-256-GCM encryption
     */
    ErrorCode aesGcmEncrypt(const uint8_t* plaintext, size_t plaintextLen,
                            const uint8_t* nonce,
                            uint8_t* ciphertext, size_t& ciphertextLen,
                            uint8_t* tag);

    /**
     * @brief Perform AES-256-GCM decryption
     */
    ErrorCode aesGcmDecrypt(const uint8_t* ciphertext, size_t ciphertextLen,
                            const uint8_t* nonce,
                            const uint8_t* tag,
                            uint8_t* plaintext, size_t& plaintextLen);

    // ========================================================================
    // State
    // ========================================================================

    /// liboqs KEM instance
    OQS_KEM* m_kem = nullptr;

    /// Our Kyber1024 key pair
    std::vector<uint8_t> m_publicKey;
    std::vector<uint8_t> m_secretKey;

    /// Derived AES-256 session key
    AESKey m_sessionKey;
    std::atomic<bool> m_hasSessionKey{false};

    /// Nonce counter for encryption (atomic for thread safety)
    std::atomic<uint64_t> m_nonceCounter{0};

    /// Initialization state
    std::atomic<bool> m_initialized{false};

    /// Mutex for key operations
    mutable std::mutex m_keyMutex;
};

} // namespace armora

