/**
 * @file HybridPQCProvider.cpp
 * @brief Implementation of Kyber1024 + AES-256-GCM hybrid crypto provider
 */

#include "HybridPQCProvider.hpp"
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstring>
#include <stdexcept>

namespace armora {

// ============================================================================
// Constants
// ============================================================================

static constexpr const char* KEM_ALGORITHM = "Kyber1024";
static constexpr const char* HKDF_INFO = "armora-session-key-v1";

// ============================================================================
// Construction / Destruction
// ============================================================================

HybridPQCProvider::HybridPQCProvider() = default;

HybridPQCProvider::~HybridPQCProvider() {
    shutdown();
}

// ============================================================================
// Lifecycle
// ============================================================================

ErrorCode HybridPQCProvider::initialize() {
    if (m_initialized) {
        return ErrorCode::Success;
    }

    // Initialize liboqs
    OQS_init();

    // Create Kyber1024 KEM instance
    m_kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (!m_kem) {
        return ErrorCode::CryptoInitError;
    }

    // Pre-allocate key buffers
    m_publicKey.resize(m_kem->length_public_key);
    m_secretKey.resize(m_kem->length_secret_key);

    // Initialize session key to zeros
    std::memset(m_sessionKey.data(), 0, m_sessionKey.size());

    // Seed the nonce counter with random value for unpredictability
    uint64_t randomSeed = 0;
    if (RAND_bytes(reinterpret_cast<uint8_t*>(&randomSeed), sizeof(randomSeed)) != 1) {
        // Fall back to time-based seed if random fails
        randomSeed = static_cast<uint64_t>(std::time(nullptr));
    }
    m_nonceCounter.store(randomSeed);

    m_initialized = true;
    return ErrorCode::Success;
}

void HybridPQCProvider::shutdown() {
    if (!m_initialized) {
        return;
    }

    // Securely clear sensitive data
    if (!m_secretKey.empty()) {
        OPENSSL_cleanse(m_secretKey.data(), m_secretKey.size());
        m_secretKey.clear();
    }
    OPENSSL_cleanse(m_sessionKey.data(), m_sessionKey.size());
    
    m_publicKey.clear();
    m_hasSessionKey = false;

    // Free KEM instance
    if (m_kem) {
        OQS_KEM_free(m_kem);
        m_kem = nullptr;
    }

    m_initialized = false;
}

bool HybridPQCProvider::isReady() const {
    return m_initialized && m_hasSessionKey;
}

// ============================================================================
// Key Management
// ============================================================================

ErrorCode HybridPQCProvider::generateKeyPair() {
    std::lock_guard<std::mutex> lock(m_keyMutex);

    if (!m_initialized || !m_kem) {
        return ErrorCode::CryptoInitError;
    }

    // Generate Kyber1024 key pair
    if (OQS_KEM_keypair(m_kem, m_publicKey.data(), m_secretKey.data()) != OQS_SUCCESS) {
        return ErrorCode::CryptoKeyExchangeError;
    }

    return ErrorCode::Success;
}

ErrorCode HybridPQCProvider::getPublicKey(std::vector<uint8_t>& publicKey) const {
    std::lock_guard<std::mutex> lock(m_keyMutex);

    if (!m_initialized || m_publicKey.empty()) {
        return ErrorCode::CryptoKeyExchangeError;
    }

    publicKey = m_publicKey;
    return ErrorCode::Success;
}

ErrorCode HybridPQCProvider::encapsulate(ByteSpan peerPublicKey,
                                          std::vector<uint8_t>& ciphertext) {
    std::lock_guard<std::mutex> lock(m_keyMutex);

    if (!m_initialized || !m_kem) {
        return ErrorCode::CryptoInitError;
    }

    if (peerPublicKey.size() != m_kem->length_public_key) {
        return ErrorCode::InvalidArgument;
    }

    // Allocate ciphertext buffer
    ciphertext.resize(m_kem->length_ciphertext);

    // Shared secret buffer
    std::vector<uint8_t> sharedSecret(m_kem->length_shared_secret);

    // Encapsulate: generate ciphertext and shared secret
    if (OQS_KEM_encaps(m_kem, ciphertext.data(), sharedSecret.data(),
                       peerPublicKey.data()) != OQS_SUCCESS) {
        return ErrorCode::CryptoKeyExchangeError;
    }

    // Derive session key from shared secret
    ErrorCode err = deriveSessionKey(sharedSecret.data(), sharedSecret.size());
    
    // Securely clear shared secret
    OPENSSL_cleanse(sharedSecret.data(), sharedSecret.size());

    return err;
}

ErrorCode HybridPQCProvider::decapsulate(ByteSpan ciphertext) {
    std::lock_guard<std::mutex> lock(m_keyMutex);

    if (!m_initialized || !m_kem) {
        return ErrorCode::CryptoInitError;
    }

    if (ciphertext.size() != m_kem->length_ciphertext) {
        return ErrorCode::InvalidArgument;
    }

    if (m_secretKey.empty()) {
        return ErrorCode::CryptoKeyExchangeError;
    }

    // Shared secret buffer
    std::vector<uint8_t> sharedSecret(m_kem->length_shared_secret);

    // Decapsulate: recover shared secret from ciphertext
    if (OQS_KEM_decaps(m_kem, sharedSecret.data(), ciphertext.data(),
                       m_secretKey.data()) != OQS_SUCCESS) {
        return ErrorCode::CryptoKeyExchangeError;
    }

    // Derive session key from shared secret
    ErrorCode err = deriveSessionKey(sharedSecret.data(), sharedSecret.size());

    // Securely clear shared secret
    OPENSSL_cleanse(sharedSecret.data(), sharedSecret.size());

    return err;
}

ErrorCode HybridPQCProvider::setPreSharedKey(ByteSpan key) {
    std::lock_guard<std::mutex> lock(m_keyMutex);

    if (!m_initialized) {
        return ErrorCode::CryptoInitError;
    }

    if (key.size() != AES_KEY_SIZE) {
        return ErrorCode::InvalidArgument;
    }

    std::memcpy(m_sessionKey.data(), key.data(), AES_KEY_SIZE);
    m_hasSessionKey = true;

    return ErrorCode::Success;
}

bool HybridPQCProvider::hasSessionKey() const {
    return m_hasSessionKey;
}

// ============================================================================
// Encryption / Decryption
// ============================================================================

ErrorCode HybridPQCProvider::encrypt(ByteSpan plaintext,
                                      std::vector<uint8_t>& ciphertext) {
    if (!isReady()) {
        return ErrorCode::CryptoInitError;
    }

    // Output: [IV (12 bytes)][ciphertext][tag (16 bytes)]
    size_t outputLen = AES_IV_SIZE + plaintext.size() + AES_TAG_SIZE;
    ciphertext.resize(outputLen);

    size_t actualLen = 0;
    MutableByteSpan outputSpan(ciphertext);
    
    ErrorCode err = encrypt(plaintext, outputSpan, actualLen);
    if (err != ErrorCode::Success) {
        ciphertext.clear();
        return err;
    }

    ciphertext.resize(actualLen);
    return ErrorCode::Success;
}

ErrorCode HybridPQCProvider::encrypt(ByteSpan plaintext,
                                      MutableByteSpan output,
                                      size_t& outputLen) {
    if (!isReady()) {
        return ErrorCode::CryptoInitError;
    }

    size_t requiredLen = AES_IV_SIZE + plaintext.size() + AES_TAG_SIZE;
    if (output.size() < requiredLen) {
        return ErrorCode::InvalidArgument;
    }

    // Generate nonce (first 12 bytes of output)
    uint8_t* nonce = output.data();
    generateNonce(nonce);

    // Encrypt (ciphertext follows nonce)
    uint8_t* ciphertextPtr = output.data() + AES_IV_SIZE;
    size_t ciphertextLen = 0;

    // Tag goes at the end
    uint8_t* tag = output.data() + AES_IV_SIZE + plaintext.size();

    ErrorCode err = aesGcmEncrypt(plaintext.data(), plaintext.size(),
                                   nonce, ciphertextPtr, ciphertextLen, tag);
    if (err != ErrorCode::Success) {
        return err;
    }

    outputLen = AES_IV_SIZE + ciphertextLen + AES_TAG_SIZE;
    return ErrorCode::Success;
}

ErrorCode HybridPQCProvider::decrypt(ByteSpan ciphertext,
                                      std::vector<uint8_t>& plaintext) {
    if (!isReady()) {
        return ErrorCode::CryptoInitError;
    }

    if (ciphertext.size() < AES_IV_SIZE + AES_TAG_SIZE) {
        return ErrorCode::InvalidArgument;
    }

    size_t plaintextMaxLen = ciphertext.size() - AES_IV_SIZE - AES_TAG_SIZE;
    plaintext.resize(plaintextMaxLen);

    size_t actualLen = 0;
    MutableByteSpan outputSpan(plaintext);

    ErrorCode err = decrypt(ciphertext, outputSpan, actualLen);
    if (err != ErrorCode::Success) {
        plaintext.clear();
        return err;
    }

    plaintext.resize(actualLen);
    return ErrorCode::Success;
}

ErrorCode HybridPQCProvider::decrypt(ByteSpan input,
                                      MutableByteSpan plaintext,
                                      size_t& plaintextLen) {
    if (!isReady()) {
        return ErrorCode::CryptoInitError;
    }

    if (input.size() < AES_IV_SIZE + AES_TAG_SIZE) {
        return ErrorCode::InvalidArgument;
    }

    size_t ciphertextLen = input.size() - AES_IV_SIZE - AES_TAG_SIZE;
    if (plaintext.size() < ciphertextLen) {
        return ErrorCode::InvalidArgument;
    }

    // Extract components: [nonce (12)][ciphertext][tag (16)]
    const uint8_t* nonce = input.data();
    const uint8_t* ciphertextPtr = input.data() + AES_IV_SIZE;
    const uint8_t* tag = input.data() + AES_IV_SIZE + ciphertextLen;

    return aesGcmDecrypt(ciphertextPtr, ciphertextLen, nonce, tag,
                         plaintext.data(), plaintextLen);
}

// ============================================================================
// Information
// ============================================================================

std::string HybridPQCProvider::getName() const {
    return "HybridPQCProvider";
}

std::string HybridPQCProvider::getKEMAlgorithm() const {
    return KEM_ALGORITHM;
}

std::string HybridPQCProvider::getCipherAlgorithm() const {
    return "AES-256-GCM";
}

size_t HybridPQCProvider::getOverhead() const {
    return CRYPTO_OVERHEAD;
}

// ============================================================================
// Internal Methods
// ============================================================================

ErrorCode HybridPQCProvider::deriveSessionKey(const uint8_t* sharedSecret,
                                               size_t secretLen) {
    // Use HKDF to derive AES key from shared secret
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) {
        return ErrorCode::CryptoKeyExchangeError;
    }

    bool success = false;
    
    do {
        if (EVP_PKEY_derive_init(ctx) <= 0) break;
        if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) break;
        if (EVP_PKEY_CTX_set1_hkdf_key(ctx, sharedSecret, secretLen) <= 0) break;
        if (EVP_PKEY_CTX_set1_hkdf_info(ctx, 
            reinterpret_cast<const uint8_t*>(HKDF_INFO), 
            std::strlen(HKDF_INFO)) <= 0) break;

        size_t keyLen = AES_KEY_SIZE;
        if (EVP_PKEY_derive(ctx, m_sessionKey.data(), &keyLen) <= 0) break;
        if (keyLen != AES_KEY_SIZE) break;

        success = true;
    } while (false);

    EVP_PKEY_CTX_free(ctx);

    if (success) {
        m_hasSessionKey = true;
        return ErrorCode::Success;
    }
    return ErrorCode::CryptoKeyExchangeError;
}

void HybridPQCProvider::generateNonce(uint8_t* nonce) {
    // Use atomic counter for unique nonces
    // Format: [random 4 bytes][counter 8 bytes]
    uint64_t counter = m_nonceCounter.fetch_add(1);

    // Random prefix (from initialization)
    uint32_t prefix = static_cast<uint32_t>(m_nonceCounter.load() >> 32);
    std::memcpy(nonce, &prefix, 4);
    
    // Counter suffix
    std::memcpy(nonce + 4, &counter, 8);
}

ErrorCode HybridPQCProvider::aesGcmEncrypt(const uint8_t* plaintext,
                                            size_t plaintextLen,
                                            const uint8_t* nonce,
                                            uint8_t* ciphertext,
                                            size_t& ciphertextLen,
                                            uint8_t* tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return ErrorCode::CryptoEncryptError;
    }

    ErrorCode result = ErrorCode::CryptoEncryptError;
    int len = 0;

    do {
        // Initialize encryption with AES-256-GCM
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            break;
        }

        // Set IV length
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr) != 1) {
            break;
        }

        // Set key and IV
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, m_sessionKey.data(), nonce) != 1) {
            break;
        }

        // Encrypt plaintext
        if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, 
                              static_cast<int>(plaintextLen)) != 1) {
            break;
        }
        ciphertextLen = len;

        // Finalize encryption
        if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
            break;
        }
        ciphertextLen += len;

        // Get authentication tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, tag) != 1) {
            break;
        }

        result = ErrorCode::Success;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return result;
}

ErrorCode HybridPQCProvider::aesGcmDecrypt(const uint8_t* ciphertext,
                                            size_t ciphertextLen,
                                            const uint8_t* nonce,
                                            const uint8_t* tag,
                                            uint8_t* plaintext,
                                            size_t& plaintextLen) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return ErrorCode::CryptoDecryptError;
    }

    ErrorCode result = ErrorCode::CryptoDecryptError;
    int len = 0;

    do {
        // Initialize decryption with AES-256-GCM
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            break;
        }

        // Set IV length
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, nullptr) != 1) {
            break;
        }

        // Set key and IV
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, m_sessionKey.data(), nonce) != 1) {
            break;
        }

        // Decrypt ciphertext
        if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext,
                              static_cast<int>(ciphertextLen)) != 1) {
            break;
        }
        plaintextLen = len;

        // Set expected tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE,
                                const_cast<uint8_t*>(tag)) != 1) {
            break;
        }

        // Finalize and verify authentication tag
        if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
            result = ErrorCode::CryptoAuthError;
            break;
        }
        plaintextLen += len;

        result = ErrorCode::Success;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return result;
}

// ============================================================================
// Factory Function
// ============================================================================

std::unique_ptr<ICryptoProvider> createDefaultCryptoProvider() {
    return std::make_unique<HybridPQCProvider>();
}

} // namespace armora

