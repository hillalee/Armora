/**
 * @file CryptoHandler.cpp
 * @brief Implementation of high-level crypto handler
 */

#include "CryptoHandler.hpp"
#include "HybridPQCProvider.hpp"
#include <sstream>

namespace armora {

// ============================================================================
// Construction / Destruction
// ============================================================================

CryptoHandler::CryptoHandler()
    : m_provider(createDefaultCryptoProvider()) {
}

CryptoHandler::CryptoHandler(std::unique_ptr<ICryptoProvider> provider)
    : m_provider(std::move(provider)) {
}

CryptoHandler::~CryptoHandler() = default;

CryptoHandler::CryptoHandler(CryptoHandler&&) noexcept = default;
CryptoHandler& CryptoHandler::operator=(CryptoHandler&&) noexcept = default;

// ============================================================================
// Lifecycle
// ============================================================================

ErrorCode CryptoHandler::initialize() {
    if (!m_provider) {
        return ErrorCode::CryptoInitError;
    }
    return m_provider->initialize();
}

bool CryptoHandler::isReady() const {
    return m_provider && m_provider->isReady();
}

// ============================================================================
// Key Setup
// ============================================================================

ErrorCode CryptoHandler::setPreSharedKey(ByteSpan key) {
    if (!m_provider) {
        return ErrorCode::CryptoInitError;
    }
    return m_provider->setPreSharedKey(key);
}

ErrorCode CryptoHandler::generateKeyPair() {
    if (!m_provider) {
        return ErrorCode::CryptoInitError;
    }
    return m_provider->generateKeyPair();
}

ErrorCode CryptoHandler::getPublicKey(std::vector<uint8_t>& publicKey) const {
    if (!m_provider) {
        return ErrorCode::CryptoInitError;
    }
    return m_provider->getPublicKey(publicKey);
}

ErrorCode CryptoHandler::encapsulateKey(ByteSpan peerPublicKey,
                                         std::vector<uint8_t>& ciphertext) {
    if (!m_provider) {
        return ErrorCode::CryptoInitError;
    }
    return m_provider->encapsulate(peerPublicKey, ciphertext);
}

ErrorCode CryptoHandler::decapsulateKey(ByteSpan ciphertext) {
    if (!m_provider) {
        return ErrorCode::CryptoInitError;
    }
    return m_provider->decapsulate(ciphertext);
}

// ============================================================================
// Packet Operations
// ============================================================================

ErrorCode CryptoHandler::encryptPacket(const uint8_t* plaintext, size_t plaintextLen,
                                        uint8_t* ciphertext, size_t& ciphertextLen) {
    if (!m_provider) {
        return ErrorCode::CryptoInitError;
    }

    ByteSpan input(plaintext, plaintextLen);
    MutableByteSpan output(ciphertext, plaintextLen + getOverhead());

    return m_provider->encrypt(input, output, ciphertextLen);
}

ErrorCode CryptoHandler::decryptPacket(const uint8_t* ciphertext, size_t ciphertextLen,
                                        uint8_t* plaintext, size_t& plaintextLen) {
    if (!m_provider) {
        return ErrorCode::CryptoInitError;
    }

    if (ciphertextLen < getOverhead()) {
        return ErrorCode::InvalidArgument;
    }

    ByteSpan input(ciphertext, ciphertextLen);
    MutableByteSpan output(plaintext, ciphertextLen - getOverhead());

    return m_provider->decrypt(input, output, plaintextLen);
}

// ============================================================================
// Information
// ============================================================================

size_t CryptoHandler::getOverhead() const {
    if (!m_provider) {
        return CRYPTO_OVERHEAD;
    }
    return m_provider->getOverhead();
}

std::string CryptoHandler::getProviderInfo() const {
    if (!m_provider) {
        return "No provider";
    }

    std::ostringstream ss;
    ss << m_provider->getName() 
       << " (KEM: " << m_provider->getKEMAlgorithm()
       << ", Cipher: " << m_provider->getCipherAlgorithm() << ")";
    return ss.str();
}

} // namespace armora

