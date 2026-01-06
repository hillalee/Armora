/**
 * @file test_crypto.cpp
 * @brief Unit tests for cryptographic operations
 * 
 * Tests the HybridPQCProvider (Kyber1024 + AES-256-GCM) implementation.
 */

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_vector.hpp>

#include "crypto/CryptoHandler.hpp"
#include "crypto/HybridPQCProvider.hpp"
#include "armora/Types.hpp"

#include <vector>
#include <array>
#include <random>
#include <cstring>

using namespace armora;

// ============================================================================
// Test Fixtures
// ============================================================================

/**
 * @brief Generate random bytes for testing
 */
static std::vector<uint8_t> randomBytes(size_t count) {
    std::vector<uint8_t> data(count);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (auto& byte : data) {
        byte = static_cast<uint8_t>(dis(gen));
    }
    return data;
}

/**
 * @brief Generate a random 32-byte key
 */
static AESKey randomKey() {
    AESKey key;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (auto& byte : key) {
        byte = static_cast<uint8_t>(dis(gen));
    }
    return key;
}

// ============================================================================
// HybridPQCProvider Tests
// ============================================================================

TEST_CASE("HybridPQCProvider initialization", "[crypto][init]") {
    HybridPQCProvider provider;

    SECTION("Provider starts uninitialized") {
        REQUIRE_FALSE(provider.isReady());
        REQUIRE_FALSE(provider.hasSessionKey());
    }

    SECTION("Initialize succeeds") {
        ErrorCode err = provider.initialize();
        REQUIRE(err == ErrorCode::Success);
        REQUIRE_FALSE(provider.isReady());  // Still need session key
    }

    SECTION("Double initialization is safe") {
        REQUIRE(provider.initialize() == ErrorCode::Success);
        REQUIRE(provider.initialize() == ErrorCode::Success);
    }
}

TEST_CASE("HybridPQCProvider pre-shared key", "[crypto][psk]") {
    HybridPQCProvider provider;
    REQUIRE(provider.initialize() == ErrorCode::Success);

    SECTION("Set valid 32-byte key") {
        AESKey key = randomKey();
        ErrorCode err = provider.setPreSharedKey(ByteSpan(key.data(), key.size()));
        REQUIRE(err == ErrorCode::Success);
        REQUIRE(provider.hasSessionKey());
        REQUIRE(provider.isReady());
    }

    SECTION("Reject invalid key length") {
        std::vector<uint8_t> shortKey(16);  // Too short
        ErrorCode err = provider.setPreSharedKey(ByteSpan(shortKey.data(), shortKey.size()));
        REQUIRE(err == ErrorCode::InvalidArgument);
        REQUIRE_FALSE(provider.hasSessionKey());
    }

    SECTION("Reject empty key") {
        ErrorCode err = provider.setPreSharedKey(ByteSpan(nullptr, 0));
        REQUIRE(err == ErrorCode::InvalidArgument);
    }
}

TEST_CASE("HybridPQCProvider encrypt/decrypt round-trip", "[crypto][roundtrip]") {
    HybridPQCProvider provider;
    REQUIRE(provider.initialize() == ErrorCode::Success);
    
    AESKey key = randomKey();
    REQUIRE(provider.setPreSharedKey(ByteSpan(key.data(), key.size())) == ErrorCode::Success);

    SECTION("Small plaintext") {
        std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> decrypted;

        ErrorCode err = provider.encrypt(ByteSpan(plaintext), ciphertext);
        REQUIRE(err == ErrorCode::Success);
        REQUIRE(ciphertext.size() == plaintext.size() + CRYPTO_OVERHEAD);

        err = provider.decrypt(ByteSpan(ciphertext), decrypted);
        REQUIRE(err == ErrorCode::Success);
        REQUIRE(decrypted == plaintext);
    }

    SECTION("Empty plaintext") {
        std::vector<uint8_t> plaintext;
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> decrypted;

        ErrorCode err = provider.encrypt(ByteSpan(plaintext), ciphertext);
        REQUIRE(err == ErrorCode::Success);
        REQUIRE(ciphertext.size() == CRYPTO_OVERHEAD);

        err = provider.decrypt(ByteSpan(ciphertext), decrypted);
        REQUIRE(err == ErrorCode::Success);
        REQUIRE(decrypted.empty());
    }

    SECTION("MTU-sized plaintext") {
        std::vector<uint8_t> plaintext = randomBytes(1500);  // Typical MTU
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> decrypted;

        ErrorCode err = provider.encrypt(ByteSpan(plaintext), ciphertext);
        REQUIRE(err == ErrorCode::Success);

        err = provider.decrypt(ByteSpan(ciphertext), decrypted);
        REQUIRE(err == ErrorCode::Success);
        REQUIRE(decrypted == plaintext);
    }

    SECTION("Large plaintext") {
        std::vector<uint8_t> plaintext = randomBytes(65536);
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> decrypted;

        ErrorCode err = provider.encrypt(ByteSpan(plaintext), ciphertext);
        REQUIRE(err == ErrorCode::Success);

        err = provider.decrypt(ByteSpan(ciphertext), decrypted);
        REQUIRE(err == ErrorCode::Success);
        REQUIRE(decrypted == plaintext);
    }
}

TEST_CASE("HybridPQCProvider ciphertext tampering detection", "[crypto][auth]") {
    HybridPQCProvider provider;
    REQUIRE(provider.initialize() == ErrorCode::Success);
    
    AESKey key = randomKey();
    REQUIRE(provider.setPreSharedKey(ByteSpan(key.data(), key.size())) == ErrorCode::Success);

    std::vector<uint8_t> plaintext = {'S', 'e', 'c', 'r', 'e', 't'};
    std::vector<uint8_t> ciphertext;
    
    REQUIRE(provider.encrypt(ByteSpan(plaintext), ciphertext) == ErrorCode::Success);

    SECTION("Tampered ciphertext fails authentication") {
        // Flip a bit in the ciphertext portion
        ciphertext[AES_IV_SIZE + 2] ^= 0x01;
        
        std::vector<uint8_t> decrypted;
        ErrorCode err = provider.decrypt(ByteSpan(ciphertext), decrypted);
        REQUIRE(err == ErrorCode::CryptoAuthError);
    }

    SECTION("Tampered IV fails authentication") {
        // Flip a bit in the IV
        ciphertext[0] ^= 0x01;
        
        std::vector<uint8_t> decrypted;
        ErrorCode err = provider.decrypt(ByteSpan(ciphertext), decrypted);
        REQUIRE(err == ErrorCode::CryptoAuthError);
    }

    SECTION("Tampered tag fails authentication") {
        // Flip a bit in the tag (last 16 bytes)
        ciphertext[ciphertext.size() - 1] ^= 0x01;
        
        std::vector<uint8_t> decrypted;
        ErrorCode err = provider.decrypt(ByteSpan(ciphertext), decrypted);
        REQUIRE(err == ErrorCode::CryptoAuthError);
    }

    SECTION("Truncated ciphertext fails") {
        ciphertext.resize(ciphertext.size() - 5);
        
        std::vector<uint8_t> decrypted;
        ErrorCode err = provider.decrypt(ByteSpan(ciphertext), decrypted);
        REQUIRE(err != ErrorCode::Success);
    }
}

TEST_CASE("HybridPQCProvider unique nonces", "[crypto][nonce]") {
    HybridPQCProvider provider;
    REQUIRE(provider.initialize() == ErrorCode::Success);
    
    AESKey key = randomKey();
    REQUIRE(provider.setPreSharedKey(ByteSpan(key.data(), key.size())) == ErrorCode::Success);

    std::vector<uint8_t> plaintext = {'T', 'e', 's', 't'};
    
    // Encrypt same plaintext multiple times
    std::vector<std::vector<uint8_t>> ciphertexts;
    for (int i = 0; i < 100; ++i) {
        std::vector<uint8_t> ciphertext;
        REQUIRE(provider.encrypt(ByteSpan(plaintext), ciphertext) == ErrorCode::Success);
        ciphertexts.push_back(std::move(ciphertext));
    }

    // Verify all nonces (first 12 bytes) are unique
    std::set<std::vector<uint8_t>> nonces;
    for (const auto& ct : ciphertexts) {
        std::vector<uint8_t> nonce(ct.begin(), ct.begin() + AES_IV_SIZE);
        auto [_, inserted] = nonces.insert(nonce);
        REQUIRE(inserted);  // Should be unique
    }
}

TEST_CASE("HybridPQCProvider Kyber key exchange", "[crypto][kem]") {
    // Simulate two parties: Alice and Bob
    HybridPQCProvider alice;
    HybridPQCProvider bob;
    
    REQUIRE(alice.initialize() == ErrorCode::Success);
    REQUIRE(bob.initialize() == ErrorCode::Success);

    SECTION("Full KEM exchange") {
        // Bob generates key pair
        REQUIRE(bob.generateKeyPair() == ErrorCode::Success);
        
        // Bob sends public key to Alice
        std::vector<uint8_t> bobPublicKey;
        REQUIRE(bob.getPublicKey(bobPublicKey) == ErrorCode::Success);
        REQUIRE(bobPublicKey.size() == KYBER1024_PUBLIC_KEY_SIZE);

        // Alice encapsulates shared secret using Bob's public key
        std::vector<uint8_t> ciphertext;
        REQUIRE(alice.encapsulate(ByteSpan(bobPublicKey), ciphertext) == ErrorCode::Success);
        REQUIRE(ciphertext.size() == KYBER1024_CIPHERTEXT_SIZE);
        REQUIRE(alice.hasSessionKey());

        // Bob decapsulates to get same shared secret
        REQUIRE(bob.decapsulate(ByteSpan(ciphertext)) == ErrorCode::Success);
        REQUIRE(bob.hasSessionKey());

        // Both should now be able to encrypt/decrypt
        std::vector<uint8_t> plaintext = {'K', 'E', 'M', ' ', 'T', 'e', 's', 't'};
        std::vector<uint8_t> encrypted;
        std::vector<uint8_t> decrypted;

        REQUIRE(alice.encrypt(ByteSpan(plaintext), encrypted) == ErrorCode::Success);
        REQUIRE(bob.decrypt(ByteSpan(encrypted), decrypted) == ErrorCode::Success);
        REQUIRE(decrypted == plaintext);

        // And vice versa
        REQUIRE(bob.encrypt(ByteSpan(plaintext), encrypted) == ErrorCode::Success);
        REQUIRE(alice.decrypt(ByteSpan(encrypted), decrypted) == ErrorCode::Success);
        REQUIRE(decrypted == plaintext);
    }
}

// ============================================================================
// CryptoHandler Tests
// ============================================================================

TEST_CASE("CryptoHandler high-level API", "[crypto][handler]") {
    CryptoHandler handler;
    
    SECTION("Initialize and set key") {
        REQUIRE(handler.initialize() == ErrorCode::Success);
        
        AESKey key = randomKey();
        REQUIRE(handler.setPreSharedKey(ByteSpan(key.data(), key.size())) == ErrorCode::Success);
        REQUIRE(handler.isReady());
    }

    SECTION("Packet encryption/decryption") {
        REQUIRE(handler.initialize() == ErrorCode::Success);
        
        AESKey key = randomKey();
        REQUIRE(handler.setPreSharedKey(ByteSpan(key.data(), key.size())) == ErrorCode::Success);

        // Simulate a packet
        std::vector<uint8_t> packet = randomBytes(1400);
        std::vector<uint8_t> encrypted(packet.size() + handler.getOverhead());
        std::vector<uint8_t> decrypted(packet.size());
        
        size_t encLen = 0, decLen = 0;

        REQUIRE(handler.encryptPacket(packet.data(), packet.size(),
                                       encrypted.data(), encLen) == ErrorCode::Success);
        REQUIRE(encLen == packet.size() + handler.getOverhead());

        REQUIRE(handler.decryptPacket(encrypted.data(), encLen,
                                       decrypted.data(), decLen) == ErrorCode::Success);
        REQUIRE(decLen == packet.size());
        
        decrypted.resize(decLen);
        REQUIRE(decrypted == packet);
    }

    SECTION("Provider info") {
        REQUIRE(handler.initialize() == ErrorCode::Success);
        std::string info = handler.getProviderInfo();
        REQUIRE(info.find("Kyber") != std::string::npos);
        REQUIRE(info.find("AES") != std::string::npos);
    }
}

// ============================================================================
// Performance Tests
// ============================================================================

TEST_CASE("Crypto performance baseline", "[crypto][perf]") {
    HybridPQCProvider provider;
    REQUIRE(provider.initialize() == ErrorCode::Success);
    
    AESKey key = randomKey();
    REQUIRE(provider.setPreSharedKey(ByteSpan(key.data(), key.size())) == ErrorCode::Success);

    // 1500 byte packets (typical MTU)
    std::vector<uint8_t> packet = randomBytes(1500);
    std::vector<uint8_t> encrypted;
    std::vector<uint8_t> decrypted;

    const int iterations = 10000;
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i) {
        encrypted.clear();
        provider.encrypt(ByteSpan(packet), encrypted);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    double avgUs = static_cast<double>(duration.count()) / iterations;
    double throughputMbps = (packet.size() * 8.0 * iterations) / duration.count();

    INFO("Average encryption time: " << avgUs << " us");
    INFO("Throughput: " << throughputMbps << " Mbps");

    // Sanity check: should be able to do at least 100 Mbps
    REQUIRE(throughputMbps > 100.0);
}

