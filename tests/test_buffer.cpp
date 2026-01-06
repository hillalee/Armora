/**
 * @file test_buffer.cpp
 * @brief Unit tests for packet buffer pool
 * 
 * Tests the lock-free PacketBufferPool implementation.
 */

#include <catch2/catch_test_macros.hpp>

#include "bridge/PacketBuffer.hpp"
#include "armora/Types.hpp"

#include <thread>
#include <vector>
#include <atomic>
#include <set>

using namespace armora;

// ============================================================================
// PacketBuffer Tests
// ============================================================================

TEST_CASE("PacketBuffer basic operations", "[buffer][basic]") {
    PacketBuffer buffer;

    SECTION("Initial state") {
        REQUIRE(buffer.length() == 0);
        REQUIRE_FALSE(buffer.hasData());
        REQUIRE(buffer.capacity() == PacketBuffer::BUFFER_SIZE);
    }

    SECTION("Set and get data") {
        const uint8_t testData[] = {0x01, 0x02, 0x03, 0x04, 0x05};
        std::memcpy(buffer.data(), testData, sizeof(testData));
        buffer.setLength(sizeof(testData));

        REQUIRE(buffer.length() == sizeof(testData));
        REQUIRE(buffer.hasData());
        REQUIRE(std::memcmp(buffer.data(), testData, sizeof(testData)) == 0);
    }

    SECTION("Clear buffer") {
        buffer.setLength(100);
        REQUIRE(buffer.hasData());
        
        buffer.clear();
        REQUIRE(buffer.length() == 0);
        REQUIRE_FALSE(buffer.hasData());
    }

    SECTION("Length clamping") {
        // Setting length beyond capacity should clamp
        buffer.setLength(PacketBuffer::BUFFER_SIZE + 1000);
        REQUIRE(buffer.length() == PacketBuffer::BUFFER_SIZE);
    }

    SECTION("Full MTU packet") {
        std::vector<uint8_t> mtuPacket(MAX_FRAME_SIZE);
        for (size_t i = 0; i < mtuPacket.size(); ++i) {
            mtuPacket[i] = static_cast<uint8_t>(i & 0xFF);
        }

        std::memcpy(buffer.data(), mtuPacket.data(), mtuPacket.size());
        buffer.setLength(mtuPacket.size());

        REQUIRE(buffer.length() == MAX_FRAME_SIZE);
        REQUIRE(std::memcmp(buffer.data(), mtuPacket.data(), mtuPacket.size()) == 0);
    }
}

// ============================================================================
// PacketBufferPool Tests
// ============================================================================

TEST_CASE("PacketBufferPool basic operations", "[buffer][pool]") {
    
    SECTION("Default pool size") {
        PacketBufferPool pool;
        REQUIRE(pool.size() == DEFAULT_BUFFER_COUNT);
        REQUIRE(pool.availableCount() == DEFAULT_BUFFER_COUNT);
    }

    SECTION("Custom pool size") {
        PacketBufferPool pool(64);
        REQUIRE(pool.size() == 64);
        REQUIRE(pool.availableCount() == 64);
    }

    SECTION("Acquire and release single buffer") {
        PacketBufferPool pool(10);
        
        PacketBuffer* buf = pool.acquire();
        REQUIRE(buf != nullptr);
        REQUIRE(pool.availableCount() == 9);

        pool.release(buf);
        REQUIRE(pool.availableCount() == 10);
    }

    SECTION("Acquire all buffers") {
        PacketBufferPool pool(10);
        std::vector<PacketBuffer*> buffers;

        for (int i = 0; i < 10; ++i) {
            PacketBuffer* buf = pool.acquire();
            REQUIRE(buf != nullptr);
            buffers.push_back(buf);
        }

        REQUIRE(pool.availableCount() == 0);

        // Next acquire should fail
        PacketBuffer* extra = pool.acquire();
        REQUIRE(extra == nullptr);

        // Release all
        for (auto* buf : buffers) {
            pool.release(buf);
        }
        REQUIRE(pool.availableCount() == 10);
    }

    SECTION("Release null is safe") {
        PacketBufferPool pool(10);
        pool.release(nullptr);  // Should not crash
        REQUIRE(pool.availableCount() == 10);
    }

    SECTION("Each buffer is unique") {
        PacketBufferPool pool(10);
        std::set<PacketBuffer*> acquired;

        for (int i = 0; i < 10; ++i) {
            PacketBuffer* buf = pool.acquire();
            REQUIRE(buf != nullptr);
            auto [_, inserted] = acquired.insert(buf);
            REQUIRE(inserted);  // Must be unique
        }

        for (auto* buf : acquired) {
            pool.release(buf);
        }
    }
}

// ============================================================================
// ScopedBuffer Tests
// ============================================================================

TEST_CASE("ScopedBuffer RAII", "[buffer][scoped]") {
    PacketBufferPool pool(10);

    SECTION("Auto-release on scope exit") {
        {
            ScopedBuffer scoped(pool);
            REQUIRE(scoped.get() != nullptr);
            REQUIRE(pool.availableCount() == 9);
        }
        // Buffer should be released
        REQUIRE(pool.availableCount() == 10);
    }

    SECTION("Boolean conversion") {
        ScopedBuffer scoped(pool);
        REQUIRE(static_cast<bool>(scoped));
        REQUIRE(scoped.get() != nullptr);
    }

    SECTION("Arrow operator") {
        ScopedBuffer scoped(pool);
        scoped->setLength(100);
        REQUIRE(scoped->length() == 100);
    }

    SECTION("Release ownership") {
        PacketBuffer* rawPtr = nullptr;
        {
            ScopedBuffer scoped(pool);
            rawPtr = scoped.release();
            REQUIRE(scoped.get() == nullptr);
        }
        // Buffer should NOT be released (we took ownership)
        REQUIRE(pool.availableCount() == 9);
        
        // Manual cleanup
        pool.release(rawPtr);
        REQUIRE(pool.availableCount() == 10);
    }

    SECTION("Pool exhaustion") {
        PacketBufferPool smallPool(1);
        
        ScopedBuffer first(smallPool);
        REQUIRE(first.get() != nullptr);
        
        ScopedBuffer second(smallPool);
        REQUIRE(second.get() == nullptr);
        REQUIRE_FALSE(static_cast<bool>(second));
    }
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

TEST_CASE("PacketBufferPool concurrent access", "[buffer][concurrent]") {
    PacketBufferPool pool(1000);
    std::atomic<int> successCount{0};
    std::atomic<int> failCount{0};
    const int numThreads = 8;
    const int opsPerThread = 10000;

    SECTION("Concurrent acquire/release") {
        std::vector<std::thread> threads;

        for (int t = 0; t < numThreads; ++t) {
            threads.emplace_back([&pool, &successCount, &failCount]() {
                for (int i = 0; i < opsPerThread; ++i) {
                    PacketBuffer* buf = pool.acquire();
                    if (buf) {
                        successCount++;
                        // Simulate some work
                        buf->setLength(100);
                        volatile uint8_t x = buf->data()[0];
                        (void)x;
                        pool.release(buf);
                    } else {
                        failCount++;
                    }
                }
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        INFO("Successful acquires: " << successCount.load());
        INFO("Failed acquires: " << failCount.load());

        // All buffers should be back in the pool
        REQUIRE(pool.availableCount() == 1000);
        
        // Most operations should succeed
        REQUIRE(successCount.load() > numThreads * opsPerThread * 0.9);
    }

    SECTION("No double-free or corruption") {
        std::atomic<bool> error{false};
        std::vector<std::thread> threads;

        for (int t = 0; t < numThreads; ++t) {
            threads.emplace_back([&pool, &error]() {
                for (int i = 0; i < opsPerThread && !error.load(); ++i) {
                    PacketBuffer* buf = pool.acquire();
                    if (buf) {
                        // Write a pattern
                        std::memset(buf->data(), 0xAA, 100);
                        buf->setLength(100);

                        // Verify pattern before release
                        for (int j = 0; j < 100; ++j) {
                            if (buf->data()[j] != 0xAA) {
                                error.store(true);
                                break;
                            }
                        }

                        pool.release(buf);
                    }
                }
            });
        }

        for (auto& t : threads) {
            t.join();
        }

        REQUIRE_FALSE(error.load());
    }
}

// ============================================================================
// Performance Tests
// ============================================================================

TEST_CASE("PacketBufferPool performance", "[buffer][perf]") {
    PacketBufferPool pool(256);

    SECTION("Acquire/release throughput") {
        const int iterations = 100000;
        
        auto start = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < iterations; ++i) {
            PacketBuffer* buf = pool.acquire();
            if (buf) {
                buf->setLength(1500);
                pool.release(buf);
            }
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
        
        double avgNs = static_cast<double>(duration.count()) / iterations;
        double opsPerSec = 1e9 / avgNs;

        INFO("Average acquire+release: " << avgNs << " ns");
        INFO("Operations per second: " << opsPerSec);

        // Should be able to do millions of ops per second
        REQUIRE(opsPerSec > 1e6);
    }
}

