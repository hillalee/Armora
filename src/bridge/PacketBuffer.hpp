#pragma once

/**
 * @file PacketBuffer.hpp
 * @brief Pre-allocated packet buffer for low-latency operation
 * 
 * Provides a pool of pre-allocated buffers to avoid malloc() in the
 * hot path during packet processing.
 */

#include "armora/Types.hpp"
#include <array>
#include <atomic>
#include <vector>
#include <memory>

namespace armora {

/**
 * @brief Single packet buffer with fixed maximum size
 * 
 * Holds one Ethernet frame plus crypto overhead.
 */
class PacketBuffer {
public:
    /// Maximum buffer size (MTU + headers + crypto overhead)
    static constexpr size_t BUFFER_SIZE = MAX_FRAME_SIZE + CRYPTO_OVERHEAD + 64;

    PacketBuffer() : m_length(0) {
        m_data.fill(0);
    }

    /// Get raw data pointer
    uint8_t* data() { return m_data.data(); }
    const uint8_t* data() const { return m_data.data(); }

    /// Get current data length
    size_t length() const { return m_length; }

    /// Set data length
    void setLength(size_t len) { 
        m_length = (len <= BUFFER_SIZE) ? len : BUFFER_SIZE;
    }

    /// Get maximum capacity
    static constexpr size_t capacity() { return BUFFER_SIZE; }

    /// Clear the buffer
    void clear() { m_length = 0; }

    /// Check if buffer has data
    bool hasData() const { return m_length > 0; }

private:
    std::array<uint8_t, BUFFER_SIZE> m_data;
    size_t m_length;
};

/**
 * @brief Lock-free packet buffer pool
 * 
 * Uses atomic operations for thread-safe buffer allocation without locks.
 * Suitable for high-frequency packet processing.
 */
class PacketBufferPool {
public:
    /**
     * @brief Construct a buffer pool
     * @param count Number of buffers to pre-allocate
     */
    explicit PacketBufferPool(size_t count = DEFAULT_BUFFER_COUNT)
        : m_buffers(count)
        , m_available(count)
        , m_head(0)
        , m_tail(0) {
        
        // Initialize all slots as available
        for (size_t i = 0; i < count; ++i) {
            m_available[i].store(true, std::memory_order_relaxed);
        }
    }

    /**
     * @brief Acquire a buffer from the pool
     * @return Pointer to buffer, or nullptr if pool exhausted
     */
    PacketBuffer* acquire() {
        // Try to find an available buffer
        size_t attempts = m_buffers.size();
        while (attempts-- > 0) {
            size_t idx = m_head.fetch_add(1, std::memory_order_relaxed) % m_buffers.size();
            
            bool expected = true;
            if (m_available[idx].compare_exchange_strong(expected, false,
                    std::memory_order_acquire, std::memory_order_relaxed)) {
                m_buffers[idx].clear();
                return &m_buffers[idx];
            }
        }
        return nullptr;  // Pool exhausted
    }

    /**
     * @brief Release a buffer back to the pool
     * @param buffer Buffer to release (must be from this pool)
     */
    void release(PacketBuffer* buffer) {
        if (!buffer) return;

        // Find buffer index
        ptrdiff_t idx = buffer - m_buffers.data();
        if (idx < 0 || static_cast<size_t>(idx) >= m_buffers.size()) {
            return;  // Not from this pool
        }

        buffer->clear();
        m_available[idx].store(true, std::memory_order_release);
    }

    /**
     * @brief Get pool size
     */
    size_t size() const { return m_buffers.size(); }

    /**
     * @brief Get approximate number of available buffers
     */
    size_t availableCount() const {
        size_t count = 0;
        for (const auto& avail : m_available) {
            if (avail.load(std::memory_order_relaxed)) {
                ++count;
            }
        }
        return count;
    }

private:
    std::vector<PacketBuffer> m_buffers;
    std::vector<std::atomic<bool>> m_available;
    std::atomic<size_t> m_head;
    std::atomic<size_t> m_tail;
};

/**
 * @brief RAII wrapper for buffer acquisition
 * 
 * Automatically releases buffer when going out of scope.
 */
class ScopedBuffer {
public:
    ScopedBuffer(PacketBufferPool& pool) 
        : m_pool(pool), m_buffer(pool.acquire()) {}
    
    ~ScopedBuffer() {
        if (m_buffer) {
            m_pool.release(m_buffer);
        }
    }

    // Non-copyable
    ScopedBuffer(const ScopedBuffer&) = delete;
    ScopedBuffer& operator=(const ScopedBuffer&) = delete;

    // Movable
    ScopedBuffer(ScopedBuffer&& other) noexcept
        : m_pool(other.m_pool), m_buffer(other.m_buffer) {
        other.m_buffer = nullptr;
    }

    /// Get underlying buffer
    PacketBuffer* get() { return m_buffer; }
    const PacketBuffer* get() const { return m_buffer; }

    /// Check if buffer was acquired
    explicit operator bool() const { return m_buffer != nullptr; }

    /// Access buffer
    PacketBuffer* operator->() { return m_buffer; }
    const PacketBuffer* operator->() const { return m_buffer; }

    /// Release ownership (caller must release manually)
    PacketBuffer* release() {
        PacketBuffer* buf = m_buffer;
        m_buffer = nullptr;
        return buf;
    }

private:
    PacketBufferPool& m_pool;
    PacketBuffer* m_buffer;
};

} // namespace armora

