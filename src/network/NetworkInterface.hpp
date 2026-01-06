#pragma once

/**
 * @file NetworkInterface.hpp
 * @brief Network interface abstraction for packet capture and injection
 * 
 * Wraps libpcap for Layer 2 packet capture and injection.
 * Designed for low-latency operation with pre-allocated buffers.
 */

#include "armora/Types.hpp"
#include <string>
#include <functional>
#include <memory>

// Forward declaration for pcap
struct pcap;
typedef struct pcap pcap_t;

namespace armora {

/**
 * @brief Callback for received packets
 * @param data Packet data
 * @param length Packet length
 * @param timestamp Capture timestamp (microseconds since epoch)
 */
using PacketReceiveCallback = std::function<void(const uint8_t* data, 
                                                   size_t length,
                                                   uint64_t timestamp)>;

/**
 * @brief Network interface for packet capture and injection
 * 
 * Uses libpcap for raw packet access at Layer 2.
 */
class NetworkInterface {
public:
    /**
     * @brief Construct for a specific interface
     * @param interfaceName Name of the interface (e.g., "eth0")
     */
    explicit NetworkInterface(const std::string& interfaceName);

    ~NetworkInterface();

    // Non-copyable
    NetworkInterface(const NetworkInterface&) = delete;
    NetworkInterface& operator=(const NetworkInterface&) = delete;

    // Movable
    NetworkInterface(NetworkInterface&&) noexcept;
    NetworkInterface& operator=(NetworkInterface&&) noexcept;

    // ========================================================================
    // Configuration
    // ========================================================================

    /**
     * @brief Set capture timeout
     * @param timeoutMs Timeout in milliseconds (0 for no timeout)
     */
    void setCaptureTimeout(int timeoutMs);

    /**
     * @brief Enable/disable promiscuous mode
     * @param enabled True to enable promiscuous mode
     */
    void setPromiscuousMode(bool enabled);

    /**
     * @brief Set snapshot length (max bytes per packet)
     * @param snapLen Maximum bytes to capture per packet
     */
    void setSnapLength(int snapLen);

    /**
     * @brief Set BPF filter expression
     * @param filter BPF filter string (e.g., "not port 22")
     * @return Success or error code
     */
    ErrorCode setFilter(const std::string& filter);

    // ========================================================================
    // Lifecycle
    // ========================================================================

    /**
     * @brief Open the interface for capture
     * @return Success or error code
     */
    ErrorCode open();

    /**
     * @brief Close the interface
     */
    void close();

    /**
     * @brief Check if interface is open
     */
    bool isOpen() const;

    // ========================================================================
    // Packet Operations
    // ========================================================================

    /**
     * @brief Capture next packet (blocking)
     * 
     * @param[out] buffer Buffer to receive packet data
     * @param bufferSize Size of buffer
     * @param[out] packetLen Actual packet length
     * @param[out] timestamp Capture timestamp (microseconds since epoch)
     * @return Success, or error code (NetworkCaptureError on timeout/error)
     */
    ErrorCode capturePacket(uint8_t* buffer, size_t bufferSize,
                            size_t& packetLen, uint64_t& timestamp);

    /**
     * @brief Capture packets with callback (blocking loop)
     * 
     * @param callback Function to call for each packet
     * @param count Number of packets to capture (0 = infinite)
     * @return Error code if capture fails
     */
    ErrorCode captureLoop(PacketReceiveCallback callback, int count = 0);

    /**
     * @brief Break out of capture loop
     */
    void breakLoop();

    /**
     * @brief Send a packet on the interface
     * 
     * @param data Packet data (complete Ethernet frame)
     * @param length Packet length
     * @return Success or error code
     */
    ErrorCode sendPacket(const uint8_t* data, size_t length);

    // ========================================================================
    // Information
    // ========================================================================

    /**
     * @brief Get interface name
     */
    const std::string& getName() const;

    /**
     * @brief Get link type (DLT_*)
     */
    int getLinkType() const;

    /**
     * @brief Get last error message
     */
    std::string getLastError() const;

    /**
     * @brief Get statistics
     * @param[out] received Packets received
     * @param[out] dropped Packets dropped
     */
    void getStats(uint64_t& received, uint64_t& dropped) const;

private:
    std::string m_name;
    pcap_t* m_pcap = nullptr;

    int m_timeoutMs = DEFAULT_CAPTURE_TIMEOUT_MS;
    bool m_promiscuous = true;
    int m_snapLen = MAX_FRAME_SIZE;
    std::string m_filter;

    mutable std::string m_lastError;
};

/**
 * @brief Get list of available network interfaces
 * @return Vector of interface names
 */
std::vector<std::string> listNetworkInterfaces();

} // namespace armora

