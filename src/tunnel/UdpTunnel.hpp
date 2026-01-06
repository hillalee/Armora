#pragma once

/**
 * @file UdpTunnel.hpp
 * @brief UDP socket wrapper for tunnel mode
 * 
 * Provides a UDP transport layer for sending encrypted packets
 * across IP networks (like a VPN).
 */

#include "armora/Types.hpp"
#include <string>
#include <atomic>
#include <functional>

namespace armora {

/**
 * @brief Callback for received tunnel packets
 * @param data Packet data
 * @param length Packet length
 * @param fromAddr Source IP address
 * @param fromPort Source port
 */
using TunnelReceiveCallback = std::function<void(
    const uint8_t* data, size_t length,
    const std::string& fromAddr, uint16_t fromPort)>;

/**
 * @brief UDP tunnel for encrypted packet transport
 * 
 * This class provides point-to-point UDP communication for
 * transporting encrypted Ethernet frames across IP networks.
 */
class UdpTunnel {
public:
    /**
     * @brief Construct a UDP tunnel
     * @param localPort Port to bind locally
     */
    explicit UdpTunnel(uint16_t localPort);

    ~UdpTunnel();

    // Non-copyable
    UdpTunnel(const UdpTunnel&) = delete;
    UdpTunnel& operator=(const UdpTunnel&) = delete;

    // ========================================================================
    // Configuration
    // ========================================================================

    /**
     * @brief Set remote peer address
     * @param address IP address or hostname
     * @param port UDP port
     */
    void setRemotePeer(const std::string& address, uint16_t port);

    /**
     * @brief Set receive timeout
     * @param timeoutMs Timeout in milliseconds (0 = blocking)
     */
    void setReceiveTimeout(int timeoutMs);

    /**
     * @brief Set send/receive buffer sizes
     * @param sendSize Send buffer size in bytes
     * @param recvSize Receive buffer size in bytes
     */
    void setBufferSizes(int sendSize, int recvSize);

    // ========================================================================
    // Lifecycle
    // ========================================================================

    /**
     * @brief Open the tunnel (bind to local port)
     * @return Success or error code
     */
    ErrorCode open();

    /**
     * @brief Close the tunnel
     */
    void close();

    /**
     * @brief Check if tunnel is open
     */
    bool isOpen() const;

    // ========================================================================
    // Data Transfer
    // ========================================================================

    /**
     * @brief Send data to remote peer
     * @param data Data to send
     * @param length Data length
     * @return Success or error code
     */
    ErrorCode send(const uint8_t* data, size_t length);

    /**
     * @brief Send data to specific address
     * @param data Data to send
     * @param length Data length
     * @param destAddr Destination IP address
     * @param destPort Destination port
     * @return Success or error code
     */
    ErrorCode sendTo(const uint8_t* data, size_t length,
                     const std::string& destAddr, uint16_t destPort);

    /**
     * @brief Receive data (blocking or with timeout)
     * @param[out] buffer Buffer for received data
     * @param bufferSize Buffer size
     * @param[out] receivedLen Actual received length
     * @param[out] fromAddr Source address (optional)
     * @param[out] fromPort Source port (optional)
     * @return Success or error code
     */
    ErrorCode receive(uint8_t* buffer, size_t bufferSize,
                      size_t& receivedLen,
                      std::string* fromAddr = nullptr,
                      uint16_t* fromPort = nullptr);

    /**
     * @brief Run receive loop with callback
     * @param callback Function to call for each received packet
     */
    void receiveLoop(TunnelReceiveCallback callback);

    /**
     * @brief Break out of receive loop
     */
    void stopReceiveLoop();

    // ========================================================================
    // Information
    // ========================================================================

    /**
     * @brief Get local port
     */
    uint16_t getLocalPort() const;

    /**
     * @brief Get remote peer address
     */
    std::string getRemoteAddress() const;

    /**
     * @brief Get remote peer port
     */
    uint16_t getRemotePort() const;

    /**
     * @brief Get last error message
     */
    std::string getLastError() const;

    /**
     * @brief Get socket file descriptor (for advanced use)
     */
    int getSocketFd() const;

private:
    uint16_t m_localPort;
    std::string m_remoteAddress;
    uint16_t m_remotePort = 0;
    
    int m_socket = -1;
    int m_timeoutMs = 1000;
    int m_sendBufferSize = 256 * 1024;
    int m_recvBufferSize = 256 * 1024;
    
    std::atomic<bool> m_running{false};
    mutable std::string m_lastError;
};

} // namespace armora

