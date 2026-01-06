/**
 * @file UdpTunnel.cpp
 * @brief Implementation of UDP tunnel transport
 */

#include "UdpTunnel.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cstring>
#include <cerrno>

namespace armora {

// ============================================================================
// Construction / Destruction
// ============================================================================

UdpTunnel::UdpTunnel(uint16_t localPort)
    : m_localPort(localPort) {
}

UdpTunnel::~UdpTunnel() {
    close();
}

// ============================================================================
// Configuration
// ============================================================================

void UdpTunnel::setRemotePeer(const std::string& address, uint16_t port) {
    m_remoteAddress = address;
    m_remotePort = port;
}

void UdpTunnel::setReceiveTimeout(int timeoutMs) {
    m_timeoutMs = timeoutMs;
}

void UdpTunnel::setBufferSizes(int sendSize, int recvSize) {
    m_sendBufferSize = sendSize;
    m_recvBufferSize = recvSize;
}

// ============================================================================
// Lifecycle
// ============================================================================

ErrorCode UdpTunnel::open() {
    if (m_socket >= 0) {
        return ErrorCode::Success;  // Already open
    }

    // Create UDP socket
    m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (m_socket < 0) {
        m_lastError = "Failed to create socket: " + std::string(strerror(errno));
        return ErrorCode::NetworkCaptureError;
    }

    // Allow address reuse
    int reuse = 1;
    setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    // Set buffer sizes
    setsockopt(m_socket, SOL_SOCKET, SO_SNDBUF, &m_sendBufferSize, sizeof(m_sendBufferSize));
    setsockopt(m_socket, SOL_SOCKET, SO_RCVBUF, &m_recvBufferSize, sizeof(m_recvBufferSize));

    // Bind to local port
    struct sockaddr_in localAddr;
    std::memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(m_localPort);
    localAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(m_socket, reinterpret_cast<struct sockaddr*>(&localAddr), 
             sizeof(localAddr)) < 0) {
        m_lastError = "Failed to bind: " + std::string(strerror(errno));
        ::close(m_socket);
        m_socket = -1;
        return ErrorCode::NetworkCaptureError;
    }

    // If port was 0, get the assigned port
    if (m_localPort == 0) {
        socklen_t len = sizeof(localAddr);
        getsockname(m_socket, reinterpret_cast<struct sockaddr*>(&localAddr), &len);
        m_localPort = ntohs(localAddr.sin_port);
    }

    return ErrorCode::Success;
}

void UdpTunnel::close() {
    stopReceiveLoop();
    
    if (m_socket >= 0) {
        ::close(m_socket);
        m_socket = -1;
    }
}

bool UdpTunnel::isOpen() const {
    return m_socket >= 0;
}

// ============================================================================
// Data Transfer
// ============================================================================

ErrorCode UdpTunnel::send(const uint8_t* data, size_t length) {
    if (m_remoteAddress.empty() || m_remotePort == 0) {
        m_lastError = "Remote peer not configured";
        return ErrorCode::InvalidArgument;
    }
    return sendTo(data, length, m_remoteAddress, m_remotePort);
}

ErrorCode UdpTunnel::sendTo(const uint8_t* data, size_t length,
                            const std::string& destAddr, uint16_t destPort) {
    if (m_socket < 0) {
        return ErrorCode::NetworkSendError;
    }

    // Resolve destination address
    struct sockaddr_in dest;
    std::memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(destPort);

    // Try as IP address first
    if (inet_pton(AF_INET, destAddr.c_str(), &dest.sin_addr) != 1) {
        // Try hostname resolution
        struct hostent* host = gethostbyname(destAddr.c_str());
        if (!host) {
            m_lastError = "Failed to resolve: " + destAddr;
            return ErrorCode::NetworkSendError;
        }
        std::memcpy(&dest.sin_addr, host->h_addr_list[0], host->h_length);
    }

    ssize_t sent = sendto(m_socket, data, length, 0,
                          reinterpret_cast<struct sockaddr*>(&dest),
                          sizeof(dest));
    
    if (sent < 0) {
        m_lastError = "Send failed: " + std::string(strerror(errno));
        return ErrorCode::NetworkSendError;
    }

    if (static_cast<size_t>(sent) != length) {
        m_lastError = "Partial send";
        return ErrorCode::NetworkSendError;
    }

    return ErrorCode::Success;
}

ErrorCode UdpTunnel::receive(uint8_t* buffer, size_t bufferSize,
                             size_t& receivedLen,
                             std::string* fromAddr, uint16_t* fromPort) {
    if (m_socket < 0) {
        return ErrorCode::NetworkCaptureError;
    }

    // Use poll for timeout
    if (m_timeoutMs > 0) {
        struct pollfd pfd;
        pfd.fd = m_socket;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, m_timeoutMs);
        if (ret < 0) {
            m_lastError = "Poll failed: " + std::string(strerror(errno));
            return ErrorCode::NetworkCaptureError;
        }
        if (ret == 0) {
            receivedLen = 0;
            return ErrorCode::NetworkCaptureError;  // Timeout
        }
    }

    struct sockaddr_in sender;
    socklen_t senderLen = sizeof(sender);
    
    ssize_t received = recvfrom(m_socket, buffer, bufferSize, 0,
                                reinterpret_cast<struct sockaddr*>(&sender),
                                &senderLen);

    if (received < 0) {
        m_lastError = "Receive failed: " + std::string(strerror(errno));
        return ErrorCode::NetworkCaptureError;
    }

    receivedLen = static_cast<size_t>(received);

    if (fromAddr) {
        char addrStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender.sin_addr, addrStr, sizeof(addrStr));
        *fromAddr = addrStr;
    }

    if (fromPort) {
        *fromPort = ntohs(sender.sin_port);
    }

    return ErrorCode::Success;
}

void UdpTunnel::receiveLoop(TunnelReceiveCallback callback) {
    if (!callback || m_socket < 0) {
        return;
    }

    m_running = true;
    
    uint8_t buffer[65536];  // Max UDP payload
    
    while (m_running) {
        size_t receivedLen = 0;
        std::string fromAddr;
        uint16_t fromPort = 0;

        ErrorCode err = receive(buffer, sizeof(buffer), receivedLen, 
                                &fromAddr, &fromPort);

        if (err == ErrorCode::Success && receivedLen > 0) {
            callback(buffer, receivedLen, fromAddr, fromPort);
        }
    }
}

void UdpTunnel::stopReceiveLoop() {
    m_running = false;
}

// ============================================================================
// Information
// ============================================================================

uint16_t UdpTunnel::getLocalPort() const {
    return m_localPort;
}

std::string UdpTunnel::getRemoteAddress() const {
    return m_remoteAddress;
}

uint16_t UdpTunnel::getRemotePort() const {
    return m_remotePort;
}

std::string UdpTunnel::getLastError() const {
    return m_lastError;
}

int UdpTunnel::getSocketFd() const {
    return m_socket;
}

} // namespace armora

