/**
 * @file NetworkInterface.cpp
 * @brief Implementation of network interface using libpcap
 */

#include "NetworkInterface.hpp"
#include <pcap/pcap.h>
#include <cstring>

namespace armora {

// ============================================================================
// Construction / Destruction
// ============================================================================

NetworkInterface::NetworkInterface(const std::string& interfaceName)
    : m_name(interfaceName) {
}

NetworkInterface::~NetworkInterface() {
    close();
}

NetworkInterface::NetworkInterface(NetworkInterface&& other) noexcept
    : m_name(std::move(other.m_name))
    , m_pcap(other.m_pcap)
    , m_timeoutMs(other.m_timeoutMs)
    , m_promiscuous(other.m_promiscuous)
    , m_snapLen(other.m_snapLen)
    , m_filter(std::move(other.m_filter))
    , m_lastError(std::move(other.m_lastError)) {
    other.m_pcap = nullptr;
}

NetworkInterface& NetworkInterface::operator=(NetworkInterface&& other) noexcept {
    if (this != &other) {
        close();
        m_name = std::move(other.m_name);
        m_pcap = other.m_pcap;
        m_timeoutMs = other.m_timeoutMs;
        m_promiscuous = other.m_promiscuous;
        m_snapLen = other.m_snapLen;
        m_filter = std::move(other.m_filter);
        m_lastError = std::move(other.m_lastError);
        other.m_pcap = nullptr;
    }
    return *this;
}

// ============================================================================
// Configuration
// ============================================================================

void NetworkInterface::setCaptureTimeout(int timeoutMs) {
    m_timeoutMs = timeoutMs;
}

void NetworkInterface::setPromiscuousMode(bool enabled) {
    m_promiscuous = enabled;
}

void NetworkInterface::setSnapLength(int snapLen) {
    m_snapLen = snapLen;
}

ErrorCode NetworkInterface::setFilter(const std::string& filter) {
    m_filter = filter;

    // If already open, apply filter immediately
    if (m_pcap) {
        struct bpf_program fp;
        if (pcap_compile(m_pcap, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
            m_lastError = pcap_geterr(m_pcap);
            return ErrorCode::NetworkCaptureError;
        }

        if (pcap_setfilter(m_pcap, &fp) == -1) {
            m_lastError = pcap_geterr(m_pcap);
            pcap_freecode(&fp);
            return ErrorCode::NetworkCaptureError;
        }

        pcap_freecode(&fp);
    }

    return ErrorCode::Success;
}

// ============================================================================
// Lifecycle
// ============================================================================

ErrorCode NetworkInterface::open() {
    if (m_pcap) {
        return ErrorCode::Success;  // Already open
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    // Create pcap handle
    m_pcap = pcap_create(m_name.c_str(), errbuf);
    if (!m_pcap) {
        m_lastError = errbuf;
        return ErrorCode::NetworkInterfaceNotFound;
    }

    // Configure capture options
    pcap_set_snaplen(m_pcap, m_snapLen);
    pcap_set_promisc(m_pcap, m_promiscuous ? 1 : 0);
    pcap_set_timeout(m_pcap, m_timeoutMs);

    // Enable immediate mode for low latency
    pcap_set_immediate_mode(m_pcap, 1);

    // Set buffer size (larger = less packet drops, but more latency)
    // 256KB is a reasonable balance for low-latency operation
    pcap_set_buffer_size(m_pcap, 256 * 1024);

    // Activate the capture
    int result = pcap_activate(m_pcap);
    if (result < 0) {
        m_lastError = pcap_statustostr(result);
        
        // Check for permission error
        if (result == PCAP_ERROR_PERM_DENIED) {
            pcap_close(m_pcap);
            m_pcap = nullptr;
            return ErrorCode::NetworkPermissionDenied;
        }
        
        pcap_close(m_pcap);
        m_pcap = nullptr;
        return ErrorCode::NetworkCaptureError;
    }

    // Apply BPF filter if set
    if (!m_filter.empty()) {
        ErrorCode err = setFilter(m_filter);
        if (err != ErrorCode::Success) {
            close();
            return err;
        }
    }

    // Set non-blocking mode for capturePacket()
    if (pcap_setnonblock(m_pcap, 0, errbuf) == -1) {
        // Non-fatal, continue with blocking mode
    }

    return ErrorCode::Success;
}

void NetworkInterface::close() {
    if (m_pcap) {
        pcap_close(m_pcap);
        m_pcap = nullptr;
    }
}

bool NetworkInterface::isOpen() const {
    return m_pcap != nullptr;
}

// ============================================================================
// Packet Operations
// ============================================================================

ErrorCode NetworkInterface::capturePacket(uint8_t* buffer, size_t bufferSize,
                                           size_t& packetLen, uint64_t& timestamp) {
    if (!m_pcap) {
        return ErrorCode::NetworkCaptureError;
    }

    struct pcap_pkthdr* header;
    const uint8_t* data;

    int result = pcap_next_ex(m_pcap, &header, &data);
    
    switch (result) {
        case 1:  // Packet captured
            packetLen = (header->caplen < bufferSize) ? header->caplen : bufferSize;
            std::memcpy(buffer, data, packetLen);
            timestamp = static_cast<uint64_t>(header->ts.tv_sec) * 1000000 
                      + static_cast<uint64_t>(header->ts.tv_usec);
            return ErrorCode::Success;

        case 0:  // Timeout
            packetLen = 0;
            return ErrorCode::NetworkCaptureError;

        case PCAP_ERROR:  // Error
            m_lastError = pcap_geterr(m_pcap);
            return ErrorCode::NetworkCaptureError;

        case PCAP_ERROR_BREAK:  // Loop broken
            return ErrorCode::NetworkCaptureError;

        default:
            return ErrorCode::NetworkCaptureError;
    }
}

// Static callback wrapper for pcap_loop
struct CaptureContext {
    PacketReceiveCallback* callback;
};

static void pcapCallback(u_char* user, const struct pcap_pkthdr* header,
                         const u_char* data) {
    auto* ctx = reinterpret_cast<CaptureContext*>(user);
    uint64_t timestamp = static_cast<uint64_t>(header->ts.tv_sec) * 1000000
                       + static_cast<uint64_t>(header->ts.tv_usec);
    (*ctx->callback)(data, header->caplen, timestamp);
}

ErrorCode NetworkInterface::captureLoop(PacketReceiveCallback callback, int count) {
    if (!m_pcap) {
        return ErrorCode::NetworkCaptureError;
    }

    CaptureContext ctx{&callback};
    
    int result = pcap_loop(m_pcap, count, pcapCallback, 
                           reinterpret_cast<u_char*>(&ctx));
    
    if (result == PCAP_ERROR) {
        m_lastError = pcap_geterr(m_pcap);
        return ErrorCode::NetworkCaptureError;
    }

    return ErrorCode::Success;
}

void NetworkInterface::breakLoop() {
    if (m_pcap) {
        pcap_breakloop(m_pcap);
    }
}

ErrorCode NetworkInterface::sendPacket(const uint8_t* data, size_t length) {
    if (!m_pcap) {
        return ErrorCode::NetworkSendError;
    }

    if (pcap_inject(m_pcap, data, length) == -1) {
        m_lastError = pcap_geterr(m_pcap);
        return ErrorCode::NetworkSendError;
    }

    return ErrorCode::Success;
}

// ============================================================================
// Information
// ============================================================================

const std::string& NetworkInterface::getName() const {
    return m_name;
}

int NetworkInterface::getLinkType() const {
    if (!m_pcap) {
        return -1;
    }
    return pcap_datalink(m_pcap);
}

std::string NetworkInterface::getLastError() const {
    return m_lastError;
}

void NetworkInterface::getStats(uint64_t& received, uint64_t& dropped) const {
    received = 0;
    dropped = 0;

    if (!m_pcap) {
        return;
    }

    struct pcap_stat stats;
    if (pcap_stats(m_pcap, &stats) == 0) {
        received = stats.ps_recv;
        dropped = stats.ps_drop;
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

std::vector<std::string> listNetworkInterfaces() {
    std::vector<std::string> interfaces;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return interfaces;
    }

    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        if (dev->name) {
            interfaces.push_back(dev->name);
        }
    }

    pcap_freealldevs(alldevs);
    return interfaces;
}

} // namespace armora

