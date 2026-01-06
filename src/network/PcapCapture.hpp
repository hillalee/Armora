#pragma once

/**
 * @file PcapCapture.hpp
 * @brief Low-level pcap utilities and helpers
 */

#include "armora/Types.hpp"
#include <cstdint>
#include <cstring>

namespace armora {

/**
 * @brief Ethernet header structure
 */
#pragma pack(push, 1)
struct EthernetHeader {
    uint8_t destMac[6];
    uint8_t srcMac[6];
    uint16_t etherType;

    /// Check if this is an IPv4 packet (etherType 0x0800)
    bool isIPv4() const { 
        return etherType == 0x0008;  // Network byte order
    }

    /// Check if this is an IPv6 packet (etherType 0x86DD)
    bool isIPv6() const {
        return etherType == 0xDD86;  // Network byte order
    }

    /// Check if this is an ARP packet (etherType 0x0806)
    bool isARP() const {
        return etherType == 0x0608;  // Network byte order
    }
};
#pragma pack(pop)

static_assert(sizeof(EthernetHeader) == 14, "EthernetHeader must be 14 bytes");

/**
 * @brief Swap MAC addresses in an Ethernet header
 * 
 * Useful for creating response packets or when bridging
 * needs to preserve original addresses.
 */
inline void swapMacAddresses(EthernetHeader* header) {
    uint8_t tmp[6];
    std::memcpy(tmp, header->destMac, 6);
    std::memcpy(header->destMac, header->srcMac, 6);
    std::memcpy(header->srcMac, tmp, 6);
}

/**
 * @brief Copy MAC address
 */
inline void copyMacAddress(uint8_t* dest, const uint8_t* src) {
    std::memcpy(dest, src, 6);
}

/**
 * @brief Compare MAC addresses
 */
inline bool compareMacAddress(const uint8_t* a, const uint8_t* b) {
    return std::memcmp(a, b, 6) == 0;
}

/**
 * @brief Check if MAC is broadcast (FF:FF:FF:FF:FF:FF)
 */
inline bool isBroadcastMac(const uint8_t* mac) {
    return mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF &&
           mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF;
}

/**
 * @brief Check if MAC is multicast (LSB of first byte is 1)
 */
inline bool isMulticastMac(const uint8_t* mac) {
    return (mac[0] & 0x01) != 0;
}

/**
 * @brief Format MAC address as string
 */
inline std::string formatMacAddress(const uint8_t* mac) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

/**
 * @brief Get payload pointer from Ethernet frame
 */
inline const uint8_t* getEthernetPayload(const uint8_t* frame) {
    return frame + sizeof(EthernetHeader);
}

/**
 * @brief Get payload pointer from Ethernet frame (mutable)
 */
inline uint8_t* getEthernetPayload(uint8_t* frame) {
    return frame + sizeof(EthernetHeader);
}

/**
 * @brief Get payload length from Ethernet frame
 */
inline size_t getEthernetPayloadLength(size_t frameLength) {
    if (frameLength <= sizeof(EthernetHeader)) {
        return 0;
    }
    return frameLength - sizeof(EthernetHeader);
}

} // namespace armora

