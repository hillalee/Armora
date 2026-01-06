cmake_minimum_required(VERSION 3.16)
project(armora 
    VERSION 0.1.0
    DESCRIPTION "Quantum-Resistant Ethernet Bridge"
    LANGUAGES CXX
)

# ============================================================================
# Build Configuration
# ============================================================================
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Build type defaults to Release for production performance
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ============================================================================
# Compiler Flags for Low-Latency Operation
# ============================================================================
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")

# Platform-specific optimizations
if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|aarch64")
    # ARM optimizations for NanoPi/Armbian
    add_compile_options(-mcpu=native -mtune=native)
    message(STATUS "Building for ARM architecture")
else()
    # x86 optimizations for development
    add_compile_options(-march=native -mtune=native)
    message(STATUS "Building for x86 architecture")
endif()

# Common flags for low-latency
add_compile_options(
    -Wall 
    -Wextra 
    -Wpedantic
    -fno-exceptions      # Reduce overhead (optional, remove if exceptions needed)
    -ffast-math          # Faster math operations
)

# ============================================================================
# Dependencies
# ============================================================================

# OpenSSL (for AES-256-GCM)
find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
    message(STATUS "Found OpenSSL: ${OPENSSL_VERSION}")
endif()

# libpcap (for packet capture)
find_path(PCAP_INCLUDE_DIR pcap.h
    HINTS /usr/include /usr/local/include
)
find_library(PCAP_LIBRARY pcap
    HINTS /usr/lib /usr/local/lib /usr/lib/aarch64-linux-gnu /usr/lib/arm-linux-gnueabihf
)
if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found. Install with: sudo apt install libpcap-dev")
endif()
message(STATUS "Found libpcap: ${PCAP_LIBRARY}")

# liboqs (for Kyber1024 PQC)
find_path(OQS_INCLUDE_DIR oqs/oqs.h
    HINTS /usr/include /usr/local/include
)
find_library(OQS_LIBRARY oqs
    HINTS /usr/lib /usr/local/lib /usr/lib/aarch64-linux-gnu /usr/lib/arm-linux-gnueabihf
)
if(NOT OQS_INCLUDE_DIR OR NOT OQS_LIBRARY)
    message(FATAL_ERROR "liboqs not found. Install from: https://github.com/open-quantum-safe/liboqs")
endif()
message(STATUS "Found liboqs: ${OQS_LIBRARY}")

# Threads
find_package(Threads REQUIRED)

# ============================================================================
# Library Sources
# ============================================================================
set(ARMORA_SOURCES
    src/crypto/CryptoHandler.cpp
    src/crypto/HybridPQCProvider.cpp
    src/network/NetworkInterface.cpp
    src/bridge/BridgeEngine.cpp
    src/tunnel/UdpTunnel.cpp
    src/tunnel/TunnelEngine.cpp
)

set(ARMORA_HEADERS
    include/armora/Types.hpp
    src/crypto/ICryptoProvider.hpp
    src/crypto/CryptoHandler.hpp
    src/crypto/HybridPQCProvider.hpp
    src/network/NetworkInterface.hpp
    src/network/PcapCapture.hpp
    src/bridge/BridgeEngine.hpp
    src/bridge/PacketBuffer.hpp
    src/tunnel/UdpTunnel.hpp
    src/tunnel/TunnelEngine.hpp
)

# ============================================================================
# Static Library (for integration into hardware firmware)
# ============================================================================
add_library(armora_static STATIC ${ARMORA_SOURCES})
set_target_properties(armora_static PROPERTIES OUTPUT_NAME armora)

target_include_directories(armora_static
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${PCAP_INCLUDE_DIR}
        ${OQS_INCLUDE_DIR}
        ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(armora_static
    PUBLIC
        ${PCAP_LIBRARY}
        ${OQS_LIBRARY}
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)

# ============================================================================
# Executables
# ============================================================================

# Bridge mode (Layer 2 between local interfaces)
add_executable(armora-bridge src/main.cpp)

target_include_directories(armora-bridge
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${PCAP_INCLUDE_DIR}
        ${OQS_INCLUDE_DIR}
        ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(armora-bridge
    PRIVATE
        armora_static
)

# Tunnel mode (encrypted UDP over IP networks)
add_executable(armora-tunnel src/tunnel_main.cpp)

target_include_directories(armora-tunnel
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${PCAP_INCLUDE_DIR}
        ${OQS_INCLUDE_DIR}
        ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(armora-tunnel
    PRIVATE
        armora_static
)

# ============================================================================
# Installation
# ============================================================================
include(GNUInstallDirs)

# Install static library
install(TARGETS armora_static
    EXPORT armoraTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# Install public headers
install(DIRECTORY include/armora
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Install executables
install(TARGETS armora-bridge armora-tunnel
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Export targets for find_package() support
install(EXPORT armoraTargets
    FILE armoraTargets.cmake
    NAMESPACE armora::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/armora
)

# ============================================================================
# Package Configuration
# ============================================================================
include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/armoraConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/armoraConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/armora
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/armoraConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/armoraConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/armoraConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/armora
)

# ============================================================================
# Testing (optional, enable with -DBUILD_TESTS=ON)
# ============================================================================
option(BUILD_TESTS "Build unit and integration tests" OFF)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
    message(STATUS "Tests: ENABLED")
else()
    message(STATUS "Tests: DISABLED (use -DBUILD_TESTS=ON to enable)")
endif()

# ============================================================================
# Summary
# ============================================================================
message(STATUS "")
message(STATUS "=== Armora Build Configuration ===")
message(STATUS "Version:      ${PROJECT_VERSION}")
message(STATUS "Build type:   ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
message(STATUS "Targets:")
message(STATUS "  - libarmora.a    (static library for firmware integration)")
message(STATUS "  - armora-bridge  (Layer 2 bridge between local interfaces)")
message(STATUS "  - armora-tunnel  (IP tunnel mode for remote communication)")
message(STATUS "")

