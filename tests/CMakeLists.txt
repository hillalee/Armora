# ============================================================================
# Armora Test Configuration
# ============================================================================

# Fetch Catch2 (header-only test framework)
include(FetchContent)
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.4.0
)
FetchContent_MakeAvailable(Catch2)

# Include Catch2 CMake helpers
list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(CTest)
include(Catch)

# ============================================================================
# Test Executables
# ============================================================================

# Unit tests for crypto
add_executable(test_crypto
    test_crypto.cpp
)
target_link_libraries(test_crypto
    PRIVATE
        armora_static
        Catch2::Catch2WithMain
)
target_include_directories(test_crypto
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
)

# Unit tests for buffer pool
add_executable(test_buffer
    test_buffer.cpp
)
target_link_libraries(test_buffer
    PRIVATE
        armora_static
        Catch2::Catch2WithMain
)
target_include_directories(test_buffer
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
)

# Integration tests (requires root for veth)
add_executable(test_integration
    test_integration.cpp
)
target_link_libraries(test_integration
    PRIVATE
        armora_static
        Catch2::Catch2WithMain
)
target_include_directories(test_integration
    PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
)

# ============================================================================
# Register Tests with CTest
# ============================================================================

catch_discover_tests(test_crypto)
catch_discover_tests(test_buffer)

# Integration tests need special handling (require root)
add_test(
    NAME integration_tests
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/run_integration_tests.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(integration_tests PROPERTIES
    LABELS "integration"
    TIMEOUT 60
)

