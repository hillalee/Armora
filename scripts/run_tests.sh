#!/bin/bash
# ============================================================================
# run_tests.sh - Run all Armora tests
# ============================================================================
#
# Usage:
#   ./run_tests.sh              # Run unit tests only
#   ./run_tests.sh --all        # Run unit + integration tests (requires root)
#   ./run_tests.sh --integration # Run integration tests only (requires root)
#
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_DIR}/build"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Print header
print_header() {
    echo ""
    echo -e "${BLUE}============================================${NC}"
    echo -e "${BLUE}  Armora Test Suite${NC}"
    echo -e "${BLUE}============================================${NC}"
    echo ""
}

# Build if needed
build_tests() {
    echo -e "${YELLOW}Building tests...${NC}"
    
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    
    cmake -DBUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug .. 
    make -j$(nproc)
    
    echo -e "${GREEN}Build complete.${NC}"
    echo ""
}

# Run unit tests
run_unit_tests() {
    echo -e "${BLUE}Running unit tests...${NC}"
    echo ""
    
    cd "$BUILD_DIR"
    
    # Crypto tests
    echo -e "${YELLOW}>>> Crypto Tests${NC}"
    if ./tests/test_crypto --reporter compact; then
        echo -e "${GREEN}✓ Crypto tests passed${NC}"
    else
        echo -e "${RED}✗ Crypto tests failed${NC}"
        return 1
    fi
    echo ""
    
    # Buffer tests
    echo -e "${YELLOW}>>> Buffer Pool Tests${NC}"
    if ./tests/test_buffer --reporter compact; then
        echo -e "${GREEN}✓ Buffer tests passed${NC}"
    else
        echo -e "${RED}✗ Buffer tests failed${NC}"
        return 1
    fi
    echo ""
    
    echo -e "${GREEN}All unit tests passed!${NC}"
}

# Run integration tests
run_integration_tests() {
    echo -e "${BLUE}Running integration tests...${NC}"
    echo ""
    
    # Check for root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: Integration tests require root privileges${NC}"
        echo "Run with: sudo $0 --integration"
        return 1
    fi
    
    cd "$BUILD_DIR"
    
    # Setup virtual interfaces
    echo -e "${YELLOW}Setting up virtual interfaces...${NC}"
    "$SCRIPT_DIR/setup_veth.sh" create
    
    # Run integration tests
    echo -e "${YELLOW}>>> Integration Tests${NC}"
    if ./tests/test_integration --reporter compact; then
        echo -e "${GREEN}✓ Integration tests passed${NC}"
    else
        echo -e "${RED}✗ Integration tests failed${NC}"
        "$SCRIPT_DIR/setup_veth.sh" destroy
        return 1
    fi
    
    # Cleanup
    echo -e "${YELLOW}Cleaning up virtual interfaces...${NC}"
    "$SCRIPT_DIR/setup_veth.sh" destroy
    
    echo ""
    echo -e "${GREEN}All integration tests passed!${NC}"
}

# Run ctest (all registered tests)
run_ctest() {
    echo -e "${BLUE}Running all tests via CTest...${NC}"
    cd "$BUILD_DIR"
    ctest --output-on-failure
}

# Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  (none)          Run unit tests only"
    echo "  --all           Run unit + integration tests (requires root)"
    echo "  --integration   Run integration tests only (requires root)"
    echo "  --ctest         Run via CTest"
    echo "  --build-only    Just build, don't run tests"
    echo "  --help          Show this help"
    echo ""
}

# Parse arguments
print_header

case "${1:-}" in
    --all)
        build_tests
        run_unit_tests
        run_integration_tests
        ;;
    --integration)
        build_tests
        run_integration_tests
        ;;
    --ctest)
        build_tests
        run_ctest
        ;;
    --build-only)
        build_tests
        ;;
    --help)
        show_usage
        ;;
    *)
        build_tests
        run_unit_tests
        ;;
esac

echo ""
echo -e "${GREEN}Done!${NC}"

