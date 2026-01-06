#!/bin/bash
# ============================================================================
# run_integration_tests.sh - Run integration tests with veth setup
# ============================================================================
# This script is called by CTest for integration tests.
# It handles veth setup/teardown around the test execution.
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${1:-$(pwd)}"

# Check for root
if [[ $EUID -ne 0 ]]; then
    echo "Integration tests require root. Skipping."
    exit 0  # Don't fail CTest, just skip
fi

# Setup
echo "Setting up virtual interfaces..."
"$SCRIPT_DIR/setup_veth.sh" create

# Run tests
echo "Running integration tests..."
RESULT=0
"$BUILD_DIR/tests/test_integration" || RESULT=$?

# Teardown
echo "Cleaning up virtual interfaces..."
"$SCRIPT_DIR/setup_veth.sh" destroy

exit $RESULT

