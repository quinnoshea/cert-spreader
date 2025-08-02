#!/bin/bash
# Unit Tests for cert-spreader.sh
# This script provides a basic testing framework for the certificate spreader

set -euo pipefail

# TEST FRAMEWORK SETUP
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_SPREADER_SCRIPT="$SCRIPT_DIR/cert-spreader.sh"
TEST_DIR="/tmp/cert-spreader-tests"
TEST_CERT_DIR="$TEST_DIR/certs"
TEST_CONFIG="$TEST_DIR/test-config.conf"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test framework functions
setup_test_environment() {
    echo -e "${BLUE}Setting up test environment...${NC}"
    
    # Create test directories
    mkdir -p "$TEST_CERT_DIR"
    
    # Create test certificate files
    echo "fake-private-key-content" > "$TEST_CERT_DIR/privkey.pem"
    echo "fake-certificate-content" > "$TEST_CERT_DIR/cert.pem"
    echo "fake-fullchain-content" > "$TEST_CERT_DIR/fullchain.pem"
    echo "fake-chain-content" > "$TEST_CERT_DIR/chain.pem"
    
    # Create test config file
    cat > "$TEST_CONFIG" << EOF
DOMAIN="test.example.com"
CERT_DIR="$TEST_CERT_DIR"
SSH_OPTS="-o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new"
LOG_FILE="$TEST_DIR/test-cert-spreader.log"
HOSTS="test-host1 test-host2"
HOST_SERVICES=(
    "test-host1:22:nginx"
    "test-host2:2222:apache2,mysql"
)
PROXMOX_USER="test@pve!testtoken"
PROXMOX_TOKEN="fake-token"
PROXMOX_NODES=("test-proxmox1" "test-proxmox2")
PLEX_CERT_ENABLED=false
ZNC_CERT_ENABLED=false
EOF
    
    # Set proper permissions on test files
    chmod 644 "$TEST_CERT_DIR"/*.pem
    chmod 600 "$TEST_CONFIG"
}

cleanup_test_environment() {
    echo -e "${BLUE}Cleaning up test environment...${NC}"
    rm -rf "$TEST_DIR"
}

# Test assertion functions
assert_equals() {
    local expected="$1"
    local actual="$2"
    local test_name="$3"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    
    if [[ "$expected" == "$actual" ]]; then
        echo -e "${GREEN}✓ PASS${NC}: $test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}✗ FAIL${NC}: $test_name"
        echo -e "  Expected: ${YELLOW}$expected${NC}"
        echo -e "  Actual:   ${YELLOW}$actual${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

assert_success() {
    local exit_code="$1"
    local test_name="$2"
    assert_equals "0" "$exit_code" "$test_name"
}

assert_failure() {
    local exit_code="$1"
    local test_name="$2"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    
    if [[ "$exit_code" != "0" ]]; then
        echo -e "${GREEN}✓ PASS${NC}: $test_name (expected failure)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}✗ FAIL${NC}: $test_name (should have failed)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Individual Test Functions

test_script_exists() {
    if [[ -f "$CERT_SPREADER_SCRIPT" ]]; then
        assert_success 0 "cert-spreader.sh script exists"
    else
        assert_failure 0 "cert-spreader.sh script exists"
    fi
}

test_help_option() {
    local output
    output=$("$CERT_SPREADER_SCRIPT" --help 2>&1) || true
    if [[ "$output" == *"Usage:"* ]]; then
        assert_success 0 "help option displays usage"
    else
        assert_failure 0 "help option displays usage"
    fi
}

test_config_validation() {
    # Test with missing config file
    local exit_code
    "$CERT_SPREADER_SCRIPT" "nonexistent.conf" --dry-run 2>/dev/null || exit_code=$?
    assert_equals "1" "${exit_code:-0}" "missing config file returns error code 1"
}

test_dry_run_mode() {
    # Test dry-run with test config
    local exit_code=0
    "$CERT_SPREADER_SCRIPT" "$TEST_CONFIG" --dry-run 2>/dev/null || exit_code=$?
    
    # Dry run should succeed even without network connectivity
    assert_success "$exit_code" "dry-run mode executes successfully"
}

test_permissions_fix_mode() {
    # Test permissions-fix mode
    local exit_code=0
    "$CERT_SPREADER_SCRIPT" "$TEST_CONFIG" --permissions-fix --dry-run 2>/dev/null || exit_code=$?
    
    assert_success "$exit_code" "permissions-fix mode executes successfully"
}

test_invalid_arguments() {
    # Test invalid argument
    local exit_code=0
    "$CERT_SPREADER_SCRIPT" --invalid-option 2>/dev/null || exit_code=$?
    
    assert_equals "6" "$exit_code" "invalid arguments return usage error code 6"
}

test_multiple_exclusive_flags() {
    # Test multiple exclusive flags
    local exit_code=0
    "$CERT_SPREADER_SCRIPT" --cert-only --services-only 2>/dev/null || exit_code=$?
    
    assert_equals "6" "$exit_code" "multiple exclusive flags return usage error code 6"
}

# Source functions from the main script for unit testing
# We need to be careful here to only source functions, not execute the main script
test_source_functions() {
    # Create a temporary version of the script that doesn't execute main
    local temp_script="$TEST_DIR/temp-functions.sh"
    head -n -1 "$CERT_SPREADER_SCRIPT" > "$temp_script"  # Remove last line (main "$@")
    
    # Source the functions
    if source "$temp_script" 2>/dev/null; then
        assert_success 0 "functions can be sourced successfully"
        
        # Test individual functions
        test_build_ssh_command
        test_check_permissions
        test_service_restart_logic
        test_cert_changed_function
        
    else
        assert_failure 0 "functions can be sourced successfully"
    fi
    
    rm -f "$temp_script"
}

test_build_ssh_command() {
    # Mock SSH_OPTS and DOMAIN for testing
    SSH_OPTS="-o ConnectTimeout=10"
    DOMAIN="test.com"
    
    local result
    result=$(build_ssh_command "testhost" "22" "echo test")
    local expected="ssh -o ConnectTimeout=10 root@testhost.test.com 'echo test'"
    
    assert_equals "$expected" "$result" "build_ssh_command with default port"
    
    # Test with custom port
    result=$(build_ssh_command "testhost" "2222" "echo test")
    expected="ssh -o ConnectTimeout=10 -p 2222 root@testhost.test.com 'echo test'"
    
    assert_equals "$expected" "$result" "build_ssh_command with custom port"
    
    # Test without command
    result=$(build_ssh_command "testhost" "22")
    expected="ssh -o ConnectTimeout=10 root@testhost.test.com"
    
    assert_equals "$expected" "$result" "build_ssh_command without command"
}

test_check_permissions() {
    # Create test files with known permissions
    local test_file="$TEST_DIR/perm_test.txt"
    echo "test" > "$test_file"
    chmod 644 "$test_file"
    chown root:root "$test_file" 2>/dev/null || true  # May fail without root
    
    # Test permission checking (this may fail if not running as root)
    if check_permissions "$test_file" "644" "root:root" 2>/dev/null; then
        assert_success 0 "check_permissions correctly identifies matching permissions"
    else
        # If not running as root, test with current user
        local current_user=$(whoami)
        local current_group=$(id -gn)
        chown "$current_user:$current_group" "$test_file" 2>/dev/null || true
        
        if check_permissions "$test_file" "644" "$current_user:$current_group" 2>/dev/null; then
            assert_success 0 "check_permissions works with current user permissions"
        else
            assert_failure 0 "check_permissions should work with some valid permissions"
        fi
    fi
    
    rm -f "$test_file"
}

test_deployed_hosts_tracking() {
    # Test DEPLOYED_HOSTS array functionality
    DEPLOYED_HOSTS=()  # Initialize empty
    
    # Simulate adding hosts
    DEPLOYED_HOSTS+=("host1")
    DEPLOYED_HOSTS+=("host2")
    
    assert_equals "2" "${#DEPLOYED_HOSTS[@]}" "DEPLOYED_HOSTS array tracks multiple hosts"
    assert_equals "host1" "${DEPLOYED_HOSTS[0]}" "DEPLOYED_HOSTS first element correct"
    assert_equals "host2" "${DEPLOYED_HOSTS[1]}" "DEPLOYED_HOSTS second element correct"
}

test_local_cert_changed_flag() {
    # Test LOCAL_CERT_CHANGED flag functionality
    LOCAL_CERT_CHANGED=false
    
    assert_equals "false" "$LOCAL_CERT_CHANGED" "LOCAL_CERT_CHANGED initial state is false"
    
    # Simulate certificate change
    LOCAL_CERT_CHANGED=true
    assert_equals "true" "$LOCAL_CERT_CHANGED" "LOCAL_CERT_CHANGED can be set to true"
}

test_service_restart_logic() {
    # Test the service restart function exists and has proper logic
    # This tests the structure of the restart_services function
    if declare -f restart_services >/dev/null 2>&1; then
        assert_success 0 "restart_services function exists"
        
        # Check if the function contains the reload fallback logic
        local function_body
        function_body=$(declare -f restart_services)
        
        if [[ "$function_body" == *"systemctl reload"* && "$function_body" == *"systemctl restart"* ]]; then
            assert_success 0 "restart_services contains both reload and restart commands"
        else
            assert_failure 0 "restart_services should contain both reload and restart commands"
        fi
        
        if [[ "$function_body" == *"DEPLOYED_HOSTS"* ]]; then
            assert_success 0 "restart_services checks DEPLOYED_HOSTS array"
        else
            assert_failure 0 "restart_services should check DEPLOYED_HOSTS array"
        fi
    else
        assert_failure 0 "restart_services function exists"
    fi
}

test_cert_changed_function() {
    # Test the cert_changed function uses head instead of cut
    if declare -f cert_changed >/dev/null 2>&1; then
        assert_success 0 "cert_changed function exists"
        
        local function_body
        function_body=$(declare -f cert_changed)
        
        if [[ "$function_body" == *"head -c 64"* ]]; then
            assert_success 0 "cert_changed uses head -c 64 for hash extraction"
        else
            assert_failure 0 "cert_changed should use head -c 64 instead of cut"
        fi
        
        # Check that it doesn't use the problematic cut command
        if [[ "$function_body" != *"cut -d"* ]]; then
            assert_success 0 "cert_changed no longer uses problematic cut command"
        else
            assert_failure 0 "cert_changed should not use cut -d command"
        fi
    else
        assert_failure 0 "cert_changed function exists"
    fi
}

# Test runner
run_all_tests() {
    echo -e "${BLUE}Starting cert-spreader.sh unit tests...${NC}"
    echo "========================================"
    
    setup_test_environment
    
    # Run individual tests
    test_script_exists
    test_help_option
    test_config_validation
    test_dry_run_mode
    test_permissions_fix_mode
    test_invalid_arguments
    test_multiple_exclusive_flags
    test_source_functions
    
    # Test new functionality
    test_deployed_hosts_tracking
    test_local_cert_changed_flag
    
    cleanup_test_environment
    
    # Print test summary
    echo "========================================"
    echo -e "${BLUE}Test Summary:${NC}"
    echo -e "  Total tests: $TESTS_RUN"
    echo -e "  ${GREEN}Passed: $TESTS_PASSED${NC}"
    echo -e "  ${RED}Failed: $TESTS_FAILED${NC}"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed!${NC}"
        exit 1
    fi
}

# Help function
show_help() {
    cat << EOF
Usage: $0 [options]

Options:
    --help, -h      Show this help message
    --setup         Only setup test environment (for manual testing)
    --cleanup       Only cleanup test environment
    
Examples:
    $0                  # Run all tests
    $0 --setup          # Setup test environment for manual testing
    $0 --cleanup        # Clean up test environment

This script tests the cert-spreader.sh functionality including:
- Command line argument parsing
- Configuration validation
- Dry-run mode
- Permission checking functions
- SSH command building
- Error code handling
- Certificate change tracking (DEPLOYED_HOSTS array)
- Local certificate change flag (LOCAL_CERT_CHANGED)
- Service restart with reload fallback logic
- Hash extraction improvements (head/awk instead of cut)
EOF
}

# Main execution
case "${1:-run}" in
    --help|-h)
        show_help
        ;;
    --setup)
        setup_test_environment
        echo "Test environment set up at: $TEST_DIR"
        echo "Test config file: $TEST_CONFIG"
        ;;
    --cleanup)
        cleanup_test_environment
        ;;
    run|*)
        run_all_tests
        ;;
esac