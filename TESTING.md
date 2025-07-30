# Certificate Spreader Testing Guide

This document describes the testing framework for the cert-spreader.sh script.

## Overview

The testing framework (`test-cert-spreader.sh`) provides comprehensive unit tests for the certificate spreader functionality including:

- Command line argument parsing
- Configuration validation  
- Dry-run mode execution
- Permission checking functions
- SSH command building
- Error code handling

## Running Tests

### Run All Tests
```bash
./test-cert-spreader.sh
```

### Setup Test Environment Only
```bash
./test-cert-spreader.sh --setup
```
This creates a test environment at `/tmp/cert-spreader-tests/` with:
- Test certificate files
- Test configuration file
- Proper directory structure

### Cleanup Test Environment
```bash
./test-cert-spreader.sh --cleanup
```

### Help
```bash
./test-cert-spreader.sh --help
```

## Test Categories

### 1. Basic Functionality Tests
- Script existence check
- Help option functionality
- Invalid argument handling

### 2. Configuration Tests
- Missing configuration file detection
- Configuration validation
- Error code verification

### 3. Mode Tests
- Dry-run mode execution
- Permissions-fix mode
- Exclusive flag validation

### 4. Function Unit Tests
- SSH command building (`build_ssh_command`)
- Permission checking (`check_permissions`)
- Function sourcing capability

## Test Environment

The test framework creates a isolated environment:

```
/tmp/cert-spreader-tests/
├── certs/
│   ├── privkey.pem      # Fake private key
│   ├── cert.pem         # Fake certificate
│   ├── fullchain.pem    # Fake full chain
│   └── chain.pem        # Fake chain
├── test-config.conf     # Test configuration
└── test-cert-spreader.log  # Test log file
```

## Configuration Used in Tests

The test configuration includes:
```bash
DOMAIN="test.example.com"
CERT_DIR="/tmp/cert-spreader-tests/certs"
BACKUP_HOST="test-backup"
HOSTS="test-host1 test-host2"
HOST_SERVICES=(
    "test-host1:22:nginx"
    "test-host2:2222:apache2,mysql"
)
```

## Error Code Testing

The framework verifies that the script returns appropriate error codes:

- `0` (ERR_SUCCESS): Successful execution
- `1` (ERR_CONFIG): Configuration errors
- `2` (ERR_CERT): Certificate errors  
- `3` (ERR_NETWORK): Network connectivity errors
- `4` (ERR_PERMISSION): Permission errors
- `5` (ERR_VALIDATION): Validation errors
- `6` (ERR_USAGE): Usage/argument errors

## Extending Tests

To add new tests:

1. Create a new test function following the naming pattern `test_*`
2. Use assertion functions:
   - `assert_equals expected actual "test_name"`
   - `assert_success exit_code "test_name"`
   - `assert_failure exit_code "test_name"`
3. Add the test to the `run_all_tests()` function

Example:
```bash
test_new_functionality() {
    local result="some_command"
    assert_equals "expected_output" "$result" "new functionality test"
}
```

## Test Output

Tests provide colored output:
- ✅ **GREEN**: Passed tests
- ❌ **RED**: Failed tests  
- 🔵 **BLUE**: Information messages
- 🟡 **YELLOW**: Expected vs actual values

## Limitations

- Tests run in user context, not as root
- Network connectivity tests are simulated
- Some permission tests may vary based on user privileges
- Tests don't make actual network connections

## Manual Testing

After running `--setup`, you can manually test:

```bash
# Test dry-run mode
./cert-spreader.sh /tmp/cert-spreader-tests/test-config.conf --dry-run

# Test permissions-fix mode
./cert-spreader.sh /tmp/cert-spreader-tests/test-config.conf --permissions-fix --dry-run

# Test help
./cert-spreader.sh --help
```

Remember to run `--cleanup` when done with manual testing.