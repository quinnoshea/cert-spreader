# Certificate Spreader Testing Guide

This document describes the testing frameworks for both the Bash (cert-spreader.sh) and Python (cert-spreader.py) implementations.

## Overview

We provide two comprehensive testing frameworks:

### 1. Bash Testing Framework (`test-cert-spreader.sh`)
Tests the Bash implementation with comprehensive coverage including:
- Command line argument parsing
- Configuration validation  
- Dry-run mode execution
- Permission checking functions
- SSH command building
- Error code handling

### 2. Python Testing Framework (`test-cert-spreader.py`)  
Tests the Python implementation using unittest framework with coverage including:
- Config dataclass functionality
- CertSpreader class methods
- Configuration file parsing
- New owner/group functionality
- Command line argument parsing
- Error handling and exit codes
- Dry-run mode testing
- Integration tests

## Running Tests

### Run All Tests

**Bash Version:**
```bash
./test-cert-spreader.sh
```

**Python Version:**
```bash
./test-cert-spreader.py
# OR
python3 test-cert-spreader.py
```

**Run Both Test Suites:**
```bash
# Quick way to run both
./test-cert-spreader.sh && ./test-cert-spreader.py
```

### Test Environment Management

**Bash Test Environment:**
```bash
# Setup test environment  
./test-cert-spreader.sh --setup

# Cleanup test environment
./test-cert-spreader.sh --cleanup

# Help
./test-cert-spreader.sh --help
```

**Python Test Environment:**
The Python tests use temporary directories that are automatically created and cleaned up. No manual setup required.

### Verbose Output

**Python Tests with Verbose Output:**
```bash
./test-cert-spreader.py -v
# OR
python3 -m unittest test-cert-spreader.py -v
```

**Run Specific Python Test Class:**
```bash
python3 -m unittest test-cert-spreader.TestConfig -v
python3 -m unittest test-cert-spreader.TestOwnerGroupFunctionality -v
```

## Test Categories

### Bash Test Categories (`test-cert-spreader.sh`)

#### 1. Basic Functionality Tests
- Script existence check
- Help option functionality
- Invalid argument handling

#### 2. Configuration Tests
- Missing configuration file detection
- Configuration validation
- Error code verification

#### 3. Mode Tests
- Dry-run mode execution
- Permissions-fix mode
- Exclusive flag validation

#### 4. Function Unit Tests
- SSH command building (`build_ssh_command`)
- Permission checking (`check_permissions`)
- Function sourcing capability

### Python Test Categories (`test-cert-spreader.py`)

#### 1. Config Dataclass Tests (`TestConfig`)
- Default value validation
- Configuration modification
- Data structure integrity

#### 2. Initialization Tests (`TestCertSpreaderInit`)
- Default initialization
- Custom configuration paths
- Instance attribute validation

#### 3. Configuration Loading Tests (`TestConfigurationLoading`)
- Missing config file handling
- Basic configuration parsing
- Missing required variables validation
- Bash script configuration integration

#### 4. Utility Method Tests (`TestUtilityMethods`)
- Domain validation
- Certificate hash calculation
- SSH command building

#### 5. Owner/Group Functionality Tests (`TestOwnerGroupFunctionality`)
- UID/GID lookup with valid users/groups
- Fallback behavior for invalid users/groups  
- Permission securing with ownership changes

#### 6. Command Line Tests (`TestCommandLineArguments`)
- Help argument handling
- Invalid argument detection
- Exclusive flag validation

#### 7. Dry-Run Tests (`TestDryRunMode`)
- Dry-run mode execution
- No-modification verification

#### 8. Integration Tests (`TestIntegration`)
- Script executability
- End-to-end functionality

## Test Environments

### Bash Test Environment (`test-cert-spreader.sh`)

The Bash test framework creates an isolated environment:

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

### Python Test Environment (`test-cert-spreader.py`)

The Python test framework uses Python's `tempfile` module to create temporary environments:

- **Automatic Setup/Cleanup**: Each test class automatically creates and destroys temporary directories
- **Isolated Tests**: Each test gets its own temporary directory to avoid interference
- **Mock Objects**: Uses `unittest.mock` to simulate external dependencies (SSH, system calls, etc.)
- **No Manual Cleanup**: Temporary files are automatically cleaned up after tests complete

## Configuration Used in Tests

### Bash Test Configuration
```bash
DOMAIN="test.example.com"
CERT_DIR="/tmp/cert-spreader-tests/certs"
HOSTS="test-host1 test-host2"
HOST_SERVICES=(
    "test-host1:22:nginx"
    "test-host2:2222:apache2,mysql"
)
PROXMOX_USER="test@pve!testtoken"
PROXMOX_TOKEN="fake-token"
PROXMOX_NODES=("test-proxmox1" "test-proxmox2")
```

### Python Test Configuration
```bash
DOMAIN="test.example.com"
CERT_DIR="/tmp/test-cert-dir"
HOSTS="host1 host2 host3"
HOST_SERVICES=(
    "host1:22:nginx"
    "host2:2222:apache2,mysql"
)
PROXMOX_USER="test@pve!token"
PROXMOX_TOKEN="fake-token"
PROXMOX_NODES=("proxmox1" "proxmox2")
PLEX_CERT_ENABLED=true
PLEX_CERT_PASSWORD="testpass"
ZNC_CERT_ENABLED=true
FILE_OWNER=nginx
FILE_GROUP=ssl-cert
```

## Error Code Testing

Both test frameworks verify that the scripts return appropriate error codes:

- `0` (ERR_SUCCESS): Successful execution
- `1` (ERR_CONFIG): Configuration errors
- `2` (ERR_CERT): Certificate errors  
- `3` (ERR_NETWORK): Network connectivity errors
- `4` (ERR_PERMISSION): Permission errors
- `5` (ERR_VALIDATION): Validation errors
- `6` (ERR_USAGE): Usage/argument errors

### Python Error Code Testing
The Python tests use `ExitCodes` class constants and verify them with:
```python
self.assertEqual(cm.exception.code, ExitCodes.CONFIG)
self.assertEqual(cm.exception.code, ExitCodes.USAGE)
```

### Bash Error Code Testing
The Bash tests verify exit codes with assertion functions:
```bash
assert_equals "1" "$exit_code" "config error test"
assert_equals "6" "$exit_code" "usage error test"
```

## Extending Tests

### Adding Bash Tests

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

### Adding Python Tests

1. Create a new test class inheriting from `unittest.TestCase`
2. Use unittest assertion methods:
   - `self.assertEqual(expected, actual)`
   - `self.assertTrue(condition)`
   - `self.assertRaises(Exception)`
3. Follow naming convention: `test_*` for test methods

Example:
```python
class TestNewFeature(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_new_functionality(self):
        """Test new functionality"""
        result = some_function()
        self.assertEqual(expected_result, result)
```

## Test Output

### Bash Test Output
Tests provide colored output:
- ✅ **GREEN**: Passed tests
- ❌ **RED**: Failed tests  
- 🔵 **BLUE**: Information messages
- 🟡 **YELLOW**: Expected vs actual values

Example output:
```
✓ PASS: cert-spreader.sh script exists
✓ PASS: help option displays usage
✗ FAIL: configuration validation test
  Expected: 1
  Actual:   0
```

### Python Test Output
Standard unittest output with optional verbosity:

**Normal Output:**
```
......F.
======================================================================
FAIL: test_missing_config_file (test-cert-spreader.TestConfigurationLoading)
----------------------------------------------------------------------
AssertionError: SystemExit not raised

----------------------------------------------------------------------
Ran 8 tests in 0.123s

FAILED (failures=1)
```

**Verbose Output (`-v` flag):**
```
test_config_defaults (test-cert-spreader.TestConfig) ... ok
test_config_modification (test-cert-spreader.TestConfig) ... ok
test_missing_config_file (test-cert-spreader.TestConfigurationLoading) ... FAIL
test_basic_config_loading (test-cert-spreader.TestConfigurationLoading) ... ok

======================================================================
FAIL: test_missing_config_file (test-cert-spreader.TestConfigurationLoading)
----------------------------------------------------------------------
AssertionError: SystemExit not raised
```

## Limitations

### Bash Test Limitations
- Tests run in user context, not as root
- Network connectivity tests are simulated
- Some permission tests may vary based on user privileges
- Tests don't make actual network connections

### Python Test Limitations  
- Most external dependencies are mocked (SSH, system calls, etc.)
- File system operations use temporary directories
- Network operations are not tested (mocked)
- Some tests require specific users/groups to exist for ownership testing

### Common Limitations
- No actual certificate deployment to remote hosts
- No real service restarts
- No actual Proxmox API calls
- Permission changes are tested but may require root for full functionality

## Manual Testing

### Bash Manual Testing
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

### Python Manual Testing
Create a test configuration file and test manually:

```bash
# Create test config
cp config.example.conf test-manual.conf
# Edit test-manual.conf with test values

# Test dry-run mode
./cert-spreader.py test-manual.conf --dry-run

# Test permissions-fix mode  
./cert-spreader.py test-manual.conf --permissions-fix --dry-run

# Test help
./cert-spreader.py --help
```

## Continuous Integration

Both test suites can be run in CI/CD pipelines:

```bash
#!/bin/bash
# CI test script
set -e

echo "Running Bash tests..."
./test-cert-spreader.sh

echo "Running Python tests..."
./test-cert-spreader.py

echo "All tests passed!"
```

## New Feature Testing

When adding new features, ensure you test in both implementations:

1. **Add Bash tests** to `test-cert-spreader.sh`
2. **Add Python tests** to `test-cert-spreader.py`  
3. **Test the new owner/group functionality** with different user configurations
4. **Update this documentation** with any new test categories
5. **Verify both implementations behave identically**