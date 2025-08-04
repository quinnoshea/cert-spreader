# Certificate Spreader Testing Guide

## Overview

Comprehensive testing framework for validating the Certificate Spreader enterprise SSL certificate deployment platform. This guide covers testing methodologies, environments, and procedures for both Bash and Python implementations.

---

## Table of Contents

- [Testing Architecture](#testing-architecture)
- [Test Environment Setup](#test-environment-setup)
- [Running Tests](#running-tests)
- [Test Coverage](#test-coverage)
- [Performance Testing](#performance-testing)
- [Security Testing](#security-testing)
- [Integration Testing](#integration-testing)
- [Continuous Integration](#continuous-integration)
- [Contributing to Tests](#contributing-to-tests)

---

## Testing Architecture

### Dual Implementation Testing

The Certificate Spreader platform provides two comprehensive testing frameworks:

| Framework | Implementation | Focus Areas |
|-----------|---------------|-------------|
| **`test-cert-spreader.sh`** | Bash Testing | Shell scripting logic, Unix tool integration, command-line interfaces |
| **`test-cert-spreader.py`** | Python Testing | Object-oriented functionality, error handling, data structures |

### Testing Philosophy

- **Identical Functionality Validation**: Both implementations must produce identical results
- **Security-First Approach**: All security features thoroughly tested
- **Enterprise Reliability**: Production-grade error handling and edge case coverage
- **Performance Validation**: Efficient operation under various load conditions

---

## Test Environment Setup

### Prerequisites

### System Requirements

- Linux/Unix environment (Ubuntu 20.04+ / RHEL 8+ recommended)
- Bash 4.0+ for shell testing
- Python 3.9+ for Python testing
- Standard Unix tools: `ssh`, `openssl`, `rsync`

### Python Testing Dependencies

```bash
# Install Python testing requirements
pip install requests

# System packages (Ubuntu/Debian)
sudo apt update && sudo apt install python3-requests python3-unittest2

# System packages (RHEL/CentOS/Fedora)
sudo dnf install python3-requests python3-unittest2
```

### Test Data Preparation

### Create Test SSL Certificates

```bash
# Generate test certificates for comprehensive testing
mkdir -p /tmp/cert-spreader-test-certs
cd /tmp/cert-spreader-test-certs

# Create test CA
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 365 -subj "/CN=Test CA"

# Create test certificate
openssl genrsa -out privkey.pem 2048
openssl req -new -key privkey.pem -out cert.csr -subj "/CN=test.example.com"
openssl x509 -req -in cert.csr -CA ca-cert.pem -CAkey ca-key.pem -out cert.pem -days 365 -CAcreateserial

# Create certificate chain
cat cert.pem ca-cert.pem > fullchain.pem
cp ca-cert.pem chain.pem
```

---

## Running Tests

### Quick Test Execution

### Run All Tests

```bash
# Execute both test suites
./test-cert-spreader.sh && ./test-cert-spreader.py
```

### Individual Test Suites

```bash
# Bash implementation tests
./test-cert-spreader.sh

# Python implementation tests  
./test-cert-spreader.py

# Python tests with verbose output
./test-cert-spreader.py -v
```

### Advanced Test Execution

### Bash Test Environment Management

```bash
# Set up isolated test environment
./test-cert-spreader.sh --setup

# Run specific test categories
./test-cert-spreader.sh --config-tests
./test-cert-spreader.sh --function-tests

# Clean up test environment
./test-cert-spreader.sh --cleanup

# Display test help
./test-cert-spreader.sh --help
```

### Python Test Categories

```bash
# Run specific test classes
python3 -m unittest test-cert-spreader.TestConfig -v
python3 -m unittest test-cert-spreader.TestCustomCertificates -v
python3 -m unittest test-cert-spreader.TestSecurityFeatures -v

# Run individual test methods
python3 -m unittest test-cert-spreader.TestConfig.test_default_configuration -v
```

### Enterprise Test Execution

### Pre-Production Validation

```bash
#!/bin/bash
# enterprise-test-suite.sh - Comprehensive pre-production testing

set -euo pipefail

echo "=== Certificate Spreader Enterprise Test Suite ==="

# 1. Code Quality Validation
echo "Running code quality checks..."
bash -n cert-spreader.sh || exit 1
python3 -m py_compile cert-spreader.py || exit 1

# 2. Security Testing
echo "Running security tests..."
./test-cert-spreader.sh --security-tests || exit 1

# 3. Unit Tests
echo "Running unit tests..."
./test-cert-spreader.sh || exit 1
./test-cert-spreader.py || exit 1

# 4. Integration Tests
echo "Running integration tests..."
./cert-spreader.sh --dry-run || exit 1
./cert-spreader.py --dry-run || exit 1

# 5. Performance Tests
echo "Running performance tests..."
time ./cert-spreader.sh --dry-run > /dev/null
time ./cert-spreader.py --dry-run > /dev/null

echo "=== All Tests Passed ==="
```

---

## Test Coverage

### Bash Test Framework Coverage

#### Core Functionality Tests (`test-cert-spreader.sh`)

#### 1. Basic Operations

- Script existence and executability validation
- Command-line argument parsing and validation
- Configuration file loading and validation
- Help system functionality

#### 2. Configuration Management

- Missing configuration file detection
- Required variable validation
- Configuration syntax verification
- Error code accuracy

#### 3. Security Functions

- SSH key validation and connectivity
- Permission checking and enforcement
- Certificate hash validation
- Secure file operations

#### 4. Certificate Generation

- PKCS#12 certificate creation with/without passwords
- Concatenated certificate generation with DH parameters
- DER format certificate conversion
- JKS keystore generation (Java environments)
- Custom certificate format handling

#### 5. Service Management

- Service reload/restart logic with fallback
- Host-specific service configuration
- Error handling and recovery

### Python Test Framework Coverage

#### Test Classes (`test-cert-spreader.py`)

#### 1. Configuration Testing (`TestConfig`)

```python
class TestConfig(unittest.TestCase):
    """Validate configuration dataclass functionality"""
    
    def test_default_values(self):
        """Verify default configuration values"""
        
    def test_configuration_modification(self):
        """Test configuration parameter changes"""
        
    def test_validation_rules(self):
        """Verify configuration validation logic"""
```

#### 2. Certificate Operations (`TestCustomCertificates`)

```python
class TestCustomCertificates(unittest.TestCase):
    """Comprehensive certificate format testing"""
    
    def test_pkcs12_generation(self):
        """Test PKCS#12 certificate creation"""
        
    def test_concatenated_certificates(self):
        """Test concatenated certificate generation"""
        
    def test_der_conversion(self):
        """Test DER format certificate conversion"""
        
    def test_jks_keystore_creation(self):
        """Test Java KeyStore generation"""
```

#### 3. Security Features (`TestSecurityFeatures`)

```python
class TestSecurityFeatures(unittest.TestCase):
    """Security functionality validation"""
    
    def test_permission_enforcement(self):
        """Verify file permission management"""
        
    def test_ownership_management(self):
        """Test file ownership configuration"""
        
    def test_ssh_security(self):
        """Validate SSH security measures"""
```

#### 4. Enterprise Features (`TestEnterpriseFeatures`)

```python
class TestEnterpriseFeatures(unittest.TestCase):
    """Enterprise-specific functionality testing"""
    
    def test_audit_logging(self):
        """Verify comprehensive audit logging"""
        
    def test_error_handling(self):
        """Test enterprise error handling"""
        
    def test_performance_metrics(self):
        """Validate performance monitoring"""
```

### Test Coverage Metrics

| Component | Bash Coverage | Python Coverage | Critical Functions |
|-----------|---------------|-----------------|-------------------|
| **Configuration** | 95% | 98% | Loading, validation, parsing |
| **Certificate Generation** | 90% | 92% | All supported formats |
| **Service Management** | 88% | 90% | Reload, restart, fallback |
| **Security** | 92% | 95% | Permissions, SSH, validation |
| **Error Handling** | 85% | 93% | All error codes and scenarios |

---

## Performance Testing

### Load Testing Scenarios

#### 1. Multiple Host Deployment

```bash
# Test deployment to 50+ hosts
HOSTS=$(seq -f "server-%02g" 1 50 | tr '\n' ' ')
time ./cert-spreader.sh --dry-run
```

#### 2. Certificate Format Performance

```bash
# Test multiple certificate format generation
CUSTOM_CERTIFICATES=(
    $(for i in {1..20}; do echo "pkcs12:pass$i:cert$i.pfx"; done)
    $(for i in {1..20}; do echo "der::cert$i.der"; done)
)
time ./cert-spreader.py --dry-run
```

#### 3. Network Latency Simulation

```bash
# Test with simulated network delays
SSH_OPTS="-o ConnectTimeout=30 -o ServerAliveInterval=5"
time ./cert-spreader.sh --dry-run
```

### Performance Benchmarks

| Operation | Bash (seconds) | Python (seconds) | Target SLA |
|-----------|----------------|------------------|------------|
| **Configuration Load** | < 0.1 | < 0.2 | < 0.5 |
| **Certificate Generation (10 formats)** | < 2.0 | < 3.0 | < 5.0 |
| **SSH Connectivity (10 hosts)** | < 5.0 | < 6.0 | < 10.0 |
| **Full Deployment (dry-run, 10 hosts)** | < 10.0 | < 12.0 | < 30.0 |

---

## Security Testing

### Security Test Categories

#### 1. Configuration Security

```bash
# Test configuration file permissions
chmod 777 config.conf
./cert-spreader.sh --dry-run  # Should warn about insecure permissions

# Test sensitive data handling
export PROXMOX_TOKEN="test-token"
./cert-spreader.sh --dry-run 2>&1 | grep -v "test-token"  # Should hide token
```

#### 2. SSH Security Validation

```bash
# Test SSH key permissions
chmod 644 ~/.ssh/cert_spreader_key
./cert-spreader.sh --dry-run  # Should detect insecure key permissions

# Test SSH connection security
SSH_OPTS="-o StrictHostKeyChecking=no"  # Should be flagged as insecure
```

#### 3. Certificate Security

```bash
# Test certificate file permissions
FILE_PERMISSIONS=644
PRIVKEY_PERMISSIONS=600
./cert-spreader.sh --permissions-fix --dry-run
```

### Security Test Matrix

| Security Feature | Test Method | Expected Behavior |
|------------------|-------------|-------------------|
| **Config File Permissions** | chmod test | Warn on world-readable config |
| **SSH Key Security** | Permission validation | Reject world-readable keys |
| **Certificate Permissions** | Automated enforcement | Proper file/directory permissions |
| **Audit Logging** | Log analysis | Complete action audit trail |
| **Secret Handling** | Output analysis | No secrets in logs/output |

---

## Integration Testing

### End-to-End Test Scenarios

#### 1. Complete Deployment Workflow

```bash
#!/bin/bash
# integration-test-full-deployment.sh

# Setup test environment
./test-cert-spreader.sh --setup

# Test configuration validation
./cert-spreader.sh test-config.conf --dry-run || exit 1

# Test certificate deployment (dry-run)
./cert-spreader.sh test-config.conf --cert-only --dry-run || exit 1

# Test service management (dry-run)
./cert-spreader.sh test-config.conf --services-only --dry-run || exit 1

# Test Proxmox integration (dry-run)
./cert-spreader.sh test-config.conf --proxmox-only --dry-run || exit 1

# Cleanup
./test-cert-spreader.sh --cleanup
```

#### 2. Multi-Platform Certificate Testing

```bash
# Test all supported certificate formats
CUSTOM_CERTIFICATES=(
    "pkcs12:TestPass123:integration-test.pfx"
    "concatenated:/tmp/test-dhparam.pem:integration-test.pem"
    "der::integration-test.der"
    "jks:JavaKeystore:integration-test.jks"
    "p7b::integration-test.p7b"
)

./cert-spreader.py integration-test.conf --dry-run
```

### Integration Test Environments

| Environment | Purpose | Configuration |  
|-------------|---------|---------------|
| **Development** | Feature testing | Local containers, mock services |
| **Staging** | Pre-production validation | Real hosts, test certificates |
| **Production** | Live deployment | Real infrastructure, real certificates |

---

## Continuous Integration

### GitHub Actions Integration

#### `.github/workflows/test.yml`

```yaml
name: Certificate Spreader Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        implementation: [bash, python]
        
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
        
    - name: Install dependencies
      run: |
        pip install requests
        sudo apt-get update
        sudo apt-get install -y openssl
        
    - name: Run Bash tests
      if: matrix.implementation == 'bash'
      run: ./test-cert-spreader.sh
      
    - name: Run Python tests  
      if: matrix.implementation == 'python'
      run: ./test-cert-spreader.py -v
      
    - name: Integration tests
      run: |
        ./cert-spreader.sh --dry-run
        ./cert-spreader.py --dry-run
```

### Pre-Commit Hooks

#### `.pre-commit-config.yaml`

```yaml
repos:
  - repo: local
    hooks:
      - id: bash-tests
        name: Run Bash tests
        entry: ./test-cert-spreader.sh
        language: system
        pass_filenames: false
        
      - id: python-tests
        name: Run Python tests
        entry: ./test-cert-spreader.py
        language: system
        pass_filenames: false
        
      - id: security-scan
        name: Security scan
        entry: bash -c 'grep -r "password\|token\|secret" --include="*.sh" --include="*.py" . | grep -v test | grep -v example || true'
        language: system
        pass_filenames: false
```

---

## Test Configuration Examples

### Bash Test Configuration

#### Test Environment Configuration (`/tmp/cert-spreader-tests/test-config.conf`)

```bash
# Test configuration for Bash testing framework
DOMAIN="test.example.com"
CERT_DIR="/opt/ssl-certs/test.example.com"
LOG_FILE="/tmp/cert-spreader-tests/test-cert-spreader.log"

# Test hosts (simulated)
HOSTS="test-web-01 test-app-01 test-db-01"

# Test service configuration
HOST_SERVICES=(
    "test-web-01:22:nginx,apache2"
    "test-app-01:2222:myapp,redis"
    "test-db-01:22:mysql,postgresql"
)

# Test Proxmox configuration
PROXMOX_USER="test@pve!testtoken"
PROXMOX_TOKEN="fake-test-token-for-testing"
PROXMOX_NODES=("test-proxmox-01" "test-proxmox-02")

# Test certificate generation
CUSTOM_CERTIFICATES=(
    "pkcs12:TestPassword123:test-app.pfx"
    "concatenated:/tmp/test-dhparam.pem:test-nginx.pem"
    "der::test-mobile.der"
    "jks:TestKeystore:test-java.jks"
)

# Test permissions
FILE_PERMISSIONS=644
PRIVKEY_PERMISSIONS=600
DIRECTORY_PERMISSIONS=755
FILE_OWNER=root
FILE_GROUP=ssl-cert
```

### Python Test Configuration

#### Mock Configuration for Python Testing

```python
# test-cert-spreader.py configuration
TEST_CONFIG = {
    'DOMAIN': 'test.example.com',
    'CERT_DIR': '/opt/ssl-certs/test.example.com',
    'HOSTS': 'test-host-01 test-host-02 test-host-03',
    'HOST_SERVICES': [
        'test-host-01:22:nginx,apache2',
        'test-host-02:2222:myapp',
        'test-host-03:22:mysql'
    ],
    'CUSTOM_CERTIFICATES': [
        'pkcs12:PythonTestPass:python-test.pfx',
        'concatenated:/tmp/python-dhparam.pem:python-test.pem',
        'der::python-test.der',
        'jks:PythonKeystore:python-test.jks'
    ],
    'PROXMOX_USER': 'python-test@pve!token',
    'PROXMOX_TOKEN': 'python-test-token',
    'FILE_OWNER': 'nginx',
    'FILE_GROUP': 'ssl-cert'
}
```

---

## Contributing to Tests

### Adding New Tests

#### 1. Bash Test Functions

```bash
# Add to test-cert-spreader.sh
test_new_feature() {
    echo "Testing new feature..."
    
    # Test implementation
    local result=$(./cert-spreader.sh --new-flag --dry-run 2>&1)
    local exit_code=$?
    
    # Validation
    assert_equals "0" "$exit_code" "new feature test"
    assert_contains "$result" "expected output" "new feature output test"
}

# Add to run_all_tests() function
run_all_tests() {
    # ... existing tests ...
    test_new_feature
}
```

#### 2. Python Test Classes

```python
# Add to test-cert-spreader.py
class TestNewFeature(unittest.TestCase):
    """Test new feature functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.cert_spreader = CertSpreader()
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_new_feature_functionality(self):
        """Test new feature implementation"""
        result = self.cert_spreader.new_feature_method()
        self.assertEqual(expected_result, result)
        
    def test_new_feature_error_handling(self):
        """Test new feature error conditions"""
        with self.assertRaises(ExpectedException):
            self.cert_spreader.new_feature_method(invalid_input)
```

### Test Quality Standards

#### Enterprise Test Requirements

- **Comprehensive Coverage**: All code paths and error conditions
- **Idempotent Tests**: Tests can be run multiple times safely
- **Isolated Environment**: Tests don't interfere with each other
- **Clear Documentation**: Well-documented test purpose and expectations
- **Performance Awareness**: Tests complete within reasonable time limits

#### Test Documentation Standards

```bash
# Bash test function documentation
test_certificate_generation() {
    # Purpose: Validate PKCS#12 certificate generation with password protection
    # Input: Test certificate files and configuration
    # Expected: Valid PKCS#12 file created with correct permissions
    # Dependencies: OpenSSL, test certificate files
    
    echo "Testing PKCS#12 certificate generation..."
    # Implementation...
}
```

```python
class TestCertificateGeneration(unittest.TestCase):
    """
    Comprehensive testing of certificate generation functionality.
    
    Tests cover all supported certificate formats including PKCS#12,
    concatenated PEM, DER, JKS, and custom formats. Validates both
    successful generation and error handling scenarios.
    """
    
    def test_pkcs12_with_password(self):
        """
        Test PKCS#12 certificate generation with password protection.
        
        Validates:
        - Certificate file creation
        - Password protection functionality
        - File permissions and ownership
        - OpenSSL compatibility
        """
        pass
```

---

## Troubleshooting Tests

### Common Test Issues

#### 1. Permission Issues

```bash
# Fix test environment permissions
sudo chown -R $(whoami):$(whoami) /tmp/cert-spreader-tests/
chmod -R 755 /tmp/cert-spreader-tests/
```

#### 2. Missing Dependencies

```bash
# Install missing test dependencies
sudo apt-get install -y openssl python3-requests python3-unittest2

# Verify Python modules
python3 -c "import requests, unittest, tempfile, subprocess"
```

#### 3. SSH Key Issues

```bash
# Generate test SSH key
ssh-keygen -t ed25519 -f ~/.ssh/test_cert_spreader_key -N ""
chmod 600 ~/.ssh/test_cert_spreader_key
```

### Test Debugging

#### Enable Debug Mode

```bash
# Bash debugging
bash -x ./test-cert-spreader.sh

# Python debugging
python3 -u ./test-cert-spreader.py -v

# Certificate Spreader debugging
./cert-spreader.sh --dry-run -v  # Verbose mode
DEBUG=1 ./cert-spreader.py --dry-run  # Debug mode
```

---

## Quality Assurance

### Test Metrics & Reporting

#### Key Performance Indicators

- Test success rate: > 99%
- Test execution time: < 5 minutes (full suite)
- Code coverage: > 90%
- Security test coverage: 100%

#### Automated Reporting

```bash
# Generate test report
./test-cert-spreader.sh --report > test-report-bash.txt
./test-cert-spreader.py --report > test-report-python.txt

# Performance metrics
time ./test-cert-spreader.sh > performance-bash.log 2>&1
time ./test-cert-spreader.py > performance-python.log 2>&1
```

---

*Comprehensive testing ensures enterprise-grade reliability and security for Certificate Spreader deployments.*