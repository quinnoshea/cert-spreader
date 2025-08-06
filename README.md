# Certificate Spreader

[![License](https://img.shields.io/badge/license-Apache%202.0-9B59B6.svg)](LICENSE)
![Bash](https://img.shields.io/badge/bash-4.0%2B-2ECC71)
![Python](https://img.shields.io/badge/python-3.9%2B-3498DB)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/2b2bed5783c842dc89ab5c56adcb2896)](https://app.codacy.com?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/2b2bed5783c842dc89ab5c56adcb2896)](https://app.codacy.com?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_coverage)
![Status](https://img.shields.io/badge/status-active-success)
[![CI](https://github.com/quinnoshea/cert-spreader/actions/workflows/ci-workflow.yml/badge.svg)](https://github.com/quinnoshea/cert-spreader/actions/workflows/ci-workflow.yml)

## Overview

A practical SSL certificate deployment tool for automating the secure distribution of certificates across multiple hosts. Supports multiple certificate formats, service management, and comprehensive logging.

### Key Capabilities

- **Multi-format certificate generation**: PKCS#12, PEM, DER, JKS, and custom formats
- **Intelligent service management**: Automatic reload/restart with fallback handling  
- **Security-focused**: Configurable permissions, SSH key authentication, audit logging
- **Dual implementation**: Identical functionality in both Bash and Python
- **Reliable operations**: Idempotent operations, comprehensive error handling, dry-run validation

---

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Security](#security)
- [Certificate Formats](#certificate-formats)
- [Monitoring & Troubleshooting](#monitoring--troubleshooting)
- [Testing](#testing)
- [Contributing](#contributing)

---

## Quick Start

### Prerequisites

### System Requirements

- Linux/Unix environment with SSH access to target hosts
- Bash 4.0+ or Python 3.9+
- Valid SSL certificates (Let's Encrypt recommended)
- Standard tools: `rsync`, `ssh`, `openssl`

### For Python Implementation

```bash
pip install requests
```

### 5-Minute Setup

```bash
# 1. Clone and configure
git clone <repository-url>
cd cert-spreader
cp config.example.conf config.conf

# 2. Edit configuration (see Configuration section)
nano config.conf

# 3. Set up SSH keys
ssh-keygen -t ed25519 -f ~/.ssh/cert_spreader_key
ssh-copy-id -i ~/.ssh/cert_spreader_key user@target-host

# 4. Validate configuration
./cert-spreader.sh --dry-run  # or ./cert-spreader.py --dry-run

# 5. Deploy certificates
./cert-spreader.sh            # or ./cert-spreader.py
```

---

## Installation

### System Deployment

```bash
# Create dedicated system user (recommended)
sudo useradd -r -s /bin/bash -d /opt/cert-spreader cert-spreader

# Install to system location
sudo mkdir -p /opt/cert-spreader
sudo cp cert-spreader.{sh,py} config.example.conf /opt/cert-spreader/
sudo chown -R cert-spreader:cert-spreader /opt/cert-spreader
sudo chmod +x /opt/cert-spreader/cert-spreader.{sh,py}

# Configure logging
sudo mkdir -p /var/log/cert-spreader
sudo chown cert-spreader:cert-spreader /var/log/cert-spreader
```

### Dependencies

#### Bash Version (`cert-spreader.sh`)

- No additional dependencies required
- Uses standard Unix tools: `rsync`, `ssh`, `openssl`, `curl`, `sha256sum`

#### Python Version (`cert-spreader.py`)

```bash
# Required Python packages
pip install requests

# System packages (Ubuntu/Debian)
sudo apt update && sudo apt install python3-requests

# System packages (RHEL/CentOS/Fedora)  
sudo dnf install python3-requests
```

### Integration with Certificate Authorities

### Let's Encrypt Integration

```bash
# Add post-renewal hook
# Add to Let's Encrypt renewal configuration if using certbot
echo 'post_hook = /opt/cert-spreader/cert-spreader.sh' >> /etc/letsencrypt/renewal/yourdomain.com.conf

# Or run manually after renewal
certbot renew && /opt/cert-spreader/cert-spreader.sh
```

---

## Configuration

### Core Configuration

Edit `config.conf` with your environment details:

```bash
# Basic settings
DOMAIN="yourdomain.com"
CERT_DIR="/opt/ssl-certs/yourdomain.com"
LOG_FILE="/var/log/cert-spreader/cert-spreader.log"

# SSH configuration
SSH_OPTS="-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"

# Target hosts
HOSTS="web-01 web-02 app-01 db-01"

# Service configuration per host
HOST_SERVICES=(
    "web-01:22:nginx,apache2"
    "web-02:22:nginx"
    "app-01:2222:myapp,redis"
    "db-01:22:mysql"
)
```

### Advanced Configuration

### Multi-Format Certificate Generation

```bash
CUSTOM_CERTIFICATES=(
    # Windows/IIS certificates
    "pkcs12:SecurePassword123:windows-iis.pfx"
    
    # Web server certificates with DH parameters
    "concatenated:/etc/ssl/dhparam.pem:nginx-combined.pem"
    
    # Java application certificates
    "jks:KeystorePassword:tomcat-app.jks"
    
    # Mobile/embedded certificates
    "der::mobile-app.der"
)
```

### Security Configuration

```bash
# File permissions and ownership
FILE_PERMISSIONS=644              # Certificate files
PRIVKEY_PERMISSIONS=600           # Private keys (more restrictive)
DIRECTORY_PERMISSIONS=755         # Directories
FILE_OWNER=root                   # File owner
FILE_GROUP=ssl-cert              # File group
```

### Local Service Configuration

```bash
# Configure local service management (replaces hardcoded nginx)
LOCAL_SERVICE="nginx"             # Service to reload/restart (empty = skip)
LOCAL_SERVICE_MANAGER="systemctl" # Service manager (systemctl, service, rc-service, etc.)

# Examples for different service managers:
# LOCAL_SERVICE="apache2" LOCAL_SERVICE_MANAGER="systemctl"    # Ubuntu/Debian systemd
# LOCAL_SERVICE="httpd" LOCAL_SERVICE_MANAGER="service"       # RHEL/CentOS SysV init  
# LOCAL_SERVICE="nginx" LOCAL_SERVICE_MANAGER="rc-service"    # Alpine/OpenRC
# LOCAL_SERVICE=""                                            # Disable local service management
```

### Proxmox Integration

```bash
PROXMOX_USER="automation@pve!cert-deployer"
PROXMOX_TOKEN="your-api-token-here"
PROXMOX_NODES=("proxmox-01" "proxmox-02")
```

### Configuration Validation

```bash
# Validate configuration before deployment
./cert-spreader.sh --dry-run
./cert-spreader.py --dry-run

# Test SSH connectivity
ssh -i ~/.ssh/cert_spreader_key user@target-host 'echo "Connection OK"'
```

---

## Usage

### Command-Line Interface

Both implementations provide identical command-line interfaces:

```bash
# Full deployment (certificates + services + Proxmox)
./cert-spreader.sh
./cert-spreader.py

# Deployment modes
./cert-spreader.sh --cert-only        # Deploy certificates only
./cert-spreader.sh --services-only    # Restart services only  
./cert-spreader.sh --proxmox-only     # Update Proxmox only
./cert-spreader.sh --permissions-fix  # Fix permissions only

# Validation and debugging
./cert-spreader.sh --dry-run          # Preview actions without changes
./cert-spreader.sh --help             # Display usage information

# Custom configuration
./cert-spreader.sh /path/to/custom.conf --dry-run
```

### Operational Workflows

### Standard Deployment Workflow

1. **Validate**: `./cert-spreader.sh --dry-run`
2. **Deploy**: `./cert-spreader.sh`
3. **Monitor**: Check logs at `/var/log/cert-spreader/cert-spreader.log`
4. **Verify**: Test services and certificate validity

### Maintenance Workflows

```bash
# Fix certificate permissions across all hosts
./cert-spreader.sh --permissions-fix

# Restart services after manual certificate updates
./cert-spreader.sh --services-only

# Update only Proxmox certificates
./cert-spreader.sh --proxmox-only
```

### Automation & Scheduling

#### Cron Integration

```bash
# Add to crontab for automated renewals
0 3 * * 1 /opt/cert-spreader/cert-spreader.sh >> /var/log/cert-spreader/cron.log 2>&1
```

#### Systemd Timer (Recommended)

```bash
# Create systemd service and timer files
sudo systemctl enable cert-spreader.timer
sudo systemctl start cert-spreader.timer
```

---

## Security

### Authentication & Authorization

### SSH Key Management

```bash
# Generate dedicated SSH keys
ssh-keygen -t ed25519 -f ~/.ssh/cert_spreader_key

# Secure key permissions
chmod 600 ~/.ssh/cert_spreader_key
chown root:root ~/.ssh/cert_spreader_key

# Deploy keys to target hosts
for host in web-01 web-02 app-01; do
    ssh-copy-id -i ~/.ssh/cert_spreader_key user@${host}.yourdomain.com
done
```

### Configuration Security

```bash
# Secure configuration files
chmod 600 config.conf
chown root:root config.conf

# Use environment variables for sensitive data
export PROXMOX_TOKEN="your-token-here"
./cert-spreader.sh
```

### Certificate Security

#### Default Security Model

- Certificate directories: `755` (drwxr-xr-x)
- Private keys: `600` (-rw-------)
- Certificate files: `644` (-rw-r--r--)
- Custom ownership and group assignment supported

#### Security Best Practices

- Never commit `config.conf` to version control
- Use dedicated service accounts for deployment
- Implement proper SSH key rotation
- Monitor certificate deployment logs
- Validate certificate chains and expiration dates

---

## Certificate Formats

### Supported Formats & Use Cases

| Format | Extension | Primary Use Cases | Platform Support |
|--------|-----------|------------------|-------------------|
| **PKCS#12** | `.pfx`, `.p12` | Windows IIS, Exchange, client certs | Windows, Cross-platform |
| **Concatenated** | `.pem` | Nginx, Apache, HAProxy, ZNC | Linux, Unix |
| **DER** | `.der`, `.crt` | Java applications, Android, embedded | Java, Mobile, IoT |
| **PKCS#7** | `.p7b`, `.p7c` | Windows cert stores, Java trust chains | Windows, Java |
| **JKS** | `.jks` | Java applications, Tomcat, Kafka | Java ecosystem |
| **PEM** | `.pem` | Custom applications, OpenSSL | Linux, Unix |
| **CRT** | `.crt` | Individual certificates, web servers | Cross-platform |

### Configuration Examples

### Web Infrastructure

```bash
CUSTOM_CERTIFICATES=(
    # Load balancer with DH parameters
    "concatenated:/etc/ssl/dhparam.pem:haproxy-frontend.pem"
    
    # Application servers
    "pkcs12:AppServerPassword:app-server.pfx"
    
    # Java middleware
    "jks:MiddlewareKeystore:tomcat-cluster.jks"
)
```

### Multi-Platform Environment

```bash
CUSTOM_CERTIFICATES=(
    # Windows infrastructure
    "pkcs12:WindowsPassword:exchange-server.pfx"
    "pkcs12:IISPassword:web-server.pfx"
    
    # Linux web services
    "concatenated:/etc/nginx/ssl/dhparam.pem:nginx-production.pem"
    "concatenated::apache-staging.pem"
    
    # Mobile applications
    "der::android-app.der"
    "der::ios-app.crt"
    
    # Java applications
    "jks:ProductionKeystore:spring-boot-app.jks"
)
```

---

## Monitoring & Troubleshooting

### Logging & Monitoring

### Log Locations

- Main log: `/var/log/cert-spreader/cert-spreader.log`
- Cron log: `/var/log/cert-spreader/cron.log`
- System log: `journalctl -u cert-spreader`

### Log Analysis

```bash
# Monitor real-time deployment
tail -f /var/log/cert-spreader/cert-spreader.log

# Check recent deployments
grep "Certificate deployment" /var/log/cert-spreader/cert-spreader.log | tail -10

# Analyze errors
grep -i error /var/log/cert-spreader/cert-spreader.log
```

### Common Issues & Solutions

### Connection Issues

```bash
# Test SSH connectivity
ssh -i ~/.ssh/cert_spreader_key user@target-host 'echo "Connection test"'

# Verify SSH agent
ssh-add -l

# Check DNS resolution
nslookup target-host.yourdomain.com
```

### Certificate Issues

```bash
# Verify certificate validity and chain
openssl x509 -in /opt/ssl-certs/domain/cert.pem -text -noout | grep -A2 Validity
openssl verify -CApath /etc/ssl/certs /opt/ssl-certs/domain/fullchain.pem

# Check certificate hash for change detection
sha256sum /opt/ssl-certs/domain/fullchain.pem | head -c 64
```

### Service Issues

```bash
# Test service reload manually
ssh target-host 'systemctl reload nginx || systemctl restart nginx'

# Check service status
ssh target-host 'systemctl status nginx'

# Verify certificate loading
ssh target-host 'openssl s_client -connect localhost:443 -servername yourdomain.com'
```

### Permission Issues

```bash
# Fix permissions manually
./cert-spreader.sh --permissions-fix --dry-run
./cert-spreader.sh --permissions-fix

# Verify ownership and permissions
ls -la /opt/ssl-certs/domain/
```

### Health Checks

### Pre-deployment Validation

```bash
# Comprehensive pre-flight check
./cert-spreader.sh --dry-run 2>&1 | tee pre-deployment-check.log

# Validate configuration syntax
bash -n cert-spreader.sh
python3 -m py_compile cert-spreader.py
```

### Post-deployment Verification

```bash
# Verify certificate deployment
for host in $(echo $HOSTS); do
    ssh ${host}.${DOMAIN} "ls -la /opt/ssl-certs/${DOMAIN}/"
done

# Test HTTPS connectivity
for host in $(echo $HOSTS); do
    curl -I https://${host}.${DOMAIN}
done
```

---

## Testing

Comprehensive test suites are provided for both implementations. See [TESTING.md](TESTING.md) for detailed information.

### Quick Test Commands

```bash
# Run all tests
./test-cert-spreader.sh
./test-cert-spreader.py

# Run with verbose output
./test-cert-spreader.py -v

# Test specific functionality
python3 -m unittest test-cert-spreader.TestCustomCertificates -v
```

---

## Implementation Comparison

### Choosing Between Bash and Python

| Criteria | Bash Implementation | Python Implementation |
|----------|-------------------|----------------------|
| **Dependencies** | Standard Unix tools only | Python 3.9+ + requests |
| **Performance** | Excellent (native shell) | Very good |
| **Error Handling** | Good with proper exit codes | Excellent with exceptions |
| **Maintainability** | Good for shell expertise | Excellent for development teams |
| **Debugging** | Shell debugging tools | Rich debugging and logging |
| **Portability** | Unix/Linux only | Cross-platform |
| **Extensibility** | Moderate | High |

### Recommendation

- **Bash**: Choose for minimal dependencies, maximum performance, pure Unix environments
- **Python**: Choose for better error handling, easier maintenance, team development

---

## Contributing

### Development Guidelines

1. **Maintain dual compatibility**: Changes must work in both Bash and Python implementations
2. **Security first**: Follow security best practices, never expose secrets
3. **Test thoroughly**: All changes must include tests and pass existing test suites
4. **Document changes**: Update README.md, TESTING.md, and inline documentation

### Testing Requirements

```bash
# Before submitting changes
./test-cert-spreader.sh
./test-cert-spreader.py

# Validate with real configuration
./cert-spreader.sh --dry-run
./cert-spreader.py --dry-run
```

### Code Standards

- **Bash**: Follow shell scripting best practices, use `set -euo pipefail`
- **Python**: Follow PEP 8, use type hints, maintain Python 3.9+ compatibility
- **Documentation**: Clear comments, comprehensive docstrings, updated examples

---

## License & Attribution

Licensed under the **Apache License, Version 2.0**.  
See [LICENSE](LICENSE) for full terms.

**Attribution Requirement:** If you publicly use or modify this project, credit the original author in your documentation.

---

## Support & Resources

- **Issues**: Report bugs and feature requests via GitHub Issues
- **Documentation**: See [TESTING.md](TESTING.md) for testing details
- **Security**: Never commit real credentials; use `.gitignore` and example files
- **Best Practices**: Always run `--dry-run` before production deployments

---

*Practical SSL certificate management for distributed infrastructure.*