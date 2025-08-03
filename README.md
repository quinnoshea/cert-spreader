# Certificate Spreader

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
![Language](https://img.shields.io/badge/Bash%20%26%20Python-3.7+-informational)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/2b2bed5783c842dc89ab5c56adcb2896)](https://app.codacy.com?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
![Status](https://img.shields.io/badge/status-active-success)
[![CI](https://github.com/quinnoshea/cert-spreader/actions/workflows/ci-workflow.yml/badge.svg)](https://github.com/quinnoshea/cert-spreader/actions/workflows/ci-workflow.yml)

> **Deploy and manage Let's Encrypt SSL certificates across multiple hosts and services — safely, automatically, and with full audit logging.**
>
> Runs in **both Bash and Python** with identical functionality.

---

A comprehensive tool for securely deploying Let's Encrypt SSL certificates to multiple hosts and services. Available in both Bash and Python implementations with identical functionality.

## 🔒 Security Features

- **Configuration-based**: Keeps sensitive data separate from code
- **SSH Key Authentication**: Uses SSH keys for secure, passwordless deployment
- **Idempotency**: Only deploys when certificates have actually changed
- **Service Restart Intelligence**: Tries reload first, falls back to restart if needed
- **Configurable Permissions**: Customizable file and directory permissions
- **Certificate Change Tracking**: Only restarts services on hosts where certificates changed
- **Flexible Certificate Generation**: Create PKCS12, concatenated, and custom certificate formats for any application

## 📋 Prerequisites

### For Bash Version (`cert-spreader.sh`)
- Bash 4.0 or higher
- SSH access to target hosts with key-based authentication
- Valid SSL certificates (Let's Encrypt recommended)
- Standard Unix tools: `rsync`, `ssh`, `openssl`, `curl`, `sha256sum`, `head`, `awk`

### For Python Version (`cert-spreader.py`)
- Python 3.7+ with `requests` library (`pip install requests`)
- SSH access to target hosts with key-based authentication
- Valid SSL certificates (Let's Encrypt recommended)
- Standard Unix tools: `rsync`, `ssh`, `openssl`

## 🚀 Quick Setup

### 1. Configure the Application

```bash
# Copy the example configuration
cp config.example.conf config.conf

# Edit config.conf with your actual values
# WARNING: config.conf is ignored by git - it won't be committed
nano config.conf
```

### 2. Set Up SSH Access

```bash
# Generate SSH key if needed (do this once)
ssh-keygen -t ed25519 -f /root/.ssh/cert_spreader_key

# Copy SSH key to each host (replace 'hostname' with actual host)
ssh-copy-id -i /root/.ssh/cert_spreader_key root@hostname.yourdomain.com
```

### 3. Test the Configuration

```bash
# Make scripts executable
chmod +x cert-spreader.sh
chmod +x cert-spreader.py

# ALWAYS test first with dry-run (choose your preferred version)
./cert-spreader.sh --dry-run
# OR
./cert-spreader.py --dry-run
```

## 🔧 Usage

Both versions support identical command-line interfaces:

### Basic Commands

```bash
# Normal deployment (deploy certs + restart services + update Proxmox)
./cert-spreader.sh
./cert-spreader.py

# Dry run (see what would happen without making changes)  
./cert-spreader.sh --dry-run
./cert-spreader.py --dry-run

# Deploy certificates only (skip service restarts)
./cert-spreader.sh --cert-only
./cert-spreader.py --cert-only

# Restart services only (skip certificate deployment)
./cert-spreader.sh --services-only
./cert-spreader.py --services-only

# Update Proxmox certificates only (skip everything else)
./cert-spreader.sh --proxmox-only
./cert-spreader.py --proxmox-only

# Fix certificate file permissions only (skip everything else)
./cert-spreader.sh --permissions-fix
./cert-spreader.py --permissions-fix

# Use custom configuration file
./cert-spreader.sh custom.conf --dry-run
./cert-spreader.py custom.conf --dry-run

# Get help
./cert-spreader.sh --help
./cert-spreader.py --help
```

### Execution Modes

The scripts support several execution modes for different scenarios:

- **Default mode**: Deploys certificates to hosts, restarts services, and updates Proxmox
- **`--cert-only`**: Only deploys certificates to hosts, skips service restarts and Proxmox updates
- **`--services-only`**: Only restarts services on hosts that had certificates deployed, skips certificate deployment and Proxmox updates  
- **`--proxmox-only`**: Only updates Proxmox certificates, skips everything else
- **`--permissions-fix`**: Only fixes certificate file permissions, skips everything else
- **`--dry-run`**: Can be combined with any mode to show what would happen without making changes

**Note**: The selective execution flags (`--cert-only`, `--services-only`, `--proxmox-only`, `--permissions-fix`) are mutually exclusive.

### Intelligence Features

**Service Restart with Fallback**: The scripts now intelligently try `systemctl reload` first, and automatically fall back to `systemctl restart` if reload is not supported by the service.

**Conditional Service Restarts**: Services are only restarted on hosts where certificates were actually deployed, avoiding unnecessary service interruptions.

**Certificate Change Detection**: Uses SHA-256 hash comparison to detect certificate changes and skip deployment when certificates are unchanged.

### Typical Workflow

1. **Test first**: Always run with `--dry-run` to verify configuration
2. **Deploy certificates**: Run without flags for full deployment  
3. **Monitor logs**: Check `/var/log/cert-spreader.log` for detailed results

### Let's Encrypt Integration

Add as a post-renewal hook in your certbot configuration:

```bash
# Add to /etc/letsencrypt/renewal/yourdomain.com.conf
post_hook = /path/to/cert-spreader.sh
# OR
post_hook = /path/to/cert-spreader.py

# Or run manually after renewal
certbot renew && /path/to/cert-spreader.sh
```

## 📦 Installation

### Python Version Requirements

For the Python version (`cert-spreader.py`), you need to install the `requests` library:

```bash
# Install requests library
pip install requests

# Or using your system package manager
# Ubuntu/Debian:
sudo apt install python3-requests

# RHEL/CentOS/Fedora:
sudo dnf install python3-requests
```

### Bash Version Requirements

The bash version (`cert-spreader.sh`) only requires standard Unix tools (rsync, ssh, openssl, curl).

## ⚙️ Configuration

### Basic Configuration (config.conf)

```bash
# Basic settings
DOMAIN="yourdomain.com"
CERT_DIR="/etc/letsencrypt/live/yourdomain.com"

# SSH settings
SSH_OPTS="-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"

# Host list (space-separated)
HOSTS="web-server mail-server app-server"

# Host-specific services
HOST_SERVICES=(
    "web-server:22:nginx,apache2"
    "mail-server:22:postfix,dovecot"
    "app-server:2222:myapp"
)

# Proxmox nodes (optional)
PROXMOX_USER="user@pve!tokenid"
PROXMOX_TOKEN="your-api-token"
PROXMOX_NODES=(
    "proxmox01"
    "proxmox02"
)

# File permissions (NEW: configurable permissions and ownership)
FILE_PERMISSIONS=644                 # Default permissions for certificate files
PRIVKEY_PERMISSIONS=600              # More restrictive permissions for private keys
DIRECTORY_PERMISSIONS=755            # Directory permissions
FILE_OWNER=root                      # File owner (NEW: configurable owner)
FILE_GROUP=root                      # File group (NEW: configurable group)
```

### Host Services Format

The `HOST_SERVICES` array uses the format: `"hostname:port:service1,service2"`

- **hostname**: Must match entries in `HOSTS`
- **port**: SSH port (22 is default)
- **services**: Comma-separated list of systemd services to reload/restart

### Flexible Custom Certificate Generation

**NEW**: The scripts now support flexible, user-configurable certificate generation for any application that needs specialized certificate formats.

#### Array-Based Configuration (Recommended)

```bash
# Flexible certificate generation using arrays
CUSTOM_CERTIFICATES=(
    "pkcs12:your-password:application.pfx"          # PKCS12/PFX with password
    "pkcs12::no-password-cert.pfx"                  # PKCS12/PFX without password
    "concatenated:/etc/ssl/dhparam.pem:nginx.pem"   # Concatenated with DH params
    "concatenated::simple-combined.pem"             # Simple concatenated cert
)
```

#### Individual Settings Configuration

```bash
# PKCS12/PFX certificate generation
PKCS12_ENABLED=true
PKCS12_PASSWORD="your-password"      # Optional - leave empty for no password
PKCS12_FILENAME="certificate.pfx"    # Custom filename

# Concatenated certificate generation  
CONCATENATED_ENABLED=true
CONCATENATED_DHPARAM_FILE="/etc/nginx/ssl/dhparam.pem"  # Optional DH parameters
CONCATENATED_FILENAME="combined.pem"                    # Custom filename
```


#### Certificate Types Supported

- **PKCS12/PFX**: Perfect for applications like Plex, Windows services, or any application requiring PKCS12 format
  - Configurable password (optional)
  - Custom filenames
  - Multiple certificates supported
  
- **Concatenated**: Ideal for applications like ZNC, nginx, or services needing combined certificates
  - Private key + certificate + chain in one file
  - Optional DH parameters inclusion
  - Custom filenames
  - Multiple certificates supported

#### Practical Examples

**For Plex Media Server:**
```bash
CUSTOM_CERTIFICATES=(
    "pkcs12:MyPlexPassword:plex-server.pfx"
)
```

**For ZNC IRC Bouncer:**
```bash
CUSTOM_CERTIFICATES=(
    "concatenated:/etc/ssl/dhparam.pem:znc.pem"
)
```

**For Multiple Applications:**
```bash
CUSTOM_CERTIFICATES=(
    "pkcs12:PlexPass123:plex.pfx"                    # Plex Media Server
    "concatenated:/etc/ssl/dhparam.pem:nginx.pem"     # Nginx with DH params
    "concatenated::znc.pem"                          # ZNC without DH params
    "pkcs12::windows-service.pfx"                    # Windows service (no password)
)
```

**Mixed Configuration (using both formats):**
```bash
# Array for multiple certificates
CUSTOM_CERTIFICATES=(
    "pkcs12:secret:app1.pfx"
    "concatenated::app2.pem"
)

# Individual settings for additional certificates
PKCS12_ENABLED=true
PKCS12_FILENAME="additional-app.pfx"  
PKCS12_PASSWORD="another-password"
```

### Configurable Certificate Permissions and Ownership

**NEW FEATURE**: File permissions and ownership are now configurable through the configuration file:

```bash
# File permissions and ownership configuration
FILE_PERMISSIONS=644                 # Default permissions for certificate files (owner: read/write, group/others: read)
PRIVKEY_PERMISSIONS=600              # More restrictive permissions for private keys (owner: read/write only)
DIRECTORY_PERMISSIONS=755            # Directory permissions (owner: read/write/execute, group/others: read/execute)
FILE_OWNER=root                      # File owner (NEW: configurable owner)
FILE_GROUP=root                      # File group (NEW: configurable group)
```

**Default Security Model:**
- Certificate directory: `755` (drwxr-xr-x, root:root)
- Private keys (`privkey.pem`): `600` (-rw-------, root:root) 
- Other certificates (`cert.pem`, `fullchain.pem`, etc.): `644` (-rw-r--r--, root:root)
- Service certificates (Plex, ZNC): Use `FILE_PERMISSIONS` setting
- **All files and directories**: Default to `root:root` ownership (configurable)

**Customization Examples:**
```bash
# More restrictive setup (all files private)
FILE_PERMISSIONS=600
PRIVKEY_PERMISSIONS=600
DIRECTORY_PERMISSIONS=700
FILE_OWNER=root
FILE_GROUP=root

# Different group for certificate access
FILE_PERMISSIONS=644
PRIVKEY_PERMISSIONS=640
DIRECTORY_PERMISSIONS=755
FILE_OWNER=root
FILE_GROUP=ssl-cert

# Application-specific ownership
FILE_PERMISSIONS=644
PRIVKEY_PERMISSIONS=600
DIRECTORY_PERMISSIONS=755
FILE_OWNER=nginx
FILE_GROUP=nginx
```

**Manual Permission Fix:** Use `--permissions-fix` to fix permissions without doing anything else.

### Alternative: Environment Variables

While the scripts currently use `config.conf`, you can use environment variables as an alternative or supplement for sensitive values:

**Option 1: Hybrid Approach (Recommended)**
Keep `config.conf` for host lists and complex settings, but override sensitive values:

```bash
# Set sensitive values via environment
export PROXMOX_TOKEN="your-real-token"
export FILE_PERMISSIONS="600"  # Override default permissions
export FILE_OWNER="nginx"      # Override default owner
export FILE_GROUP="ssl-cert"   # Override default group

# Run script normally
./cert-spreader.sh
```

**Option 2: Full Environment Variables**
Copy and customize the example file:

```bash
# Create your environment file
cp secrets.env.example secrets.env
nano secrets.env

# Example secrets.env content:
export DOMAIN="yourdomain.com"
export PROXMOX_TOKEN="your-real-token"
export CUSTOM_CERTIFICATES=(
    "pkcs12:YourSecretPassword:plex.pfx"
    "concatenated:/etc/ssl/dhparam.pem:nginx.pem"
)
export FILE_PERMISSIONS="644"
export PRIVKEY_PERMISSIONS="600"
export FILE_OWNER="root"
export FILE_GROUP="ssl-cert"

# Modify script to source it (add to beginning of cert-spreader.sh):
if [[ -f "secrets.env" ]]; then
    source secrets.env
fi
```

## 🔄 Bash vs Python Versions

| Feature | Bash Version | Python Version |
|---------|-------------|----------------|
| **Dependencies** | Standard Unix tools | Python 3.7+ + requests |
| **Performance** | Very fast | Fast |
| **Error Handling** | Good | Excellent |
| **Debugging** | Standard bash debugging | Rich exception info |
| **Configuration** | Bash source files | Bash source files (same format) |
| **Portability** | Unix/Linux only | Cross-platform |
| **Type Safety** | No | Yes (with type hints) |
| **Maintainability** | Good | Excellent |

**Choose Bash if:**
- You prefer shell scripting
- Minimal dependencies are critical
- You need maximum performance
- Your environment is Unix/Linux only

**Choose Python if:**
- You prefer structured programming
- You want better error messages
- You need cross-platform compatibility
- You plan to extend functionality

## 🔒 Security Best Practices

### SSH Key Management

1. **Use dedicated keys**: Create separate SSH keys for certificate deployment
2. **Restrict key access**: 
   ```bash
   chmod 600 /root/.ssh/cert_spreader_key
   chown root:root /root/.ssh/cert_spreader_key
   ```
3. **Limit key usage**: Consider using SSH key restrictions where possible

### Configuration Security

1. **Protect config file**:
   ```bash
   chmod 600 config.conf
   chown root:root config.conf
   ```

2. **Review before commits**: Always check `git status` before pushing

3. **Use the example file**: Share `config.example.conf`, never `config.conf`

4. **Configure permissions appropriately**: Use the permission settings to match your security requirements

## 🔧 Troubleshooting

### Common Issues

1. **Permission Denied**: 
   - Check SSH key permissions and SSH agent
   - Verify SSH key is copied to target hosts
   - Test manual SSH connection: `ssh -i /root/.ssh/cert_spreader_key root@host.domain.com`

2. **Certificate unchanged, skipping**: 
   - This is normal behavior (idempotency)
   - Use `--dry-run` to see what would happen
   - Check certificate hashes match between local and remote

3. **Service restart failures**:
   - **NEW**: Scripts now automatically try reload first, then restart
   - Verify service names in configuration
   - Test manually: `ssh host 'systemctl reload nginx || systemctl restart nginx'`

4. **Proxmox API errors**:
   - Verify API token permissions in Proxmox
   - Check token format: `user@realm!tokenname`
   - Test connectivity: `curl -k https://proxmox.domain.com:8006`

5. **Permission issues**:
   - Use `--permissions-fix` to fix permissions without deployment
   - Check if your permission settings match your security requirements
   - Verify script is running as root for chown operations

### Debug Commands

```bash
# Test SSH connectivity
ssh -i /root/.ssh/cert_spreader_key root@hostname.domain.com 'echo "Connection OK"'

# Check certificate validity
openssl x509 -in /etc/letsencrypt/live/domain/cert.pem -text -noout | grep -A2 Validity

# Verify certificate hash (new method)
sha256sum /etc/letsencrypt/live/domain/fullchain.pem | head -c 64

# Test service reload with fallback
ssh hostname.domain.com 'systemctl reload nginx || systemctl restart nginx'

# Check current permissions
ls -la /etc/letsencrypt/live/domain/
```

### Testing

Both implementations include comprehensive test suites:

**Bash Testing Framework:**
```bash
# Run all Bash tests
./test-cert-spreader.sh

# Setup test environment for manual testing
./test-cert-spreader.sh --setup

# Clean up test environment
./test-cert-spreader.sh --cleanup
```

**Python Testing Framework:**
```bash
# Run all Python tests
./test-cert-spreader.py

# Run with verbose output
./test-cert-spreader.py -v

# Run specific test class
python3 -m unittest test-cert-spreader.TestOwnerGroupFunctionality -v
```

**Run Both Test Suites:**
```bash
# Run both test frameworks
./test-cert-spreader.sh && ./test-cert-spreader.py
```

See `TESTING.md` for detailed testing documentation and test coverage information.

## 🎯 Design Philosophy

This tool follows the principle of **simplicity with intelligence**:

- **Linear execution**: Easy to understand and debug
- **Minimal dependencies**: Uses standard Unix tools and Python with requests library
- **Clear logging**: Simple, readable log messages with dry-run support
- **Fail-fast**: Stops on errors rather than continuing with undefined state
- **Idempotent**: Safe to run multiple times, only changes what's needed
- **Intelligent**: Tries reload before restart, only acts on changed certificates
- **Configurable**: Flexible permissions and behavior without complexity

## 🔄 Recent Improvements

### Version 2.0 Features

- **Service Restart Intelligence**: Automatically tries reload first, falls back to restart
- **Conditional Restarts**: Only restarts services on hosts where certificates changed
- **Configurable Permissions**: File and directory permissions are now configurable
- **Configurable Ownership**: File owner and group are now configurable (NEW)
- **Python Implementation**: Complete Python version with identical functionality
- **Better Hash Handling**: Improved certificate change detection (fixed quote escaping issues)
- **Enhanced Testing**: Comprehensive test suite for validation

## 🤝 Contributing

1. **Report issues**: Document any problems you encounter
2. **Suggest improvements**: Ideas for better security or functionality  
3. **Test thoroughly**: Always use `--dry-run` when testing changes
4. **Keep it simple**: Resist the urge to add complexity
5. **Update tests**: Ensure test suite covers new functionality

## 📄 License

Licensed under the **Apache License, Version 2.0** (the "License");  
you may not use this file except in compliance with the License.  
You may obtain a copy at:

> http://www.apache.org/licenses/LICENSE-2.0

Unless required by law or agreed to in writing, software  
distributed under the License is distributed on an **"AS IS" BASIS**,  
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.  
See the License for the specific language governing permissions and  
limitations under the License.

**Attribution Requirement:**  
If you publicly use or modify this project, you must credit the original author in your documentation or README.

---

**⚠️ Security Reminder**: Never commit real hostnames, tokens, or private keys to any repository, even private ones!

**💡 Pro Tip**: Always run with `--dry-run` first to see what the script will do before making actual changes.

**🔧 New Feature**: Configure file permissions and ownership to match your security requirements using the new permission and ownership settings!