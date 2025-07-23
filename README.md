# Certificate Spreader

A simplified bash script for securely deploying Let's Encrypt SSL certificates to multiple hosts and services. This tool replaces complex shell scripts with a maintainable, configurable solution.

## 🔒 Security Features

- **Configuration-based**: Keeps sensitive data separate from code
- **SSH Key Authentication**: Uses SSH keys for secure, passwordless deployment
- **Idempotency**: Only deploys when certificates have actually changed
- **Comprehensive .gitignore**: Prevents accidental commit of sensitive files

## 📋 Prerequisites

- Bash 4.0 or higher
- SSH access to target hosts with key-based authentication
- Valid SSL certificates (Let's Encrypt recommended)
- Standard Unix tools: `rsync`, `ssh`, `openssl`, `curl`, `sha256sum`

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
# Make script executable
chmod +x cert-spreader.sh

# ALWAYS test first with dry-run
./cert-spreader.sh --dry-run
```

## 🔧 Usage

### Basic Commands

```bash
# Normal deployment (deploy certs + restart services + update Proxmox)
./cert-spreader.sh

# Dry run (see what would happen without making changes)  
./cert-spreader.sh --dry-run

# Deploy certificates only (skip service restarts)
./cert-spreader.sh --cert-only

# Restart services only (skip certificate deployment)
./cert-spreader.sh --services-only

# Update Proxmox certificates only (skip everything else)
./cert-spreader.sh --proxmox-only

# Fix certificate file permissions only (skip everything else)
./cert-spreader.sh --permissions-fix

# Use custom configuration file
./cert-spreader.sh custom.conf --dry-run

# Get help
./cert-spreader.sh --help
```

### Execution Modes

The script supports several execution modes for different scenarios:

- **Default mode**: Deploys certificates to hosts, restarts services, and updates Proxmox
- **`--cert-only`**: Only deploys certificates to hosts, skips service restarts and Proxmox updates
- **`--services-only`**: Only restarts services on hosts, skips certificate deployment and Proxmox updates  
- **`--proxmox-only`**: Only updates Proxmox certificates, skips everything else
- **`--permissions-fix`**: Only fixes certificate file permissions, skips everything else
- **`--dry-run`**: Can be combined with any mode to show what would happen without making changes

**Note**: The selective execution flags (`--cert-only`, `--services-only`, `--proxmox-only`, `--permissions-fix`) are mutually exclusive.

**Common use cases:**
- `--proxmox-only`: When you only need to update Proxmox after manual certificate changes, or if host deployments failed but Proxmox is still reachable
- `--cert-only`: When testing certificate deployment without affecting running services
- `--services-only`: When certificates are already deployed but services need to be restarted
- `--permissions-fix`: When certificate permissions have been changed manually or after system maintenance, ensuring proper Let's Encrypt security standards

### Typical Workflow

1. **Test first**: Always run with `--dry-run` to verify configuration
2. **Deploy certificates**: Run without flags for full deployment  
3. **Monitor logs**: Check `/var/log/cert-spreader.log` for detailed results

### Let's Encrypt Integration

Add as a post-renewal hook in your certbot configuration:

```bash
# Add to /etc/letsencrypt/renewal/yourdomain.com.conf
post_hook = /path/to/cert-spreader.sh

# Or run manually after renewal
certbot renew && /path/to/cert-spreader.sh
```

## 📁 Repository Structure

```
cert-spreader/
├── cert-spreader.sh           # Main deployment script
├── config.conf                # Your actual config (NOT in git)
├── config.example.conf        # Configuration template (safe to commit)
├── python/                    # Previous Python implementation
│   ├── cert-spreader.py
│   ├── config.yml
│   └── ...
├── originals/                 # Original shell scripts (NOT in git)
│   ├── cert-deploy.sh
│   └── plex-cert.sh
├── .gitignore                 # Protects sensitive files  
└── README.md                  # This file
```

## ⚙️ Configuration

### Basic Configuration (config.conf)

```bash
# Basic settings
DOMAIN="yourdomain.com"
CERT_DIR="/etc/letsencrypt/live/yourdomain.com"
BACKUP_HOST="backup-server"

# SSH settings
SSH_OPTS="-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"

# Host list (space-separated)
HOSTS="web-server mail-server app-server"

# Host-specific services
declare -a HOST_SERVICES=(
    "web-server:22:nginx,apache2"
    "mail-server:22:postfix,dovecot"
    "app-server:2222:myapp"
)

# Proxmox nodes (optional)
PROXMOX_USER="user@pve!tokenid"
PROXMOX_TOKEN="your-api-token"
declare -a PROXMOX_NODES=(
    "proxmox01"
    "proxmox02"
)
```

### Host Services Format

The `HOST_SERVICES` array uses the format: `"hostname:port:service1,service2"`

- **hostname**: Must match entries in `HOSTS`
- **port**: SSH port (22 is default)
- **services**: Comma-separated list of systemd services to reload

### Service Certificate Generation

The script can generate specialized certificate formats:

```bash
# Enable Plex PKCS12 certificate
PLEX_CERT_ENABLED=true
PLEX_CERT_PASSWORD="your-password"

# Enable ZNC certificate bundle
ZNC_CERT_ENABLED=true
ZNC_DHPARAM_FILE="/etc/nginx/ssl/dhparam.pem"
```

### Certificate Permissions Security

The script automatically secures certificate permissions following Let's Encrypt best practices:

**Directory Permissions:**
- Certificate directory: `755` (drwxr-xr-x, root:root)

**File Permissions:**
- Private keys (`privkey.pem`): `600` (-rw-------, root:root)
- Certificates (`cert.pem`, `fullchain.pem`, `chain.pem`): `644` (-rw-r--r--, root:root)
- Plex certificate (`plex-certificate.pfx`): `644` (-rw-r--r--, root:root) 
- ZNC certificate (`znc.pem`): `600` (-rw-------, root:root)

**Idempotency:** The script only changes permissions when needed, logging "permissions OK" when they're already correct.

**Manual fix:** Use `./cert-spreader.sh --permissions-fix` to fix permissions without doing anything else.

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

## 🚨 What Gets Ignored by Git

The `.gitignore` file prevents these sensitive files from being committed:

- `config.conf` (your real configuration)
- `originals/` (original scripts with secrets)
- `python/config.yml` (Python version config)
- Certificate files (`*.pem`, `*.pfx`, `*.key`)
- Log files (`*.log`)
- Backup and temporary files

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
   - Verify service names in configuration
   - Check if services support `reload` vs need `restart`
   - Test manually: `ssh host 'systemctl reload nginx'`

4. **Proxmox API errors**:
   - Verify API token permissions in Proxmox
   - Check token format: `user@realm!tokenname`
   - Test connectivity: `curl -k https://proxmox.domain.com:8006`

### Debug Commands

```bash
# Test SSH connectivity
ssh -i /root/.ssh/cert_spreader_key root@hostname.domain.com 'echo "Connection OK"'

# Check certificate validity
openssl x509 -in /etc/letsencrypt/live/domain/cert.pem -text -noout | grep -A2 Validity

# Verify certificate hash
sha256sum /etc/letsencrypt/live/domain/fullchain.pem

# Test service reload
ssh hostname.domain.com 'systemctl reload nginx'
```

## 📝 Migration from Complex Scripts

If you're migrating from the previous Python version or complex shell scripts:

1. **Extract host lists**: Copy your host definitions to `HOSTS` variable
2. **Map services**: Convert service configurations to `HOST_SERVICES` format  
3. **Preserve working commands**: SSH and curl commands work the same way
4. **Test thoroughly**: Use `--dry-run` extensively during migration
5. **Simplify gradually**: Start with basic functionality, add features as needed

## 🎯 Design Philosophy

This script follows the principle of **simplicity over complexity**:

- **Linear execution**: Easy to understand and debug
- **Minimal dependencies**: Uses standard Unix tools
- **Clear logging**: Simple, readable log messages
- **Fail-fast**: Stops on errors rather than continuing with undefined state
- **Idempotent**: Safe to run multiple times

## 🤝 Contributing

1. **Report issues**: Document any problems you encounter
2. **Suggest improvements**: Ideas for better security or functionality  
3. **Test thoroughly**: Always use `--dry-run` when testing changes
4. **Keep it simple**: Resist the urge to add complexity

## 📄 License

Private repository - internal use only.

---

**⚠️ Security Reminder**: Never commit real hostnames, tokens, or private keys to any repository, even private ones!

**💡 Pro Tip**: Always run `./cert-spreader.sh --dry-run` first to see what the script will do before making actual changes.