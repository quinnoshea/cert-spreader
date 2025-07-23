# Certificate Spreader

A Python application for securely deploying SSL certificates to multiple hosts and services, including Proxmox nodes. This replaces shell scripts with a more maintainable and secure solution.

## 🔒 Security Features

- **Secret Management**: Keeps sensitive data (tokens, passwords) out of git
- **Environment Variables**: Override config values with environment variables
- **Template-based Config**: Provides safe templates for sharing configuration structure
- **Comprehensive .gitignore**: Prevents accidental commit of sensitive files

## 📋 Prerequisites

- Python 3.6 or higher
- Required Python packages: `pyyaml`, `requests`
- SSH access to target hosts
- Valid SSL certificates (Let's Encrypt recommended)

## 🚀 Quick Setup

### 1. Install Dependencies

```bash
# Install required Python packages
pip3 install pyyaml requests
```

### 2. Configure the Application

```bash
# Copy the template to create your config
cp config.template.yml config.yml

# Edit config.yml with your actual values
# WARNING: config.yml is ignored by git - it won't be committed
nano config.yml
```

### 3. Set Up Secrets

```bash
# Copy the example secrets file
cp secrets.env.example secrets.env

# Edit with your actual secrets
nano secrets.env

# Secure the secrets file
chmod 600 secrets.env

# Make the wrapper script executable
chmod +x run-cert-spreader.sh
```

### 4. Test the Configuration

```bash
# RECOMMENDED: Use the wrapper script (handles secrets automatically)
./run-cert-spreader.sh --dry-run

# Verbose dry run for detailed output
./run-cert-spreader.sh --dry-run --verbose
```

## 🔧 Usage

### Basic Commands

#### Using the Wrapper Script (Recommended)

```bash
# Normal deployment (deploy certs + restart services + update Proxmox)
./run-cert-spreader.sh

# Dry run (see what would happen without making changes)  
./run-cert-spreader.sh --dry-run

# Deploy certificates only (skip service restarts)
./run-cert-spreader.sh --deploy-only

# Restart services only (skip certificate deployment)
./run-cert-spreader.sh --services-only

# Enable verbose logging
./run-cert-spreader.sh --verbose

# Use custom config file
./run-cert-spreader.sh --config /path/to/other-config.yml

# Get help
./run-cert-spreader.sh --help
```

#### Direct Python Execution (Alternative)

```bash
# If you prefer to manage environment variables manually
source secrets.env
python3 cert-spreader.py --dry-run
unset CERT_SPREADER_PROXMOX_TOKEN  # Manual cleanup
```

### Typical Workflow

1. **Test first**: Always run with `--dry-run` to verify configuration
2. **Deploy certificates**: Run without flags for full deployment
3. **Monitor logs**: Check `/var/log/cert-spreader.log` for detailed results

## 📁 File Structure

```
cert-spreader/
├── cert-spreader.py        # Main Python application
├── run-cert-spreader.sh    # Wrapper script with automatic secret management
├── config.yml              # Your actual config (NOT in git)
├── config.template.yml     # Template for config (safe to commit)
├── secrets.env             # Your actual secrets (NOT in git)  
├── secrets.env.example     # Template for secrets (safe to commit)
├── .gitignore              # Protects sensitive files
└── README.md               # This file
```

## ⚙️ Configuration

### Host Configuration Example

```yaml
hosts:
  web-server:
    port: 22                    # SSH port (optional, defaults to 22)
    services:
      - name: "nginx"
        action: "reload"        # or "restart"
      - name: "apache2" 
        action: "restart"
    post_deploy_commands:       # Optional commands after cert deployment
      - "chown www-data:www-data /path/to/cert"
      
  special-server:
    port: 2222                  # Custom SSH port
    services:
      - name: "custom-service"
        action: "reload"
```

### Environment Variables

All sensitive values can be overridden with environment variables:

| Environment Variable | Description |
|---------------------|-------------|
| `CERT_SPREADER_PROXMOX_USER` | Proxmox API user (format: `user@pve!tokenname`) |
| `CERT_SPREADER_PROXMOX_TOKEN` | Proxmox API token |
| `CERT_SPREADER_PLEX_PASSWORD` | Password for Plex PKCS12 certificate |
| `CERT_SPREADER_DOMAIN` | Your domain name |
| `CERT_SPREADER_USERNAME` | Username for file ownership |
| `CERT_SPREADER_CERT_DIR` | Certificate directory path |

## 🔒 Security Best Practices

### For Git Repositories

1. **Never commit real secrets**: The `.gitignore` file protects you, but double-check
2. **Use templates**: Share `config.template.yml`, not `config.yml`
3. **Environment variables**: Preferred method for sensitive values
4. **Review before pushing**: Always check `git status` before committing

### For Production

1. **Restrict file permissions**: 
   ```bash
   chmod 600 config.yml secrets.env
   chown root:root config.yml secrets.env
   ```

2. **Use dedicated SSH keys**: Create separate SSH keys for certificate deployment

3. **Monitor logs**: Set up log monitoring for deployment failures

4. **Test regularly**: Use `--dry-run` to validate configuration changes

## 🚨 What Gets Ignored by Git

The `.gitignore` file prevents these sensitive files from being committed:

- `config.yml` (your real config)
- `secrets.env` (your real secrets)
- `*.pem`, `*.pfx`, `*.key` (certificate files)
- `*.log` (log files)
- Various backup and temporary files

## 🔧 Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure SSH keys and file permissions are correct
2. **Module Not Found**: Install required packages with `pip3 install pyyaml requests`
3. **Connection Timeout**: Check SSH connectivity and firewall rules
4. **Proxmox API Errors**: Verify token permissions and API user privileges

### Debug Mode

```bash
# Enable maximum verbosity
python3 cert-spreader.py --verbose --dry-run

# Check certificate validity
openssl x509 -in /etc/letsencrypt/live/your-domain/cert.pem -text -noout
```

## 📝 Migration from Shell Scripts

If you're migrating from `plex-cert.sh` or similar scripts:

1. **Map your hosts**: Copy host definitions from your shell script arrays
2. **Preserve service actions**: Note which services use `reload` vs `restart` 
3. **Keep working curl commands**: Proxmox curl commands are preserved exactly
4. **Test thoroughly**: Use `--dry-run` to verify behavior before going live

## 🤝 Contributing

This is a private repository, but you can:

1. **Report issues**: Document any problems you encounter
2. **Suggest improvements**: Ideas for better security or functionality
3. **Share templates**: Contribute configuration templates for common setups

## 📄 License

Private repository - internal use only.

---

**⚠️ Security Reminder**: Never commit real tokens, passwords, or private keys to any repository, even private ones!