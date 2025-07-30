#!/usr/bin/env python3
"""
Certificate Spreader - Python Version
Purpose: Deploy Let's Encrypt certificates to multiple hosts after renewal
This script automates the process of distributing SSL certificates to various servers

This is a Python port of cert-spreader.sh using only standard library modules.
"""

import os
import sys
import argparse
import subprocess
import hashlib
import logging
import json
import urllib.request
import urllib.parse
import urllib.error
import ssl
import base64
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime


# Error codes matching the bash version
class ExitCodes:
    SUCCESS = 0
    CONFIG = 1
    CERT = 2
    NETWORK = 3
    PERMISSION = 4
    VALIDATION = 5
    USAGE = 6


@dataclass
class Config:
    """Configuration data structure"""
    domain: str = ""
    cert_dir: str = ""
    backup_host: str = ""
    ssh_opts: str = "-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"
    log_file: str = "/var/log/cert-spreader.log"
    hosts: List[str] = field(default_factory=list)
    host_services: List[str] = field(default_factory=list)
    proxmox_nodes: List[str] = field(default_factory=list)
    proxmox_user: str = ""
    proxmox_token: str = ""
    plex_cert_enabled: bool = False
    plex_cert_password: str = "PASSWORD"
    znc_cert_enabled: bool = False
    znc_dhparam_file: str = ""
    ssl_backup_dir: str = "/backup/ssl"
    nginx_backup_dir: str = "/backup/nginx"
    # File permission configuration
    file_permissions: str = "644"        # Default permissions for certificate files
    privkey_permissions: str = "600"     # More restrictive permissions for private key
    directory_permissions: str = "755"   # Directory permissions


class CertSpreader:
    """Main certificate spreader class"""
    
    def __init__(self, config_file: str = "config.conf"):
        self.config_file = config_file
        self.config = Config()
        self.dry_run = False
        self.cert_only = False
        self.services_only = False
        self.proxmox_only = False
        self.permissions_fix = False
        self.deployed_hosts: List[str] = []
        self.local_cert_changed = False
        self.logger = self._setup_logging()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('cert-spreader')
        logger.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter('[%(asctime)s] %(message)s', 
                                    datefmt='%Y-%m-%d %H:%M:%S')
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        return logger
    
    def log(self, message: str) -> None:
        """Log message with optional dry-run prefix"""
        prefix = "[DRY-RUN] " if self.dry_run else ""
        full_message = f"{prefix}{message}"
        self.logger.info(full_message)
        
        # Also log to system logger using subprocess (similar to bash version)
        try:
            subprocess.run(['logger', '-t', 'cert-spreader', full_message], 
                         check=False, capture_output=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            pass  # logger command not available or failed
    
    def load_config(self) -> None:
        """Load configuration from file"""
        if not os.path.isfile(self.config_file):
            self.log(f"ERROR: Configuration file '{self.config_file}' not found")
            self.log(f"Copy config.example.conf to {self.config_file} and customize it")
            sys.exit(ExitCodes.CONFIG)
        
        # Parse configuration file
        config_vars = {}
        arrays = {}
        
        try:
            with open(self.config_file, 'r') as f:
                content = f.read()
            
            # First, extract bash arrays by parsing the file directly
            import re
            
            # Look for array declarations like HOST_SERVICES=(...) 
            for match in re.finditer(r'(\w+)=\(\s*(.*?)\s*\)', content, re.DOTALL):
                array_name = match.group(1)
                array_content = match.group(2)
                
                # Parse array elements (simple approach - assumes quoted strings)
                elements = []
                for element_match in re.finditer(r'"([^"]*)"', array_content):
                    elements.append(element_match.group(1))
                
                arrays[array_name] = elements
            
            # Execute the bash config file to extract scalar variables
            bash_script = f'''
            source {self.config_file}
            # Export all variables
            echo "DOMAIN=${{DOMAIN:-}}"
            echo "CERT_DIR=${{CERT_DIR:-}}"
            echo "BACKUP_HOST=${{BACKUP_HOST:-}}"
            echo "SSH_OPTS=${{SSH_OPTS:-}}"
            echo "LOG_FILE=${{LOG_FILE:-}}"
            echo "HOSTS=${{HOSTS:-}}"
            echo "PROXMOX_USER=${{PROXMOX_USER:-}}"
            echo "PROXMOX_TOKEN=${{PROXMOX_TOKEN:-}}"
            echo "PLEX_CERT_ENABLED=${{PLEX_CERT_ENABLED:-false}}"
            echo "ZNC_CERT_ENABLED=${{ZNC_CERT_ENABLED:-false}}"
            echo "PLEX_CERT_PASSWORD=${{PLEX_CERT_PASSWORD:-PASSWORD}}"
            echo "ZNC_DHPARAM_FILE=${{ZNC_DHPARAM_FILE:-}}"
            echo "SSL_BACKUP_DIR=${{SSL_BACKUP_DIR:-/backup/ssl}}"
            echo "NGINX_BACKUP_DIR=${{NGINX_BACKUP_DIR:-/backup/nginx}}"
            echo "FILE_PERMISSIONS=${{FILE_PERMISSIONS:-644}}"
            echo "PRIVKEY_PERMISSIONS=${{PRIVKEY_PERMISSIONS:-600}}"
            echo "DIRECTORY_PERMISSIONS=${{DIRECTORY_PERMISSIONS:-755}}"
            '''
            
            result = subprocess.run(['bash', '-c', bash_script], 
                                  capture_output=True, text=True, check=True)
            
            # Parse environment variables
            for line in result.stdout.strip().split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    config_vars[key] = value
                    
        except subprocess.SubprocessError as e:
            self.log(f"ERROR: Failed to parse configuration file: {e}")
            sys.exit(ExitCodes.CONFIG)
        
        # Map config variables to our Config object
        self.config.domain = config_vars.get('DOMAIN', '')
        self.config.cert_dir = config_vars.get('CERT_DIR', '')
        self.config.backup_host = config_vars.get('BACKUP_HOST', '')
        self.config.ssh_opts = config_vars.get('SSH_OPTS', self.config.ssh_opts)
        self.config.log_file = config_vars.get('LOG_FILE', self.config.log_file)
        self.config.ssl_backup_dir = config_vars.get('SSL_BACKUP_DIR', self.config.ssl_backup_dir)
        self.config.nginx_backup_dir = config_vars.get('NGINX_BACKUP_DIR', self.config.nginx_backup_dir)
        
        # Parse HOSTS string into list
        hosts_str = config_vars.get('HOSTS', '')
        self.config.hosts = hosts_str.split() if hosts_str else []
        
        # Parse Proxmox configuration
        self.config.proxmox_user = config_vars.get('PROXMOX_USER', '')
        self.config.proxmox_token = config_vars.get('PROXMOX_TOKEN', '')
        
        # Parse boolean flags
        self.config.plex_cert_enabled = config_vars.get('PLEX_CERT_ENABLED', 'false').lower() == 'true'
        self.config.znc_cert_enabled = config_vars.get('ZNC_CERT_ENABLED', 'false').lower() == 'true'
        self.config.plex_cert_password = config_vars.get('PLEX_CERT_PASSWORD', 'PASSWORD')
        self.config.znc_dhparam_file = config_vars.get('ZNC_DHPARAM_FILE', '')
        
        # Parse permission configuration
        self.config.file_permissions = config_vars.get('FILE_PERMISSIONS', '644')
        self.config.privkey_permissions = config_vars.get('PRIVKEY_PERMISSIONS', '600')
        self.config.directory_permissions = config_vars.get('DIRECTORY_PERMISSIONS', '755')
        
        # Parse arrays from extracted bash arrays
        self.config.host_services = arrays.get('HOST_SERVICES', [])
        self.config.proxmox_nodes = arrays.get('PROXMOX_NODES', [])
        
        self._validate_config()
    
    def _validate_config(self) -> None:
        """Validate configuration values"""
        required_vars = ['domain', 'cert_dir', 'backup_host', 'hosts']
        validation_errors = 0
        
        for var in required_vars:
            value = getattr(self.config, var)
            if not value:
                self.log(f"ERROR: Required variable '{var.upper()}' not set in {self.config_file}")
                validation_errors += 1
        
        # Validate certificate directory
        if self.config.cert_dir and not os.path.isdir(self.config.cert_dir):
            self.log(f"ERROR: Certificate directory does not exist: {self.config.cert_dir}")
            validation_errors += 1
        elif self.config.cert_dir and not os.access(self.config.cert_dir, os.R_OK):
            self.log(f"ERROR: Certificate directory is not readable: {self.config.cert_dir}")
            validation_errors += 1
        
        # Validate domain format (basic check)
        if self.config.domain and not self._is_valid_domain(self.config.domain):
            self.log(f"WARNING: DOMAIN format may be invalid: {self.config.domain}")
        
        if validation_errors > 0:
            self.log(f"Configuration validation failed with {validation_errors} error(s)")
            sys.exit(ExitCodes.VALIDATION)
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Basic domain validation"""
        import re
        pattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
    
    def calculate_cert_hash(self, cert_path: str) -> str:
        """Calculate SHA256 hash of certificate file"""
        try:
            with open(cert_path, 'rb') as f:
                content = f.read()
            return hashlib.sha256(content).hexdigest()
        except IOError as e:
            self.log(f"ERROR: Failed to read certificate file {cert_path}: {e}")
            return "none"
    
    def build_ssh_command(self, host: str, port: int = 22, command: str = "") -> List[str]:
        """Build SSH command list"""
        ssh_cmd = ['ssh'] + self.config.ssh_opts.split()
        
        if port != 22:
            ssh_cmd.extend(['-p', str(port)])
        
        ssh_cmd.append(f'root@{host}.{self.config.domain}')
        
        if command:
            ssh_cmd.append(command)
        
        return ssh_cmd
    
    def cert_changed(self, host: str, port: int = 22) -> bool:
        """Check if certificate has changed on remote host"""
        # Calculate local hash
        cert_file = os.path.join(self.config.cert_dir, 'fullchain.pem')
        local_hash = self.calculate_cert_hash(cert_file)
        
        # Calculate remote hash
        ssh_cmd = self.build_ssh_command(host, port, f'sha256sum {cert_file} 2>/dev/null | head -c 64')
        
        try:
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
            remote_hash = result.stdout.strip() if result.returncode == 0 else "none"
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            remote_hash = "none"
        
        return local_hash != remote_hash
    
    def deploy_to_host(self, host: str, port: int = 22) -> bool:
        """Deploy certificates to a single remote host"""
        # Check if certificate has changed
        if not self.cert_changed(host, port):
            self.log(f"Skipping {host} (certificate unchanged)")
            return True
        
        self.log(f"Deploying certificates to {host}")
        
        if self.dry_run:
            self.log(f"Would deploy certificates to {host} using rsync")
            self.deployed_hosts.append(host)
            return True
        
        # Build rsync command
        rsync_ssh = f"ssh {self.config.ssh_opts}"
        if port != 22:
            rsync_ssh += f" -p {port}"
        
        rsync_cmd = [
            'rsync', '-aL', '-e', rsync_ssh,
            f'{self.config.cert_dir}/',
            f'root@{host}.{self.config.domain}:{self.config.cert_dir}/'
        ]
        
        try:
            result = subprocess.run(rsync_cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                self.log(f"Successfully deployed certificates to {host}")
                self.deployed_hosts.append(host)
                return True
            else:
                self.log(f"ERROR: Failed to deploy certificates to {host}")
                self.log(f"rsync error: {result.stderr}")
                return False
        except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
            self.log(f"ERROR: Failed to deploy certificates to {host}: {e}")
            return False
    
    def generate_service_certificates(self) -> None:
        """Generate service-specific certificates"""
        self.log("Generating service-specific certificates")
        
        # Generate Plex PKCS12 certificate
        if self.config.plex_cert_enabled:
            self.log("Generating Plex PKCS12 certificate")
            plex_cert_path = os.path.join(self.config.cert_dir, 'plex-certificate.pfx')
            
            if self.dry_run:
                self.log(f"Would generate Plex certificate: {plex_cert_path}")
            else:
                openssl_cmd = [
                    'openssl', 'pkcs12', '-export', '-out', plex_cert_path,
                    '-inkey', os.path.join(self.config.cert_dir, 'privkey.pem'),
                    '-in', os.path.join(self.config.cert_dir, 'cert.pem'),
                    '-certfile', os.path.join(self.config.cert_dir, 'fullchain.pem'),
                    '-passout', f'pass:{self.config.plex_cert_password}'
                ]
                
                try:
                    subprocess.run(openssl_cmd, check=True, capture_output=True)
                    os.chmod(plex_cert_path, 0o755)
                    self.log("Generated Plex certificate")
                    self.local_cert_changed = True
                except subprocess.SubprocessError as e:
                    self.log(f"ERROR: Failed to generate Plex certificate: {e}")
        
        # Generate ZNC certificate
        if self.config.znc_cert_enabled:
            self.log("Generating ZNC certificate")
            znc_cert_path = os.path.join(self.config.cert_dir, 'znc.pem')
            
            if self.dry_run:
                self.log(f"Would generate ZNC certificate: {znc_cert_path}")
            else:
                try:
                    with open(znc_cert_path, 'w') as znc_file:
                        # Concatenate private key and full chain
                        with open(os.path.join(self.config.cert_dir, 'privkey.pem'), 'r') as f:
                            znc_file.write(f.read())
                        with open(os.path.join(self.config.cert_dir, 'fullchain.pem'), 'r') as f:
                            znc_file.write(f.read())
                        
                        # Add DH parameters if file exists
                        if self.config.znc_dhparam_file and os.path.isfile(self.config.znc_dhparam_file):
                            with open(self.config.znc_dhparam_file, 'r') as f:
                                znc_file.write(f.read())
                    
                    self.log("Generated ZNC certificate")
                    self.local_cert_changed = True
                except IOError as e:
                    self.log(f"ERROR: Failed to generate ZNC certificate: {e}")
    
    def restart_services(self) -> None:
        """Restart services on remote hosts with reload fallback"""
        self.log("Processing service restarts")
        
        if not self.config.host_services:
            self.log("No HOST_SERVICES configured, skipping service restarts")
            return
        
        if not self.deployed_hosts:
            self.log("No certificates were deployed, skipping service restarts")
            return
        
        for host_config in self.config.host_services:
            # Parse host:port:services format
            parts = host_config.split(':', 2)
            if len(parts) != 3:
                self.log(f"ERROR: Invalid HOST_SERVICES format: {host_config}")
                continue
            
            host, port_str, services = parts
            try:
                port = int(port_str)
            except ValueError:
                self.log(f"ERROR: Invalid port in HOST_SERVICES: {port_str}")
                continue
            
            # Check if this host had certificates deployed
            if host not in self.deployed_hosts:
                self.log(f"Skipping service restart on {host} (certificates not deployed)")
                continue
            
            if self.dry_run:
                self.log(f"Would restart services on {host}:{port} - {services}")
                continue
            
            self.log(f"Restarting services on {host}: {services}")
            
            # Build systemctl command with reload fallback
            service_list = services.split(',')
            service_commands = []
            
            for service in service_list:
                service = service.strip()
                # Try reload first, fallback to restart
                service_commands.append(f"(systemctl reload {service} || systemctl restart {service})")
            
            # Join commands with &&
            full_command = " && ".join(service_commands)
            ssh_cmd = self.build_ssh_command(host, port, full_command)
            
            try:
                result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    self.log(f"Successfully restarted services on {host}")
                else:
                    self.log(f"WARNING: Failed to restart services on {host}")
                    if result.stderr:
                        self.log(f"Error output: {result.stderr.strip()}")
            except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
                self.log(f"WARNING: Failed to restart services on {host}: {e}")
    
    def update_proxmox(self) -> None:
        """Update certificates on Proxmox VE nodes using REST API"""
        if not self.config.proxmox_user or not self.config.proxmox_token:
            self.log("Proxmox credentials not configured, skipping Proxmox updates")
            return
        
        if not self.config.proxmox_nodes:
            self.log("No Proxmox nodes configured, skipping Proxmox updates")
            return
        
        self.log("Updating Proxmox certificates")
        
        # Read certificate files
        try:
            with open(os.path.join(self.config.cert_dir, 'privkey.pem'), 'r') as f:
                privkey = f.read()
            with open(os.path.join(self.config.cert_dir, 'fullchain.pem'), 'r') as f:
                fullchain = f.read()
        except IOError as e:
            self.log(f"ERROR: Failed to read certificate files: {e}")
            return
        
        # Parse Proxmox user format (user@realm!tokenid)
        import re
        match = re.match(r'^([^!]+)!(.+)$', self.config.proxmox_user)
        if not match:
            self.log("ERROR: PROXMOX_USER must be in 'user@realm!tokenid' format")
            return
        
        user_realm, token_id = match.groups()
        
        for node in self.config.proxmox_nodes:
            node_url = f"https://{node}.{self.config.domain}:8006"
            
            if self.dry_run:
                self.log(f"Would update Proxmox node {node} at {node_url}")
                continue
            
            # Check connectivity
            try:
                # Create SSL context that ignores certificate verification
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                req = urllib.request.Request(node_url, method='GET')
                with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
                    pass  # Just checking connectivity
            except (urllib.error.URLError, OSError):
                self.log(f"{node} unreachable, skipping")
                continue
            
            self.log(f"Updating {node} certificates")
            
            # Prepare API request
            api_url = f"{node_url}/api2/json/nodes/{node}/certificates/custom"
            
            # Prepare form data
            data = {
                'key': privkey,
                'certificates': fullchain,
                'restart': '1',
                'force': '1',
                'node': node
            }
            
            # URL encode the data
            encoded_data = urllib.parse.urlencode(data).encode('utf-8')
            
            # Create request
            req = urllib.request.Request(api_url, data=encoded_data, method='POST')
            req.add_header('Authorization', f'PVEAPIToken={user_realm}!{token_id}={self.config.proxmox_token}')
            req.add_header('Content-Type', 'application/x-www-form-urlencoded')
            
            try:
                with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
                    if response.status == 200:
                        self.log(f"Successfully updated {node} certificates")
                    else:
                        self.log(f"WARNING: {node} update failed with status {response.status}")
            except urllib.error.URLError as e:
                self.log(f"WARNING: {node} update failed: {e}")
    
    def secure_cert_permissions(self) -> None:
        """Secure certificate file permissions"""
        self.log("Checking and securing certificate directory permissions")
        
        if self.dry_run:
            self.log("Checking permissions in dry-run mode...")
        
        changes_needed = False
        
        # Secure certificate directory
        if os.path.isdir(self.config.cert_dir):
            stat_info = os.stat(self.config.cert_dir)
            current_perms = oct(stat_info.st_mode)[-3:]
            
            if current_perms != self.config.directory_permissions:
                if self.dry_run:
                    self.log(f"Would secure directory: {self.config.cert_dir} ({self.config.directory_permissions}, root:root)")
                else:
                    try:
                        os.chmod(self.config.cert_dir, int(self.config.directory_permissions, 8))
                        # Note: chown requires root privileges, so we'll skip it in Python for now
                        self.log(f"Secured directory: {self.config.cert_dir} ({self.config.directory_permissions})")
                    except OSError as e:
                        self.log(f"WARNING: Failed to secure directory permissions: {e}")
                changes_needed = True
            else:
                self.log(f"Directory permissions OK: {self.config.cert_dir} ({self.config.directory_permissions})")
        
        # Secure certificate files with configurable permissions
        cert_files = {
            'privkey.pem': self.config.privkey_permissions,
            'cert.pem': self.config.file_permissions, 
            'fullchain.pem': self.config.file_permissions,
            'chain.pem': self.config.file_permissions
        }
        
        for filename, expected_perms in cert_files.items():
            filepath = os.path.join(self.config.cert_dir, filename)
            if os.path.isfile(filepath):
                stat_info = os.stat(filepath)
                current_perms = oct(stat_info.st_mode)[-3:]
                
                if current_perms != expected_perms:
                    if self.dry_run:
                        self.log(f"Would secure file: {filename} ({expected_perms}, root:root)")
                    else:
                        try:
                            os.chmod(filepath, int(expected_perms, 8))
                            self.log(f"Secured file: {filename} ({expected_perms})")
                        except OSError as e:
                            self.log(f"WARNING: Failed to secure {filename}: {e}")
                    changes_needed = True
                else:
                    self.log(f"File permissions OK: {filename} ({expected_perms})")
        
        if not changes_needed:
            self.log("All certificate permissions already correct")
        elif not self.dry_run:
            self.log("Certificate directory permissions secured")
    
    def perform_backups(self) -> None:
        """Backup certificates and configurations"""
        self.log(f"Backing up certificates to {self.config.backup_host}")
        
        if self.dry_run:
            self.log(f"Would backup certificates to {self.config.backup_host}:{self.config.ssl_backup_dir}")
            if os.path.isdir('/etc/nginx'):
                self.log(f"Would backup nginx configs to {self.config.backup_host}:{self.config.nginx_backup_dir}")
            return
        
        # Backup SSL certificates
        rsync_ssh = f"ssh {self.config.ssh_opts}"
        rsync_cmd = [
            'rsync', '-aL', '-e', rsync_ssh,
            f'{self.config.cert_dir}/',
            f'root@{self.config.backup_host}.{self.config.domain}:{self.config.ssl_backup_dir}/'
        ]
        
        try:
            subprocess.run(rsync_cmd, check=True, capture_output=True, timeout=300)
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            self.log("WARNING: Certificate backup failed")
        
        # Backup nginx configs if directory exists
        if os.path.isdir('/etc/nginx'):
            rsync_cmd = [
                'rsync', '-aL', '--exclude', 'modules/*', '-e', rsync_ssh,
                '/etc/nginx/',
                f'root@{self.config.backup_host}.{self.config.domain}:{self.config.nginx_backup_dir}/'
            ]
            
            try:
                subprocess.run(rsync_cmd, check=True, capture_output=True, timeout=300)
            except (subprocess.SubprocessError, subprocess.TimeoutExpired):
                self.log("WARNING: Nginx config backup failed")
    
    def reload_local_nginx(self) -> None:
        """Reload local nginx if certificates changed"""
        if self.local_cert_changed:
            self.log("Reloading local nginx")
            if self.dry_run:
                self.log("Would reload local nginx")
            else:
                try:
                    subprocess.run(['systemctl', 'reload', 'nginx'], 
                                 check=True, capture_output=True, timeout=30)
                except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
                    self.log(f"WARNING: Failed to reload nginx: {e}")
        else:
            self.log("Skipping local nginx reload (certificates unchanged)")
    
    def run(self) -> None:
        """Main execution logic"""
        # Special mode: permissions-fix only
        if self.permissions_fix:
            self.log("Running in permissions-fix only mode")
            self.secure_cert_permissions()
            return
        
        # Validate certificate files exist (skip in services-only mode)
        if not self.services_only:
            required_files = ['privkey.pem', 'fullchain.pem', 'cert.pem']
            for filename in required_files:
                filepath = os.path.join(self.config.cert_dir, filename)
                if not os.path.isfile(filepath) or os.path.getsize(filepath) == 0:
                    self.log(f"ERROR: Certificate file missing or empty: {filepath}")
                    sys.exit(ExitCodes.CERT)
        
        # Certificate processing phase
        if not self.services_only and not self.proxmox_only and not self.permissions_fix:
            # Generate service certificates
            self.generate_service_certificates()
            
            # Secure permissions
            self.secure_cert_permissions()
            
            # Reload local nginx
            self.reload_local_nginx()
            
            # Backup operations
            self.perform_backups()
            
            # Deploy certificates to remote hosts
            failed_hosts = []
            for host in self.config.hosts:
                # Determine SSH port for this host
                port = 22  # Default port
                
                # Search for custom port in host_services
                for host_config in self.config.host_services:
                    parts = host_config.split(':', 2)
                    if len(parts) >= 2 and parts[0] == host:
                        try:
                            port = int(parts[1])
                            break
                        except ValueError:
                            pass  # Use default port if parsing fails
                
                if not self.deploy_to_host(host, port):
                    failed_hosts.append(host)
            
            # Set local cert changed flag if any hosts had certificates deployed
            if self.deployed_hosts:
                self.local_cert_changed = True
            
            # Handle deployment failures
            if failed_hosts:
                self.log(f"ERROR: Failed to deploy to hosts: {', '.join(failed_hosts)}")
                if not self.cert_only:
                    self.log("Continuing with service restarts despite deployment failures")
        
        # Service management phase
        if not self.cert_only:
            # Restart services (unless proxmox-only mode)
            if not self.proxmox_only:
                self.restart_services()
            
            # Update Proxmox nodes (unless services-only mode)
            if not self.services_only:
                self.update_proxmox()


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Certificate Spreader - Deploy Let's Encrypt certificates to multiple hosts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s                          # Use config.conf, deploy certs and restart services
    %(prog)s --dry-run               # Show what would be done
    %(prog)s --cert-only             # Deploy certificates only
    %(prog)s --services-only         # Restart services only
    %(prog)s --proxmox-only          # Update Proxmox certificates only
    %(prog)s --permissions-fix       # Fix certificate permissions only
    %(prog)s custom.conf --dry-run   # Use custom config in dry-run mode
        """
    )
    
    parser.add_argument('config_file', nargs='?', default='config.conf',
                       help='Configuration file (default: config.conf)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be done without making changes')
    parser.add_argument('--cert-only', action='store_true',
                       help='Only deploy certificates, skip service restarts')
    parser.add_argument('--services-only', action='store_true',
                       help='Only restart services, skip certificate deployment')
    parser.add_argument('--proxmox-only', action='store_true',
                       help='Only update Proxmox certificates, skip everything else')
    parser.add_argument('--permissions-fix', action='store_true',
                       help='Only fix certificate file permissions, skip everything else')
    
    args = parser.parse_args()
    
    # Validate exclusive flags
    exclusive_flags = sum([args.cert_only, args.services_only, args.proxmox_only, args.permissions_fix])
    if exclusive_flags > 1:
        print("ERROR: Only one of --cert-only, --services-only, --proxmox-only, or --permissions-fix can be used at a time", 
              file=sys.stderr)
        sys.exit(ExitCodes.USAGE)
    
    # Validate config file extension
    if not args.config_file.endswith('.conf'):
        print(f"Config file should have .conf extension: {args.config_file}", file=sys.stderr)
        sys.exit(ExitCodes.USAGE)
    
    print(f"Starting cert-spreader with arguments: {' '.join(sys.argv[1:])}")
    
    # Create and configure cert spreader
    spreader = CertSpreader(args.config_file)
    spreader.dry_run = args.dry_run
    spreader.cert_only = args.cert_only
    spreader.services_only = args.services_only
    spreader.proxmox_only = args.proxmox_only
    spreader.permissions_fix = args.permissions_fix
    
    try:
        # Load configuration
        spreader.load_config()
        
        # Start main processing
        spreader.log("=== Certificate Spreader Started ===")
        spreader.log(f"Mode: DRY_RUN={spreader.dry_run}, CERT_ONLY={spreader.cert_only}, "
                    f"SERVICES_ONLY={spreader.services_only}, PROXMOX_ONLY={spreader.proxmox_only}, "
                    f"PERMISSIONS_FIX={spreader.permissions_fix}")
        
        # Run main logic
        spreader.run()
        
        spreader.log("=== Certificate Spreader Completed Successfully ===")
        
    except KeyboardInterrupt:
        spreader.log("Certificate Spreader interrupted by user")
        sys.exit(ExitCodes.SUCCESS)
    except Exception as e:
        spreader.log(f"FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(ExitCodes.CONFIG)


if __name__ == "__main__":
    main()