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
import requests
import pwd
import grp
from typing import List, Optional, Tuple
from dataclasses import dataclass, field


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
    ssh_opts: str = "-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"
    log_file: str = "/var/log/cert-spreader.log"
    hosts: List[str] = field(default_factory=list)
    host_services: List[str] = field(default_factory=list)
    proxmox_nodes: List[str] = field(default_factory=list)
    proxmox_user: str = ""
    proxmox_token: str = ""
    proxmox_verify_ssl: bool = False  # Default to False for self-signed Proxmox certs
    # Custom certificate generation configuration
    custom_certificates: List[str] = field(default_factory=list)
    # Backward compatibility settings
    pkcs12_enabled: bool = False
    pkcs12_password: str = ""
    pkcs12_filename: str = "certificate.pfx"
    concatenated_enabled: bool = False
    concatenated_dhparam_file: str = ""
    concatenated_filename: str = "combined.pem"
    # File permission configuration
    file_permissions: str = "644"        # Default permissions for certificate files
    privkey_permissions: str = "600"     # More restrictive permissions for private key
    directory_permissions: str = "755"   # Directory permissions
    file_owner: str = "root"             # Default file owner
    file_group: str = "root"             # Default file group


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
            echo "SSH_OPTS=${{SSH_OPTS:-}}"
            echo "LOG_FILE=${{LOG_FILE:-}}"
            echo "HOSTS=${{HOSTS:-}}"
            echo "PROXMOX_USER=${{PROXMOX_USER:-}}"
            echo "PROXMOX_TOKEN=${{PROXMOX_TOKEN:-}}"
            echo "PROXMOX_VERIFY_SSL=${{PROXMOX_VERIFY_SSL:-false}}"
            echo "PKCS12_ENABLED=${{PKCS12_ENABLED:-false}}"
            echo "PKCS12_PASSWORD=${{PKCS12_PASSWORD:-}}"
            echo "PKCS12_FILENAME=${{PKCS12_FILENAME:-certificate.pfx}}"
            echo "CONCATENATED_ENABLED=${{CONCATENATED_ENABLED:-false}}"
            echo "CONCATENATED_DHPARAM_FILE=${{CONCATENATED_DHPARAM_FILE:-}}"
            echo "CONCATENATED_FILENAME=${{CONCATENATED_FILENAME:-combined.pem}}"
            echo "FILE_PERMISSIONS=${{FILE_PERMISSIONS:-644}}"
            echo "PRIVKEY_PERMISSIONS=${{PRIVKEY_PERMISSIONS:-600}}"
            echo "DIRECTORY_PERMISSIONS=${{DIRECTORY_PERMISSIONS:-755}}"
            echo "FILE_OWNER=${{FILE_OWNER:-root}}"
            echo "FILE_GROUP=${{FILE_GROUP:-root}}"
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
        self.config.ssh_opts = config_vars.get('SSH_OPTS', self.config.ssh_opts)
        self.config.log_file = config_vars.get('LOG_FILE', self.config.log_file)
        
        # Parse HOSTS string into list
        hosts_str = config_vars.get('HOSTS', '')
        self.config.hosts = hosts_str.split() if hosts_str else []
        
        # Parse Proxmox configuration
        self.config.proxmox_user = config_vars.get('PROXMOX_USER', '')
        self.config.proxmox_token = config_vars.get('PROXMOX_TOKEN', '')
        self.config.proxmox_verify_ssl = config_vars.get('PROXMOX_VERIFY_SSL', 'false').lower() == 'true'
        
        # Parse new certificate configuration
        self.config.pkcs12_enabled = config_vars.get('PKCS12_ENABLED', 'false').lower() == 'true'
        self.config.pkcs12_password = config_vars.get('PKCS12_PASSWORD', '')
        self.config.pkcs12_filename = config_vars.get('PKCS12_FILENAME', 'certificate.pfx')
        self.config.concatenated_enabled = config_vars.get('CONCATENATED_ENABLED', 'false').lower() == 'true'
        self.config.concatenated_dhparam_file = config_vars.get('CONCATENATED_DHPARAM_FILE', '')
        self.config.concatenated_filename = config_vars.get('CONCATENATED_FILENAME', 'combined.pem')
        
        
        # Parse permission configuration
        self.config.file_permissions = config_vars.get('FILE_PERMISSIONS', '644')
        self.config.privkey_permissions = config_vars.get('PRIVKEY_PERMISSIONS', '600')
        self.config.directory_permissions = config_vars.get('DIRECTORY_PERMISSIONS', '755')
        self.config.file_owner = config_vars.get('FILE_OWNER', 'root')
        self.config.file_group = config_vars.get('FILE_GROUP', 'root')
        
        # Parse arrays from extracted bash arrays
        self.config.host_services = arrays.get('HOST_SERVICES', [])
        self.config.proxmox_nodes = arrays.get('PROXMOX_NODES', [])
        self.config.custom_certificates = arrays.get('CUSTOM_CERTIFICATES', [])
        
        self._validate_config()
    
    def _validate_config(self) -> None:
        """Validate configuration values"""
        required_vars = ['domain', 'cert_dir', 'hosts']
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
    
    def _check_command_available(self, command: str) -> bool:
        """Check if a command is available in system PATH"""
        try:
            result = subprocess.run(
                ['which', command],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _check_keytool_available(self) -> bool:
        """Check if Java keytool is available and functional"""
        if not self._check_command_available('keytool'):
            return False
        
        try:
            # Test keytool with a simple command to verify it's functional
            result = subprocess.run(
                ['keytool', '-help'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
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
        """Generate custom certificates based on configuration"""
        self.log("Generating custom certificates")
        
        # Process array-based custom certificates first
        for cert_config in self.config.custom_certificates:
            self._generate_custom_certificate(cert_config)
        
        # Process individual configuration settings
        if self.config.pkcs12_enabled:
            self._generate_pkcs12_certificate(
                self.config.pkcs12_filename,
                self.config.pkcs12_password
            )
        
        if self.config.concatenated_enabled:
            self._generate_concatenated_certificate(
                self.config.concatenated_filename,
                self.config.concatenated_dhparam_file
            )
    
    def _generate_custom_certificate(self, cert_config: str) -> None:
        """Generate a custom certificate based on configuration string"""
        # Parse configuration: "type:param:filename"
        parts = cert_config.split(':', 2)
        if len(parts) < 1:
            self.log(f"ERROR: Invalid custom certificate config: {cert_config}")
            return
        
        cert_type = parts[0].lower()
        param = parts[1] if len(parts) > 1 else ''
        filename = parts[2] if len(parts) > 2 else self._get_default_filename(cert_type)
        
        # Certificate type dispatch table
        cert_generators = {
            'pkcs12': lambda: self._generate_pkcs12_certificate(filename, param),
            'concatenated': lambda: self._generate_concatenated_certificate(filename, param),
            'der': lambda: self._generate_der_certificate(filename),
            'pkcs7': lambda: self._generate_pkcs7_certificate(filename),
            'p7b': lambda: self._generate_pkcs7_certificate(filename),  # Alias for pkcs7
            'crt': lambda: self._generate_crt_certificate(filename),
            'pem': lambda: self._generate_pem_certificate(filename),
            'bundle': lambda: self._generate_bundle_certificate(filename),
            'jks': lambda: self._generate_jks_certificate(filename, param)
        }
        
        generator = cert_generators.get(cert_type)
        if generator:
            generator()
        else:
            self.log(f"ERROR: Unknown certificate type: {cert_type}")
            self.log(f"Supported types: {', '.join(cert_generators.keys())}")
    
    def _get_default_filename(self, cert_type: str) -> str:
        """Get default filename for certificate type"""
        defaults = {
            'pkcs12': 'certificate.pfx',
            'concatenated': 'combined.pem',
            'der': 'certificate.der',
            'pkcs7': 'certificate.p7b',
            'p7b': 'certificate.p7b',
            'crt': 'certificate.crt',
            'pem': 'certificate.pem',
            'bundle': 'ca-bundle.pem',
            'jks': 'certificate.jks'
        }
        return defaults.get(cert_type, f"certificate.{cert_type}")
    
    def _generate_pkcs12_certificate(self, filename: str, password: str = None) -> None:
        """Generate PKCS12/PFX certificate"""
        self.log(f"Generating PKCS12 certificate: {filename}")
        cert_path = os.path.join(self.config.cert_dir, filename)
        
        if self.dry_run:
            self.log(f"Would generate PKCS12 certificate: {cert_path}")
            return
        
        # Build OpenSSL command
        openssl_cmd = [
            'openssl', 'pkcs12', '-export', '-out', cert_path,
            '-inkey', os.path.join(self.config.cert_dir, 'privkey.pem'),
            '-in', os.path.join(self.config.cert_dir, 'cert.pem'),
            '-certfile', os.path.join(self.config.cert_dir, 'fullchain.pem')
        ]
        
        # Add password if provided
        if password:
            openssl_cmd.extend(['-passout', f'pass:{password}'])
        else:
            openssl_cmd.extend(['-passout', 'pass:'])  # No password
        
        try:
            subprocess.run(openssl_cmd, check=True, capture_output=True)
            os.chmod(cert_path, 0o644)  # Use configurable permissions
            self.log(f"Generated PKCS12 certificate: {filename}")
            self.local_cert_changed = True
        except subprocess.SubprocessError as e:
            self.log(f"ERROR: Failed to generate PKCS12 certificate {filename}: {e}")
    
    def _generate_concatenated_certificate(self, filename: str, dhparam_file: str = '') -> None:
        """Generate concatenated certificate (private key + certificate + chain + optional DH params)"""
        self.log(f"Generating concatenated certificate: {filename}")
        cert_path = os.path.join(self.config.cert_dir, filename)
        
        if self.dry_run:
            self.log(f"Would generate concatenated certificate: {cert_path}")
            return
        
        try:
            with open(cert_path, 'w') as cert_file:
                # Concatenate private key and full chain
                with open(os.path.join(self.config.cert_dir, 'privkey.pem'), 'r') as f:
                    cert_file.write(f.read())
                with open(os.path.join(self.config.cert_dir, 'fullchain.pem'), 'r') as f:
                    cert_file.write(f.read())
                
                # Add DH parameters if file exists
                if dhparam_file and os.path.isfile(dhparam_file):
                    with open(dhparam_file, 'r') as f:
                        cert_file.write(f.read())
                    self.log(f"Added DH parameters from: {dhparam_file}")
            
            os.chmod(cert_path, 0o644)  # Use configurable permissions
            self.log(f"Generated concatenated certificate: {filename}")
            self.local_cert_changed = True
        except IOError as e:
            self.log(f"ERROR: Failed to generate concatenated certificate {filename}: {e}")
    
    def _generate_der_certificate(self, filename: str) -> None:
        """Generate DER certificate for Java/Android"""
        self.log(f"Generating DER certificate: {filename}")
        cert_path = os.path.join(self.config.cert_dir, filename)
        
        if self.dry_run:
            self.log(f"Would generate DER certificate: {cert_path}")
            return
        
        # Convert PEM to DER format
        openssl_cmd = [
            'openssl', 'x509', 
            '-in', os.path.join(self.config.cert_dir, 'cert.pem'),
            '-outform', 'der',
            '-out', cert_path
        ]
        
        try:
            subprocess.run(openssl_cmd, check=True, capture_output=True)
            os.chmod(cert_path, 0o644)
            self.log(f"Generated DER certificate: {filename}")
            self.local_cert_changed = True
        except subprocess.SubprocessError as e:
            self.log(f"ERROR: Failed to generate DER certificate {filename}: {e}")
    
    def _generate_pkcs7_certificate(self, filename: str) -> None:
        """Generate PKCS#7 certificate for Windows/Java trust chains"""
        self.log(f"Generating PKCS#7 certificate: {filename}")
        cert_path = os.path.join(self.config.cert_dir, filename)
        
        if self.dry_run:
            self.log(f"Would generate PKCS#7 certificate: {cert_path}")
            return
        
        # Create PKCS#7 certificate bundle
        openssl_cmd = [
            'openssl', 'crl2pkcs7',
            '-certfile', os.path.join(self.config.cert_dir, 'fullchain.pem'),
            '-out', cert_path,
            '-nocrl'
        ]
        
        try:
            subprocess.run(openssl_cmd, check=True, capture_output=True)
            os.chmod(cert_path, 0o644)
            self.log(f"Generated PKCS#7 certificate: {filename}")
            self.local_cert_changed = True
        except subprocess.SubprocessError as e:
            self.log(f"ERROR: Failed to generate PKCS#7 certificate {filename}: {e}")
    
    def _generate_crt_certificate(self, filename: str) -> None:
        """Generate individual CRT certificate file"""
        self.log(f"Generating CRT certificate: {filename}")
        cert_path = os.path.join(self.config.cert_dir, filename)
        
        if self.dry_run:
            self.log(f"Would generate CRT certificate: {cert_path}")
            return
        
        try:
            # Copy cert.pem to .crt file
            import shutil
            shutil.copy2(os.path.join(self.config.cert_dir, 'cert.pem'), cert_path)
            os.chmod(cert_path, 0o644)
            self.log(f"Generated CRT certificate: {filename}")
            self.local_cert_changed = True
        except IOError as e:
            self.log(f"ERROR: Failed to generate CRT certificate {filename}: {e}")
    
    def _generate_pem_certificate(self, filename: str) -> None:
        """Generate individual PEM certificate file"""
        self.log(f"Generating PEM certificate: {filename}")
        cert_path = os.path.join(self.config.cert_dir, filename)
        
        if self.dry_run:
            self.log(f"Would generate PEM certificate: {cert_path}")
            return
        
        try:
            # Copy fullchain.pem to custom filename
            import shutil
            shutil.copy2(os.path.join(self.config.cert_dir, 'fullchain.pem'), cert_path)
            os.chmod(cert_path, 0o644)
            self.log(f"Generated PEM certificate: {filename}")
            self.local_cert_changed = True
        except IOError as e:
            self.log(f"ERROR: Failed to generate PEM certificate {filename}: {e}")
    
    def _generate_bundle_certificate(self, filename: str) -> None:
        """Generate CA bundle certificate file"""
        self.log(f"Generating CA bundle certificate: {filename}")
        cert_path = os.path.join(self.config.cert_dir, filename)
        
        if self.dry_run:
            self.log(f"Would generate CA bundle certificate: {cert_path}")
            return
        
        try:
            # Copy chain.pem (CA bundle) to custom filename
            chain_path = os.path.join(self.config.cert_dir, 'chain.pem')
            if os.path.exists(chain_path):
                import shutil
                shutil.copy2(chain_path, cert_path)
                os.chmod(cert_path, 0o644)
                self.log(f"Generated CA bundle certificate: {filename}")
                self.local_cert_changed = True
            else:
                self.log(f"WARNING: chain.pem not found, cannot generate CA bundle: {filename}")
        except IOError as e:
            self.log(f"ERROR: Failed to generate CA bundle certificate {filename}: {e}")
    
    def _generate_jks_certificate(self, filename: str, password: str = None) -> None:
        """Generate JKS (Java KeyStore) certificate via PKCS#12 intermediate"""
        self.log(f"Generating JKS certificate: {filename}")
        
        cert_path = os.path.join(self.config.cert_dir, filename)
        
        if self.dry_run:
            self.log(f"Would generate JKS certificate: {cert_path}")
            return
        
        # Check keytool availability first
        if not self._check_keytool_available():
            self.log(f"ERROR: JKS generation requires Java keytool (install Java JDK/JRE)")
            self.log(f"Alternative: Generate PKCS#12 with 'pkcs12:{password}:{filename.replace('.jks', '.pfx')}' and convert manually")
            self.log(f"Conversion command: keytool -importkeystore -srckeystore {filename.replace('.jks', '.pfx')} -srcstoretype PKCS12 -destkeystore {filename} -deststoretype JKS")
            return
        
        if not password:
            self.log(f"ERROR: JKS certificates require a password. Use format: 'jks:password:{filename}'")
            return
        
        # Generate intermediate PKCS#12 file with secure temp name
        import tempfile
        import uuid
        with tempfile.NamedTemporaryFile(suffix='.p12', delete=False) as temp_p12_file:
            temp_p12_path = temp_p12_file.name
            temp_p12_name = os.path.basename(temp_p12_path)
        
        try:
            # Step 1: Generate PKCS#12 intermediate using existing method
            self.log(f"Creating intermediate PKCS#12 for JKS conversion")
            
            # Build OpenSSL command for PKCS#12 generation
            openssl_cmd = [
                'openssl', 'pkcs12', '-export',
                '-out', temp_p12_path,
                '-inkey', os.path.join(self.config.cert_dir, 'privkey.pem'),
                '-in', os.path.join(self.config.cert_dir, 'cert.pem'),
                '-certfile', os.path.join(self.config.cert_dir, 'fullchain.pem'),
                '-name', 'certificate',  # Default alias
                '-passout', f'pass:{password}'
            ]
            
            result = subprocess.run(openssl_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                self.log(f"ERROR: Failed to generate intermediate PKCS#12: {result.stderr}")
                return
            
            # Step 2: Convert PKCS#12 to JKS using keytool
            self.log(f"Converting PKCS#12 to JKS format")
            
            keytool_cmd = [
                'keytool', '-importkeystore',
                '-srckeystore', temp_p12_path,
                '-srcstoretype', 'PKCS12',  
                '-destkeystore', cert_path,
                '-deststoretype', 'JKS',
                '-srcalias', 'certificate',
                '-destalias', 'certificate',
                '-srcstorepass', password,
                '-deststorepass', password,
                '-noprompt'  # Don't prompt for confirmation
            ]
            
            result = subprocess.run(keytool_cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                self.log(f"ERROR: Failed to convert PKCS#12 to JKS: {result.stderr}")
                return
            
            # Set proper permissions
            os.chmod(cert_path, int(self.config.file_permissions, 8))
            
            # Set ownership if configured and running as root
            try:
                uid, gid = self._get_uid_gid()
                if uid != -1 and gid != -1:
                    os.chown(cert_path, uid, gid)
            except (OSError, PermissionError):
                pass  # Non-root execution, skip chown
            
            self.log(f"Generated JKS certificate: {filename}")
            self.local_cert_changed = True
            
        except subprocess.TimeoutExpired:
            self.log(f"ERROR: JKS generation timed out for {filename}")
        except subprocess.SubprocessError as e:
            self.log(f"ERROR: Failed to generate JKS certificate {filename}: {e}")
        except Exception as e:
            self.log(f"ERROR: Unexpected error generating JKS certificate {filename}: {e}")
        finally:
            # Always cleanup intermediate PKCS#12 file
            try:
                if os.path.exists(temp_p12_path):
                    os.remove(temp_p12_path)
                    self.log(f"Cleaned up intermediate file: {temp_p12_name}")
            except OSError as e:
                self.log(f"WARNING: Failed to cleanup intermediate file {temp_p12_name}: {e}")
    
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
                # Check connectivity with configurable SSL verification (default False for self-signed certs)
                response = requests.get(node_url, timeout=30, verify=self.config.proxmox_verify_ssl)
                # Just checking connectivity - any response (even error) means it's reachable
            except (requests.RequestException, OSError):
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
            
            # Prepare headers
            headers = {
                'Authorization': f'PVEAPIToken={user_realm}!{token_id}={self.config.proxmox_token}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            try:
                # Make POST request with configurable SSL verification
                # Default False for Proxmox environments with self-signed certificates
                # The API token provides authentication security
                response = requests.post(
                    api_url, 
                    data=data, 
                    headers=headers, 
                    timeout=30, 
                    verify=self.config.proxmox_verify_ssl
                )
                
                if response.status_code == 200:
                    self.log(f"Successfully updated {node} certificates")
                else:
                    self.log(f"WARNING: {node} update failed with status {response.status_code}")
                    self.log(f"Response: {response.text}")
            except requests.RequestException as e:
                self.log(f"WARNING: {node} update failed: {e}")
    
    def _get_uid_gid(self) -> Tuple[int, int]:
        """Get UID and GID for configured owner and group"""
        try:
            uid = pwd.getpwnam(self.config.file_owner).pw_uid
        except KeyError:
            self.log(f"WARNING: User '{self.config.file_owner}' not found, using current user")
            uid = os.getuid()
        
        try:
            gid = grp.getgrnam(self.config.file_group).gr_gid
        except KeyError:
            self.log(f"WARNING: Group '{self.config.file_group}' not found, using current group")
            gid = os.getgid()
        
        return uid, gid

    def secure_cert_permissions(self) -> None:
        """Secure certificate file permissions"""
        self.log("Checking and securing certificate directory permissions")
        
        if self.dry_run:
            self.log("Checking permissions in dry-run mode...")
        
        changes_needed = False
        uid, gid = self._get_uid_gid()
        
        # Secure certificate directory
        if os.path.isdir(self.config.cert_dir):
            stat_info = os.stat(self.config.cert_dir)
            current_perms = oct(stat_info.st_mode)[-3:]
            current_uid = stat_info.st_uid
            current_gid = stat_info.st_gid
            
            perms_need_change = current_perms != self.config.directory_permissions
            owner_needs_change = current_uid != uid or current_gid != gid
            
            if perms_need_change or owner_needs_change:
                if self.dry_run:
                    self.log(f"Would secure directory: {self.config.cert_dir} ({self.config.directory_permissions}, {self.config.file_owner}:{self.config.file_group})")
                else:
                    try:
                        if perms_need_change:
                            os.chmod(self.config.cert_dir, int(self.config.directory_permissions, 8))
                        if owner_needs_change:
                            os.chown(self.config.cert_dir, uid, gid)
                        self.log(f"Secured directory: {self.config.cert_dir} ({self.config.directory_permissions}, {self.config.file_owner}:{self.config.file_group})")
                    except OSError as e:
                        self.log(f"WARNING: Failed to secure directory permissions: {e}")
                changes_needed = True
            else:
                self.log(f"Directory permissions OK: {self.config.cert_dir} ({self.config.directory_permissions}, {self.config.file_owner}:{self.config.file_group})")
        
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
                current_uid = stat_info.st_uid
                current_gid = stat_info.st_gid
                
                perms_need_change = current_perms != expected_perms
                owner_needs_change = current_uid != uid or current_gid != gid
                
                if perms_need_change or owner_needs_change:
                    if self.dry_run:
                        self.log(f"Would secure file: {filename} ({expected_perms}, {self.config.file_owner}:{self.config.file_group})")
                    else:
                        try:
                            if perms_need_change:
                                os.chmod(filepath, int(expected_perms, 8))
                            if owner_needs_change:
                                os.chown(filepath, uid, gid)
                            self.log(f"Secured file: {filename} ({expected_perms}, {self.config.file_owner}:{self.config.file_group})")
                        except OSError as e:
                            self.log(f"WARNING: Failed to secure {filename}: {e}")
                    changes_needed = True
                else:
                    self.log(f"File permissions OK: {filename} ({expected_perms}, {self.config.file_owner}:{self.config.file_group})")
        
        # Secure custom certificate files
        self._secure_custom_certificate_files(uid, gid, changes_needed)
        
        if not changes_needed:
            self.log("All certificate permissions already correct")
        elif not self.dry_run:
            self.log("Certificate directory permissions secured")
    
    def _secure_custom_certificate_files(self, uid: int, gid: int, changes_needed: bool) -> bool:
        """Secure custom certificate files"""
        # Secure individual setting certificates
        custom_files = []
        
        if self.config.pkcs12_enabled:
            custom_files.append(self.config.pkcs12_filename)
        
        if self.config.concatenated_enabled:
            custom_files.append(self.config.concatenated_filename)
        
        # Extract filenames from custom certificate array
        for cert_config in self.config.custom_certificates:
            parts = cert_config.split(':', 2)
            if len(parts) >= 3:
                custom_files.append(parts[2])
            elif len(parts) >= 1:
                cert_type = parts[0].lower()
                custom_files.append(f"custom-{cert_type}.pem")
        
        # Secure each custom certificate file
        for filename in custom_files:
            filepath = os.path.join(self.config.cert_dir, filename)
            if os.path.isfile(filepath):
                stat_info = os.stat(filepath)
                current_perms = oct(stat_info.st_mode)[-3:]
                current_uid = stat_info.st_uid
                current_gid = stat_info.st_gid
                
                perms_need_change = current_perms != self.config.file_permissions
                owner_needs_change = current_uid != uid or current_gid != gid
                
                if perms_need_change or owner_needs_change:
                    if self.dry_run:
                        self.log(f"Would secure custom certificate: {filename} ({self.config.file_permissions}, {self.config.file_owner}:{self.config.file_group})")
                    else:
                        try:
                            if perms_need_change:
                                os.chmod(filepath, int(self.config.file_permissions, 8))
                            if owner_needs_change:
                                os.chown(filepath, uid, gid)
                            self.log(f"Secured custom certificate: {filename} ({self.config.file_permissions}, {self.config.file_owner}:{self.config.file_group})")
                        except OSError as e:
                            self.log(f"WARNING: Failed to secure custom certificate {filename}: {e}")
                    changes_needed = True
                else:
                    self.log(f"Custom certificate permissions OK: {filename} ({self.config.file_permissions}, {self.config.file_owner}:{self.config.file_group})")
        
        return changes_needed
    
    
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
    # Filter out spurious single-digit arguments that might come from shell redirection
    filtered_args = []
    for arg in sys.argv[1:]:
        if arg.isdigit() and len(arg) == 1:
            print(f"Warning: Ignoring spurious numeric argument: {arg}", file=sys.stderr)
            continue
        filtered_args.append(arg)
    
    # Temporarily replace sys.argv for argparse
    original_argv = sys.argv[1:]
    sys.argv[1:] = filtered_args
    
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
    
    print(f"Starting cert-spreader with arguments: {' '.join(original_argv)}")
    
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