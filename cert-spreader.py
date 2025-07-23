#!/usr/bin/env python3
"""
Certificate Spreader - Deploy SSL certificates to multiple hosts
Replaces plex-cert.sh and cert-deploy.sh with a more maintainable Python solution.

This script reads configuration from a YAML file and deploys SSL certificates
to multiple remote hosts, restarting/reloading services as needed.
"""

# Import statements - these bring in functionality from Python's standard library and third-party packages
import argparse          # For parsing command-line arguments (like --dry-run)
import concurrent.futures # For running multiple operations in parallel (threading)
import hashlib           # For creating SHA256 hashes of files to detect changes
import logging           # Python's built-in logging system (better than print statements)
import os                # For file system operations (checking if files exist, etc.)
import shutil            # For advanced file operations (not used here but good to have)
import subprocess        # For running shell commands (like ssh, rsync, curl)
import sys               # For system-specific parameters (like sys.exit())
import time              # For time-related operations (delays, timestamps)
from pathlib import Path # Modern way to handle file paths in Python
from typing import Dict, List, Optional, Tuple # Type hints to make code more readable

# Third-party imports - these need to be installed with pip
import requests          # For making HTTP requests (checking if Proxmox is reachable)
import yaml              # For parsing YAML configuration files


class CertificateSpreader:
    """
    Main class for certificate deployment operations.
    
    In Python, a 'class' is like a blueprint for creating objects.
    This class contains all the methods (functions) needed to deploy certificates.
    """
    
    def __init__(self, config_file: str = "config.yml"):
        """
        Initialize the CertificateSpreader object.
        
        This is called when you create a new instance: spreader = CertificateSpreader()
        The __init__ method sets up the object's initial state.
        
        Args:
            config_file: Path to the YAML configuration file (defaults to "config.yml")
        """
        # Store the config file path as an instance variable (self.config_file)
        self.config_file = config_file
        
        # Load and parse the configuration file into a Python dictionary
        self.config = self._load_config()
        
        # Set up the logging system based on config settings
        self.logger = self._setup_logging()
        
        # Initialize empty dictionaries to track deployment status and certificate hashes
        # Dict[str, str] means: dictionary with string keys and string values
        self.deploy_status: Dict[str, str] = {}
        self.original_cert_hashes: Dict[str, str] = {}
        
    def _load_config(self) -> dict:
        """
        Load configuration from YAML file and override with environment variables.
        
        This method loads the YAML config file and then checks for environment
        variables that can override sensitive values like tokens and passwords.
        
        Environment variables checked:
        - CERT_SPREADER_PROXMOX_USER
        - CERT_SPREADER_PROXMOX_TOKEN  
        - CERT_SPREADER_PLEX_PASSWORD
        - CERT_SPREADER_DOMAIN
        - CERT_SPREADER_USERNAME
        
        Returns:
            dict: The parsed configuration as a Python dictionary
        """
        try:
            # Open the config file and parse it as YAML
            # 'with open()' automatically closes the file when done, even if there's an error
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f)  # safe_load prevents dangerous code execution
        except FileNotFoundError:
            # If file doesn't exist, print error and exit the program
            print(f"Error: Configuration file {self.config_file} not found")
            sys.exit(1)  # Exit with error code 1 (non-zero means error)
        except yaml.YAMLError as e:
            # If YAML is malformed, print error and exit
            print(f"Error parsing configuration file: {e}")
            sys.exit(1)
            
        # Override sensitive config values with environment variables if they exist
        # This allows keeping secrets out of the config file
        
        # Proxmox credentials
        if 'CERT_SPREADER_PROXMOX_USER' in os.environ:
            config['proxmox_user'] = os.environ['CERT_SPREADER_PROXMOX_USER']
            
        if 'CERT_SPREADER_PROXMOX_TOKEN' in os.environ:
            config['proxmox_token'] = os.environ['CERT_SPREADER_PROXMOX_TOKEN']
            
        # Plex certificate password
        if 'CERT_SPREADER_PLEX_PASSWORD' in os.environ:
            if 'certificates' not in config:
                config['certificates'] = {}
            if 'plex' not in config['certificates']:
                config['certificates']['plex'] = {}
            config['certificates']['plex']['password'] = os.environ['CERT_SPREADER_PLEX_PASSWORD']
            
        # Other potentially sensitive settings
        if 'CERT_SPREADER_DOMAIN' in os.environ:
            config['domain'] = os.environ['CERT_SPREADER_DOMAIN']
            
        if 'CERT_SPREADER_USERNAME' in os.environ:
            config['username'] = os.environ['CERT_SPREADER_USERNAME']
            
        if 'CERT_SPREADER_CERT_DIR' in os.environ:
            config['certificate_dir'] = os.environ['CERT_SPREADER_CERT_DIR']
            
        return config
            
    def _setup_logging(self) -> logging.Logger:
        """
        Setup Python logging based on configuration.
        
        Python's logging module is much better than using print() statements
        because it allows different log levels (DEBUG, INFO, WARNING, ERROR)
        and can write to multiple destinations (console, file, syslog).
        
        Returns:
            logging.Logger: Configured logger instance
        """
        # Create a logger with a specific name
        logger = logging.getLogger('cert-spreader')
        
        # Get log level from config, default to 'INFO' if not specified
        # .get() safely retrieves dictionary values with a default fallback
        level_str = self.config.get('logging', {}).get('level', 'INFO')
        
        # Convert string level to logging constant (e.g., 'INFO' -> logging.INFO)
        # getattr gets an attribute from an object by name
        level = getattr(logging, level_str.upper(), logging.INFO)
        logger.setLevel(level)
        
        # Remove any existing handlers (in case this is called multiple times)
        logger.handlers.clear()
        
        # Create a formatter to control how log messages look
        formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] %(message)s',  # Format string
            datefmt='%Y-%m-%d %H:%M:%S'                   # Date format
        )
        
        # Create a console handler to print logs to the terminal
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # Create a file handler to write logs to a file
        log_file = self.config.get('logging', {}).get('file', '/var/log/cert-spreader.log')
        try:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except PermissionError:
            # If we can't write to the log file (permission denied), just warn and continue
            logger.warning(f"Cannot write to log file {log_file}, using console only")
        
        return logger
        
    def validate_certificates(self) -> bool:
        """
        Validate local certificates before deployment.
        
        This checks that all required certificate files exist and are valid
        before we try to deploy them to remote hosts.
        
        Returns:
            bool: True if certificates are valid, False if there are problems
        """
        # Path() creates a Path object for easier file manipulation
        cert_dir = Path(self.config['certificate_dir'])
        
        # List of certificate files that must exist
        required_files = ['privkey.pem', 'fullchain.pem', 'cert.pem']
        
        # Loop through each required file and check if it exists
        for filename in required_files:
            cert_file = cert_dir / filename  # The / operator joins paths
            
            # Check if file exists and has content (size > 0)
            if not cert_file.exists() or cert_file.stat().st_size == 0:
                self.logger.error(f"Certificate file missing or empty: {cert_file}")
                return False  # Return immediately if any file is missing
                
        # Check certificate validity using OpenSSL
        cert_file = cert_dir / 'cert.pem'
        try:
            # Run the openssl command to check certificate dates
            result = subprocess.run([
                'openssl', 'x509', '-noout', '-dates', '-in', str(cert_file)
            ], capture_output=True, text=True, check=True)
            
            # Parse the output to get certificate dates
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if 'notAfter' in line:
                    # Log when the certificate expires
                    self.logger.info(f"Certificate expiry: {line}")
                    
        except subprocess.CalledProcessError as e:
            # If openssl command fails, certificate is probably invalid
            self.logger.error(f"Certificate validation failed: {e}")
            return False
            
        self.logger.info("Certificate validation passed")
        return True
        
    def generate_service_certificates(self, dry_run: bool = False) -> bool:
        """
        Generate service-specific certificate files.
        
        Some services (like Plex) need certificates in special formats.
        This function creates those specialized certificate files.
        
        Args:
            dry_run: If True, just simulate the operation without actually doing it
            
        Returns:
            bool: True if successful, False if there were errors
        """
        cert_dir = Path(self.config['certificate_dir'])
        
        # If this is a dry run, just log what we would do and return
        if dry_run:
            self.logger.info("[DRY-RUN] Would generate service certificates")
            return True
            
        try:
            # Generate Plex PKCS12 certificate (if configured)
            # PKCS12 is a format that bundles private key and certificate together
            plex_config = self.config.get('certificates', {}).get('plex', {})
            if plex_config:  # Only do this if plex section exists in config
                plex_file = cert_dir / plex_config.get('filename', 'plex-certificate.pfx')
                password = plex_config.get('password', 'PASSWORD')
                
                # Build the openssl command as a list of arguments
                cmd = [
                    'openssl', 'pkcs12', '-export',           # Export to PKCS12 format
                    '-inkey', str(cert_dir / 'privkey.pem'),  # Input private key
                    '-in', str(cert_dir / 'cert.pem'),        # Input certificate
                    '-certfile', str(cert_dir / 'fullchain.pem'), # Certificate chain
                    '-out', str(plex_file),                   # Output file
                    '-passout', f'pass:{password}'            # Password for PKCS12 file
                ]
                
                # Run the command and check for errors
                subprocess.run(cmd, check=True, capture_output=True)
                
                # Set file permissions (0o755 = rwxr-xr-x in octal notation)
                os.chmod(plex_file, 0o755)
                self.logger.info(f"Generated Plex certificate: {plex_file}")
                
            # Generate ZNC certificate (if configured)
            # ZNC wants a concatenated file: private key + certificate chain + DH params
            znc_config = self.config.get('certificates', {}).get('znc', {})
            if znc_config:
                znc_file = cert_dir / znc_config.get('filename', 'znc.pem')
                
                # Open the output file for writing
                with open(znc_file, 'w') as f:
                    # Write private key first
                    with open(cert_dir / 'privkey.pem', 'r') as privkey:
                        f.write(privkey.read())
                    
                    # Write certificate chain
                    with open(cert_dir / 'fullchain.pem', 'r') as fullchain:
                        f.write(fullchain.read())
                    
                    # Write DH parameters if configured and file exists
                    if znc_config.get('include_dhparam', False):
                        dhparam_file = znc_config.get('dhparam_file', '/etc/nginx/ssl/dhparam.pem')
                        if os.path.exists(dhparam_file):
                            with open(dhparam_file, 'r') as dhparam:
                                f.write(dhparam.read())
                                
                self.logger.info(f"Generated ZNC certificate: {znc_file}")
                
        except subprocess.CalledProcessError as e:
            # If any subprocess (like openssl) fails, log error and return False
            self.logger.error(f"Failed to generate service certificates: {e}")
            return False
        except Exception as e:
            # Catch any other unexpected errors
            self.logger.error(f"Error generating service certificates: {e}")
            return False
            
        return True
        
    def reload_local_services(self, dry_run: bool = False) -> bool:
        """
        Reload local services after certificate generation.
        
        After we create new certificates, we need to reload services like nginx
        so they pick up the new certificates.
        
        Args:
            dry_run: If True, just simulate without actually reloading services
            
        Returns:
            bool: True if successful, False if there were errors
        """
        # Get the list of local services from config
        local_services = self.config.get('local_services', [])
        
        # Loop through each service configuration
        for service in local_services:
            service_name = service['name']  # Required: service name
            action = service.get('action', 'reload')  # Optional: action, defaults to 'reload'
            
            if dry_run:
                self.logger.info(f"[DRY-RUN] Would {action} local service: {service_name}")
                continue  # Skip to next service
                
            try:
                # First check if the service is actually running
                result = subprocess.run([
                    'systemctl', 'is-active', service_name
                ], capture_output=True, text=True)
                
                # If service is active (return code 0), reload/restart it
                if result.returncode == 0:
                    subprocess.run(['systemctl', action, service_name], check=True)
                    self.logger.info(f"Local service {action}ed: {service_name}")
                else:
                    # Service is not active, just warn (don't fail)
                    self.logger.warning(f"Local service not active: {service_name}")
                    
            except subprocess.CalledProcessError as e:
                # If systemctl command fails, log error and return False
                self.logger.error(f"Failed to {action} local service {service_name}: {e}")
                return False
                
        return True
        
    def _get_cert_hash(self, cert_path: str) -> str:
        """
        Get SHA256 hash of certificate file.
        
        We use hashes to detect if certificates have changed.
        If the hash is the same, we can skip deployment.
        
        Args:
            cert_path: Path to the certificate file
            
        Returns:
            str: SHA256 hash of the file, or "none" if file can't be read
        """
        try:
            # Open file in binary mode ('rb') and read all content
            with open(cert_path, 'rb') as f:
                # Create SHA256 hash of file content and return as hex string
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            # If we can't read the file for any reason, return "none"
            return "none"
            
    def _run_ssh_command(self, host: str, port: int, command: str) -> Tuple[bool, str]:
        """
        Execute SSH command on remote host.
        
        This is a helper function to run commands on remote hosts via SSH.
        
        Args:
            host: Hostname (without domain)
            port: SSH port number
            command: Shell command to run on remote host
            
        Returns:
            Tuple[bool, str]: (success, output) - success is True/False, output is command result
        """
        # Get SSH configuration from config file
        ssh_key = self.config.get('ssh', {}).get('key', '/root/.ssh/id_ed25519')
        ssh_opts = self.config.get('ssh', {}).get('opts', '').split()  # Split string into list
        domain = self.config['domain']
        
        # Build the SSH command as a list
        cmd = [
            'ssh', '-i', ssh_key, '-p', str(port)  # ssh -i keyfile -p port
        ] + ssh_opts + [  # Add additional SSH options from config
            f'root@{host}.{domain}', command  # user@hostname command
        ]
        
        try:
            # Run SSH command with timeout
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            # Return success status and output
            return result.returncode == 0, result.stdout.strip()
        except subprocess.TimeoutExpired:
            return False, "SSH command timed out"
        except Exception as e:
            return False, str(e)
            
    def deploy_to_host(self, hostname: str, dry_run: bool = False) -> str:
        """
        Deploy certificates to a single host.
        
        This function handles the deployment of certificates to one remote host.
        It includes checks for reachability, idempotency (don't deploy if unchanged),
        and post-deployment commands.
        
        Args:
            hostname: Name of the host to deploy to
            dry_run: If True, simulate without actually deploying
            
        Returns:
            str: Status of deployment ("success", "failed", "skipped", "dry-run")
        """
        # Get configuration for this specific host
        host_config = self.config['hosts'][hostname]
        port = host_config.get('port', 22)  # Default to port 22 if not specified
        domain = self.config['domain']
        cert_dir = self.config['certificate_dir']
        # Allow override of remote cert directory, default to same as local
        remote_cert_dir = self.config.get('remote_certificate_dir', cert_dir)
        
        self.logger.info(f"Deploying to {hostname}")
        
        # First, check if the host is reachable with ping
        ping_result = subprocess.run([
            'ping', '-c', '1', '-W', '2', f'{hostname}.{domain}'  # 1 ping, 2 second timeout
        ], capture_output=True)
        
        if ping_result.returncode != 0:
            self.logger.warning(f"Host {hostname} not reachable")
            return "failed"
            
        # Check for certificate changes (idempotency)
        # Get hash of local certificate
        local_hash = self._get_cert_hash(os.path.join(cert_dir, 'fullchain.pem'))
        
        # Get hash of remote certificate
        success, remote_hash = self._run_ssh_command(
            hostname, port, 
            f"sha256sum {remote_cert_dir}/fullchain.pem 2>/dev/null | cut -d' ' -f1"
        )
        
        # If remote hash matches local hash, certificate is unchanged
        if success and local_hash == remote_hash:
            self.logger.info(f"Skip {hostname} (certificate unchanged)")
            return "skipped"
            
        # If this is a dry run, just log what we would do
        if dry_run:
            self.logger.info(f"[DRY-RUN] Would rsync certificates to {hostname}")
            return "dry-run"
            
        # Create remote directory if it doesn't exist
        success, _ = self._run_ssh_command(hostname, port, f"mkdir -p {remote_cert_dir}")
        if not success:
            self.logger.error(f"Failed to create directory on {hostname}")
            return "failed"
            
        # Use rsync to copy certificates to remote host
        ssh_key = self.config.get('ssh', {}).get('key', '/root/.ssh/id_ed25519')
        rsync_cmd = [
            'rsync', '-aL',  # -a = archive mode, -L = follow symlinks
            '-e', f'ssh -i {ssh_key} -p {port}',  # Use SSH with specific key and port
            f'{cert_dir}/', f'root@{hostname}.{domain}:{remote_cert_dir}/'
        ]
        
        try:
            # Run rsync command
            subprocess.run(rsync_cmd, check=True, capture_output=True)
            self.logger.info(f"Certificates deployed to {hostname}")
            
            # Run post-deploy commands if configured
            # Some hosts need special commands after certificate deployment
            post_commands = host_config.get('post_deploy_commands', [])
            for command in post_commands:
                success, output = self._run_ssh_command(hostname, port, command)
                if success:
                    self.logger.info(f"Post-deploy command completed on {hostname}: {command}")
                else:
                    self.logger.warning(f"Post-deploy command failed on {hostname}: {command}")
                    
            return "success"
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to deploy certificates to {hostname}: {e}")
            return "failed"
            
    def restart_services(self, hostname: str, dry_run: bool = False) -> bool:
        """
        Restart/reload services on a host.
        
        After deploying new certificates, services need to be restarted or reloaded
        to pick up the new certificates.
        
        Args:
            hostname: Name of the host
            dry_run: If True, simulate without actually restarting services
            
        Returns:
            bool: True if successful, False if there were errors
        """
        # Get configuration for this host
        host_config = self.config['hosts'][hostname]
        port = host_config.get('port', 22)
        services = host_config.get('services', [])  # List of services to restart
        
        # If no services configured, nothing to do
        if not services:
            return True
            
        self.logger.info(f"Processing services on {hostname}")
        
        commands = []  # Build list of systemctl commands
        
        # Build systemctl commands for each service
        for service in services:
            service_name = service['name']
            action = service.get('action', 'reload')  # Default to reload
            
            if dry_run:
                self.logger.info(f"[DRY-RUN] Would {action} {service_name} on {hostname}")
                continue
                
            commands.append(f"systemctl {action} {service_name}")
            
        # If dry run or no commands, return early
        if dry_run or not commands:
            return True
            
        # Join all commands with && so they all run (and stop if any fails)
        full_command = " && ".join(commands)
        success, output = self._run_ssh_command(hostname, port, full_command)
        
        if success:
            self.logger.info(f"Services restarted successfully on {hostname}")
            return True
        else:
            self.logger.error(f"Failed to restart services on {hostname}: {output}")
            return False
            
    def update_proxmox_certificates(self, dry_run: bool = False) -> bool:
        """
        Update Proxmox certificates using curl commands.
        
        Proxmox VE has a REST API for updating certificates. This function
        uses curl (via subprocess) to post certificates to each Proxmox node.
        The curl commands are preserved exactly as they work in the shell script.
        
        Args:
            dry_run: If True, simulate without actually updating certificates
            
        Returns:
            bool: True if successful, False if there were errors
        """
        cert_dir = Path(self.config['certificate_dir'])
        
        # Read certificate content into memory
        try:
            with open(cert_dir / 'privkey.pem', 'r') as f:
                privkey = f.read()
            with open(cert_dir / 'fullchain.pem', 'r') as f:
                fullchain = f.read()
        except Exception as e:
            self.logger.error(f"Failed to read certificates: {e}")
            return False
            
        # Get Proxmox credentials from config
        user = self.config['proxmox_user']
        token = self.config['proxmox_token']
        nodes = self.config.get('proxmox', {}).get('nodes', {})
        
        # Parse user format (user@realm!tokenid)
        # Proxmox API tokens have a specific format
        if '!' not in user:
            self.logger.error("Proxmox user must be in 'user@realm!tokenid' format")
            return False
            
        # Split user string into user@realm and tokenid parts
        user_realm, token_id = user.split('!', 1)
        
        # Process each Proxmox node
        for node_name, node_config in nodes.items():
            url = node_config['url']
            # Build API URL for certificate upload
            api_url = f"{url}/api2/json/nodes/{node_name}/certificates/custom"
            
            if dry_run:
                self.logger.info(f"[DRY-RUN] Would update Proxmox {node_name} certificates")
                self.deploy_status[node_name] = "dry-run"
                continue
                
            # Check if Proxmox node is reachable
            try:
                # Simple HTTP request to check if node responds
                response = requests.get(url, timeout=5, verify=False)  # verify=False for self-signed certs
            except Exception:
                self.logger.warning(f"Proxmox {node_name} unreachable, skipping")
                self.deploy_status[node_name] = "failed"
                continue
                
            # Prepare curl command (preserving original working command structure)
            # This is exactly the same curl command that works in the shell script
            curl_cmd = [
                'curl', '--connect-timeout', '30', '-v', '-k', '-X', 'POST', api_url,
                '-H', f'Authorization: PVEAPIToken={user_realm}!{token_id}={token}',
                '-H', 'Content-Type: application/x-www-form-urlencoded',
                '--data-urlencode', f'key={privkey}',
                '--data-urlencode', 'restart=1',     # Tell Proxmox to restart services
                '--data-urlencode', 'force=1',       # Force certificate replacement
                '--data-urlencode', f'node={node_name}',
                '--data-urlencode', f'certificates={fullchain}'
            ]
            
            try:
                # Execute curl command
                result = subprocess.run(curl_cmd, capture_output=True, text=True, check=True)
                self.logger.info(f"Proxmox {node_name} certificates updated successfully")
                self.deploy_status[node_name] = "success"
                
                # Log to system logger for compatibility with existing monitoring
                subprocess.run([
                    'logger', '-t', 'cert-spreader', 
                    f"Proxmox {node_name} certificate update completed"
                ], capture_output=True)
                
            except subprocess.CalledProcessError as e:
                # If curl fails, log the error
                self.logger.error(f"Failed to update Proxmox {node_name}: {e.stderr}")
                self.deploy_status[node_name] = "failed"
                
                # Log error to system logger
                subprocess.run([
                    'logger', '-t', 'cert-spreader',
                    f"Proxmox {node_name} certificate update failed: {e.stderr}"
                ], capture_output=True)
                
        return True
        
    def deploy_all(self, dry_run: bool = False, deploy_only: bool = False, 
                   services_only: bool = False) -> bool:
        """
        Deploy certificates to all configured hosts.
        
        This is the main deployment function that coordinates deployment to all hosts.
        It handles the backup host specially (deploys there first), then deploys to
        all other hosts in parallel for speed.
        
        Args:
            dry_run: If True, simulate without making changes
            deploy_only: If True, deploy certificates but don't restart services
            services_only: If True, only restart services, don't deploy certificates
            
        Returns:
            bool: True if successful, False if there were errors
        """
        hosts = self.config.get('hosts', {})
        backup_host = self.config.get('backup', {}).get('host')
        max_parallel = self.config.get('deployment', {}).get('max_parallel', 5)
        
        # Deploy to backup host first (if configured)
        # The backup host is special because we also do backup operations there
        if backup_host and backup_host in hosts:
            self.deploy_status[backup_host] = self.deploy_to_host(backup_host, dry_run)
            
            # Handle backup operations if backup host deployment succeeded
            if not dry_run and self.deploy_status[backup_host] in ['success', 'skipped']:
                self._handle_backup_operations(backup_host)
                
        # Get list of remaining hosts (all except backup host)
        remaining_hosts = [h for h in hosts.keys() if h != backup_host]
        
        # Deploy certificates to remaining hosts (unless services-only mode)
        if not services_only:
            # Use ThreadPoolExecutor for parallel deployment
            # This allows us to deploy to multiple hosts simultaneously
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_parallel) as executor:
                # Submit deployment jobs to the thread pool
                future_to_host = {
                    executor.submit(self.deploy_to_host, host, dry_run): host 
                    for host in remaining_hosts
                }
                
                # Wait for each deployment to complete and collect results
                for future in concurrent.futures.as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        self.deploy_status[host] = future.result()
                    except Exception as e:
                        self.logger.error(f"Exception deploying to {host}: {e}")
                        self.deploy_status[host] = "failed"
                        
        # Restart services (unless deploy-only mode)
        if not deploy_only:
            # Use ThreadPoolExecutor for parallel service restarts
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_parallel) as executor:
                futures = []
                # Only restart services on hosts where deployment succeeded
                for host in hosts.keys():
                    if self.deploy_status.get(host) == "success":
                        future = executor.submit(self.restart_services, host, dry_run)
                        futures.append(future)
                        
                # Wait for all service restarts to complete
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        self.logger.error(f"Exception restarting services: {e}")
                        
        return True
        
    def _handle_backup_operations(self, backup_host: str):
        """
        Handle backup operations to the backup host.
        
        This function backs up SSL certificates and nginx configs to a central location.
        It's called after successfully deploying to the backup host.
        
        Args:
            backup_host: Name of the backup host
        """
        backup_config = self.config.get('backup', {})
        ssl_backup_dir = backup_config.get('ssl_backup_dir')
        nginx_backup_dir = backup_config.get('nginx_backup_dir')
        domain = self.config['domain']
        cert_dir = self.config['certificate_dir']
        username = self.config.get('username', 'root')
        
        ssh_key = self.config.get('ssh', {}).get('key', '/root/.ssh/id_ed25519')
        
        try:
            # Create backup directories on remote host
            self._run_ssh_command(backup_host, 22, f"mkdir -p {ssl_backup_dir} {nginx_backup_dir}")
            
            # Backup SSL certificates
            if ssl_backup_dir:
                rsync_cmd = [
                    'rsync', '-pEvaLu',  # Preserve permissions, verbose, archive, update only
                    '-e', f'ssh -i {ssh_key}',  # Use SSH with specific key
                    f'{cert_dir}/', f'root@{backup_host}.{domain}:{ssl_backup_dir}/'
                ]
                subprocess.run(rsync_cmd, check=True, capture_output=True)
                self.logger.info(f"SSL certificates backed up to {backup_host}")
                
            # Backup nginx configs (if nginx directory exists)
            if nginx_backup_dir and os.path.exists('/etc/nginx'):
                rsync_cmd = [
                    'rsync', '-pEvaLu', '--exclude', 'modules/*',  # Exclude modules directory
                    '-e', f'ssh -i {ssh_key}',
                    '/etc/nginx/', f'root@{backup_host}.{domain}:{nginx_backup_dir}/'
                ]
                subprocess.run(rsync_cmd, check=True, capture_output=True)
                self.logger.info(f"Nginx configs backed up to {backup_host}")
                
            # Set proper ownership on backed up files
            self._run_ssh_command(
                backup_host, 22,
                f"chown -R {username}:{username} {ssl_backup_dir} {nginx_backup_dir}"
            )
            
        except Exception as e:
            # Backup failure is not critical, just warn
            self.logger.warning(f"Backup operations failed: {e}")
            
    def print_summary(self):
        """
        Print deployment summary.
        
        This function provides a summary of what happened during deployment,
        showing how many hosts were successful, failed, skipped, etc.
        """
        # Count hosts in each status category
        deployed = sum(1 for status in self.deploy_status.values() if status == "success")
        skipped = sum(1 for status in self.deploy_status.values() if status == "skipped")
        dry_run = sum(1 for status in self.deploy_status.values() if status == "dry-run")
        failed = sum(1 for status in self.deploy_status.values() if status == "failed")
        
        # Log and print summary
        self.logger.info(f"SUMMARY: deployed={deployed} skipped={skipped} dry-run={dry_run} failed={failed}")
        print(f"[SUMMARY] Deployed: {deployed}, Skipped: {skipped}, Dry-run: {dry_run}, Failed: {failed}")
        
        # If there were failures, list the failed hosts
        if failed > 0:
            failed_hosts = [host for host, status in self.deploy_status.items() if status == "failed"]
            self.logger.warning(f"Failed hosts: {' '.join(failed_hosts)}")
            print(f"[FAILURES] Hosts with errors: {' '.join(failed_hosts)}")
            
        # Print individual host status for debugging
        for host, status in self.deploy_status.items():
            self.logger.info(f"{host} status: {status}")


def main():
    """
    Main entry point for the script.
    
    This function is called when the script is run from the command line.
    It handles command-line argument parsing and coordinates the overall operation.
    """
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Deploy SSL certificates to multiple hosts")
    
    # Define all the command-line options
    parser.add_argument('--config', '-c', default='config.yml', 
                       help='Configuration file path (default: config.yml)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Simulate deployment without making changes')
    parser.add_argument('--deploy-only', action='store_true',
                       help='Deploy certificates but skip service restarts')
    parser.add_argument('--services-only', action='store_true',
                       help='Skip certificate deployment, only restart services')
    parser.add_argument('--skip-validation', action='store_true',
                       help='Skip certificate validation checks')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    # Parse the command-line arguments
    args = parser.parse_args()
    
    try:
        # Create the main CertificateSpreader object
        spreader = CertificateSpreader(args.config)
        
        # Enable debug logging if verbose flag is set
        if args.verbose:
            spreader.logger.setLevel(logging.DEBUG)
            
        spreader.logger.info("=== Certificate Spreader Started ===")
        
        # Validate certificates (unless --skip-validation is used)
        if not args.skip_validation and not spreader.validate_certificates():
            spreader.logger.error("Certificate validation failed")
            return 1  # Return error code 1
            
        # Generate service-specific certificates (like Plex PKCS12)
        if not spreader.generate_service_certificates(args.dry_run):
            spreader.logger.error("Failed to generate service certificates")
            return 1
            
        # Reload local services (like nginx)
        if not spreader.reload_local_services(args.dry_run):
            spreader.logger.error("Failed to reload local services")
            return 1
            
        # Deploy to all configured hosts
        if not spreader.deploy_all(args.dry_run, args.deploy_only, args.services_only):
            spreader.logger.error("Deployment failed")
            return 1
            
        # Update Proxmox certificates (unless --deploy-only is used)
        if not args.deploy_only:
            if not spreader.update_proxmox_certificates(args.dry_run):
                spreader.logger.error("Proxmox certificate update failed")
                return 1
                
        # Print summary of what happened
        spreader.print_summary()
        spreader.logger.info("=== Certificate Spreader Completed ===")
        
        return 0  # Return success code 0
        
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print("\nOperation cancelled by user")
        return 130  # Standard exit code for SIGINT
    except Exception as e:
        # Handle any unexpected errors
        print(f"Unexpected error: {e}")
        return 1


# This is a Python idiom that means "run main() only if this script is executed directly"
# (not if it's imported as a module by another script)
if __name__ == '__main__':
    sys.exit(main())  # Exit with the return code from main()