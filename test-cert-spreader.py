#!/usr/bin/env python3
"""
Unit Tests for cert-spreader.py
This script provides comprehensive testing for the Python certificate spreader implementation.
"""

import unittest
import tempfile
import shutil
import os
import sys
import subprocess
import pwd
import grp
from pathlib import Path
from unittest.mock import patch, Mock, MagicMock
from io import StringIO

# Add the current directory to Python path to import cert-spreader
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__ if '__file__' in globals() else '.')))

# Import the modules we want to test
import importlib.util
spec = importlib.util.spec_from_file_location("cert_spreader", "cert-spreader.py")
cert_spreader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cert_spreader)

CertSpreader = cert_spreader.CertSpreader
Config = cert_spreader.Config
ExitCodes = cert_spreader.ExitCodes


class TestConfig(unittest.TestCase):
    """Test the Config dataclass"""
    
    def test_config_defaults(self):
        """Test that Config has proper default values"""
        config = Config()
        
        # Test basic defaults
        self.assertEqual(config.domain, "")
        self.assertEqual(config.cert_dir, "")
        self.assertEqual(config.ssh_opts, "-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new")
        self.assertEqual(config.log_file, "/var/log/cert-spreader.log")
        
        # Test arrays are initialized empty
        self.assertEqual(config.hosts, [])
        self.assertEqual(config.host_services, [])
        self.assertEqual(config.proxmox_nodes, [])
        
        # Test new certificate configuration defaults
        self.assertEqual(config.custom_certificates, [])
        self.assertFalse(config.pkcs12_enabled)
        self.assertEqual(config.pkcs12_password, "")
        self.assertEqual(config.pkcs12_filename, "certificate.pfx")
        self.assertFalse(config.concatenated_enabled)
        self.assertEqual(config.concatenated_dhparam_file, "")
        self.assertEqual(config.concatenated_filename, "combined.pem")
        
        # Test permission defaults
        self.assertEqual(config.file_permissions, "644")
        self.assertEqual(config.privkey_permissions, "600")
        self.assertEqual(config.directory_permissions, "755")
        
        # Test new owner/group defaults
        self.assertEqual(config.file_owner, "root")
        self.assertEqual(config.file_group, "root")
    
    def test_config_modification(self):
        """Test that Config values can be modified"""
        config = Config()
        config.domain = "test.example.com"
        config.hosts = ["host1", "host2"]
        config.file_owner = "nginx"
        config.file_group = "ssl-cert"
        
        self.assertEqual(config.domain, "test.example.com")
        self.assertEqual(config.hosts, ["host1", "host2"])
        self.assertEqual(config.file_owner, "nginx")
        self.assertEqual(config.file_group, "ssl-cert")


class TestCertSpreaderInit(unittest.TestCase):
    """Test CertSpreader initialization"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_config = os.path.join(self.temp_dir, "test-config.conf")
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_init_defaults(self):
        """Test CertSpreader initialization with defaults"""
        spreader = CertSpreader("nonexistent.conf")
        
        self.assertEqual(spreader.config_file, "nonexistent.conf")
        self.assertIsInstance(spreader.config, Config)
        self.assertFalse(spreader.dry_run)
        self.assertFalse(spreader.cert_only)
        self.assertFalse(spreader.services_only)
        self.assertFalse(spreader.proxmox_only)
        self.assertFalse(spreader.permissions_fix)
        self.assertEqual(spreader.deployed_hosts, [])
        self.assertFalse(spreader.local_cert_changed)
    
    def test_init_custom_config(self):
        """Test CertSpreader initialization with custom config file"""
        spreader = CertSpreader("custom.conf")
        self.assertEqual(spreader.config_file, "custom.conf")


class TestConfigurationLoading(unittest.TestCase):
    """Test configuration file loading"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_config = os.path.join(self.temp_dir, "test-config.conf")
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def create_test_config(self, content):
        """Helper to create test config file"""
        with open(self.test_config, 'w') as f:
            f.write(content)
    
    def test_missing_config_file(self):
        """Test behavior when config file doesn't exist"""
        spreader = CertSpreader("nonexistent.conf")
        
        with self.assertRaises(SystemExit) as cm:
            with patch('sys.stderr', new_callable=StringIO):
                spreader.load_config()
        
        self.assertEqual(cm.exception.code, ExitCodes.CONFIG)
    
    def test_basic_config_loading(self):
        """Test loading a basic configuration"""
        config_content = '''
DOMAIN="test.example.com"
CERT_DIR="/etc/letsencrypt/live/test.example.com"
HOSTS="host1 host2 host3"
HOST_SERVICES=(
    "host1:22:nginx"
    "host2:2222:apache2,mysql"
)
PROXMOX_NODES=(
    "proxmox1"
    "proxmox2"
)
PROXMOX_USER="test@pve!token"
PROXMOX_TOKEN="fake-token"
CUSTOM_CERTIFICATES=(
    "pkcs12:testpass:test-certificate.pfx"
    "concatenated:/etc/ssl/dhparam.pem:test-combined.pem"
)
PKCS12_ENABLED=true
PKCS12_PASSWORD="individual-password"
PKCS12_FILENAME="individual.pfx"
CONCATENATED_ENABLED=true
CONCATENATED_DHPARAM_FILE="/etc/ssl/dhparam2.pem"
CONCATENATED_FILENAME="individual.pem"
FILE_PERMISSIONS=640
PRIVKEY_PERMISSIONS=600
DIRECTORY_PERMISSIONS=750
FILE_OWNER=nginx
FILE_GROUP=ssl-cert
'''
        self.create_test_config(config_content)
        
        spreader = CertSpreader(self.test_config)
        
        # Mock the certificate directory existence for validation
        with patch('os.path.isdir', return_value=True), \
             patch('os.access', return_value=True):
            spreader.load_config()
        
        # Test basic configuration
        self.assertEqual(spreader.config.domain, "test.example.com")
        self.assertEqual(spreader.config.cert_dir, "/etc/letsencrypt/live/test.example.com")
        self.assertEqual(spreader.config.hosts, ["host1", "host2", "host3"])
        
        # Test arrays
        self.assertEqual(spreader.config.host_services, ["host1:22:nginx", "host2:2222:apache2,mysql"])
        self.assertEqual(spreader.config.proxmox_nodes, ["proxmox1", "proxmox2"])
        
        # Test new certificate configuration
        self.assertEqual(spreader.config.custom_certificates, 
                        ["pkcs12:testpass:test-certificate.pfx", "concatenated:/etc/ssl/dhparam.pem:test-combined.pem"])
        self.assertTrue(spreader.config.pkcs12_enabled)
        self.assertEqual(spreader.config.pkcs12_password, "individual-password")
        self.assertEqual(spreader.config.pkcs12_filename, "individual.pfx")
        self.assertTrue(spreader.config.concatenated_enabled)
        self.assertEqual(spreader.config.concatenated_dhparam_file, "/etc/ssl/dhparam2.pem")
        self.assertEqual(spreader.config.concatenated_filename, "individual.pem")
        
        # Test permission configuration
        self.assertEqual(spreader.config.file_permissions, "640")
        self.assertEqual(spreader.config.privkey_permissions, "600")
        self.assertEqual(spreader.config.directory_permissions, "750")
        
        # Test new owner/group configuration
        self.assertEqual(spreader.config.file_owner, "nginx")
        self.assertEqual(spreader.config.file_group, "ssl-cert")
    
    def test_missing_required_variables(self):
        """Test validation with missing required variables"""
        config_content = '''
DOMAIN="test.example.com"
# Missing CERT_DIR, HOSTS
'''
        self.create_test_config(config_content)
        
        spreader = CertSpreader(self.test_config)
        
        with self.assertRaises(SystemExit) as cm:
            with patch('sys.stderr', new_callable=StringIO):
                spreader.load_config()
        
        self.assertEqual(cm.exception.code, ExitCodes.VALIDATION)


class TestUtilityMethods(unittest.TestCase):
    """Test utility methods"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.spreader = CertSpreader("test.conf")
        self.spreader.config.domain = "test.example.com"
        self.spreader.config.ssh_opts = "-o ConnectTimeout=10"
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_is_valid_domain(self):
        """Test domain validation"""
        # Valid domains
        self.assertTrue(self.spreader._is_valid_domain("example.com"))
        self.assertTrue(self.spreader._is_valid_domain("sub.example.com"))
        self.assertTrue(self.spreader._is_valid_domain("test-site.co.uk"))
        
        # Invalid domains
        self.assertFalse(self.spreader._is_valid_domain(""))
        self.assertFalse(self.spreader._is_valid_domain("invalid"))
        self.assertFalse(self.spreader._is_valid_domain(".com"))
        self.assertFalse(self.spreader._is_valid_domain("example."))
    
    def test_calculate_cert_hash(self):
        """Test certificate hash calculation"""
        # Create a test certificate file
        test_cert = os.path.join(self.temp_dir, "test.pem")
        with open(test_cert, 'w') as f:
            f.write("fake certificate content")
        
        hash_result = self.spreader.calculate_cert_hash(test_cert)
        
        # Should return a 64-character hex string
        self.assertEqual(len(hash_result), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in hash_result))
        
        # Test with nonexistent file
        hash_result = self.spreader.calculate_cert_hash("/nonexistent/file.pem")
        self.assertEqual(hash_result, "none")
    
    def test_build_ssh_command(self):
        """Test SSH command building"""
        # Test with default port
        cmd = self.spreader.build_ssh_command("testhost")
        expected = ["ssh", "-o", "ConnectTimeout=10", "root@testhost.test.example.com"]
        self.assertEqual(cmd, expected)
        
        # Test with custom port
        cmd = self.spreader.build_ssh_command("testhost", 2222)
        expected = ["ssh", "-o", "ConnectTimeout=10", "-p", "2222", "root@testhost.test.example.com"]
        self.assertEqual(cmd, expected)
        
        # Test with command
        cmd = self.spreader.build_ssh_command("testhost", 22, "echo test")
        expected = ["ssh", "-o", "ConnectTimeout=10", "root@testhost.test.example.com", "echo test"]
        self.assertEqual(cmd, expected)


class TestOwnerGroupFunctionality(unittest.TestCase):
    """Test the new configurable owner/group functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.spreader = CertSpreader("test.conf")
        self.spreader.config.file_owner = "testuser"
        self.spreader.config.file_group = "testgroup"
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('pwd.getpwnam')
    @patch('grp.getgrnam')
    def test_get_uid_gid_valid_user_group(self, mock_getgrnam, mock_getpwnam):
        """Test UID/GID lookup with valid user and group"""
        # Mock user and group lookups
        mock_user = Mock()
        mock_user.pw_uid = 1001
        mock_getpwnam.return_value = mock_user
        
        mock_group = Mock()
        mock_group.gr_gid = 1002
        mock_getgrnam.return_value = mock_group
        
        uid, gid = self.spreader._get_uid_gid()
        
        self.assertEqual(uid, 1001)
        self.assertEqual(gid, 1002)
        mock_getpwnam.assert_called_once_with("testuser")
        mock_getgrnam.assert_called_once_with("testgroup")
    
    @patch('pwd.getpwnam')
    @patch('grp.getgrnam')
    @patch('os.getuid')
    @patch('os.getgid')
    def test_get_uid_gid_invalid_user_group(self, mock_getgid, mock_getuid, mock_getgrnam, mock_getpwnam):
        """Test UID/GID lookup with invalid user and group"""
        # Mock failed lookups
        mock_getpwnam.side_effect = KeyError("User not found")
        mock_getgrnam.side_effect = KeyError("Group not found")
        mock_getuid.return_value = 1000
        mock_getgid.return_value = 1000
        
        uid, gid = self.spreader._get_uid_gid()
        
        # Should fall back to current user/group
        self.assertEqual(uid, 1000)
        self.assertEqual(gid, 1000)
    
    @patch('os.path.isdir')
    @patch('os.stat')
    @patch('os.chmod')
    @patch('os.chown')
    def test_secure_cert_permissions_with_ownership(self, mock_chown, mock_chmod, mock_stat, mock_isdir):
        """Test certificate permission securing with ownership"""
        self.spreader.config.cert_dir = "/test/certs"
        self.spreader.config.directory_permissions = "755"
        self.spreader.config.file_permissions = "644"
        self.spreader.config.file_owner = "nginx"
        self.spreader.config.file_group = "ssl-cert"
        
        # Mock directory exists
        mock_isdir.return_value = True
        
        # Mock stat results for directory (needs permission and ownership change)
        mock_stat_result = Mock()
        mock_stat_result.st_mode = 0o750  # Different from desired 755
        mock_stat_result.st_uid = 0       # root
        mock_stat_result.st_gid = 0       # root
        mock_stat.return_value = mock_stat_result
        
        with patch.object(self.spreader, '_get_uid_gid', return_value=(33, 101)), \
             patch('os.path.isfile', return_value=False):  # No certificate files exist
            
            self.spreader.secure_cert_permissions()
            
            # Should change both permissions and ownership
            mock_chmod.assert_called_with("/test/certs", 0o755)
            mock_chown.assert_called_with("/test/certs", 33, 101)


class TestCommandLineArguments(unittest.TestCase):
    """Test command line argument parsing"""
    
    def test_main_function_help(self):
        """Test main function with help argument"""
        with patch('sys.argv', ['cert-spreader.py', '--help']):
            with self.assertRaises(SystemExit) as cm:
                with patch('sys.stdout', new_callable=StringIO):
                    from cert_spreader import main
                    main()
            
            # Help should exit with code 0
            self.assertEqual(cm.exception.code, 0)
    
    def test_main_function_invalid_args(self):
        """Test main function with invalid arguments"""
        with patch('sys.argv', ['cert-spreader.py', '--invalid-option']):
            with self.assertRaises(SystemExit) as cm:
                with patch('sys.stderr', new_callable=StringIO):
                    from cert_spreader import main
                    main()
            
            # Invalid args should exit with usage error
            self.assertEqual(cm.exception.code, ExitCodes.USAGE)
    
    def test_exclusive_flags(self):
        """Test exclusive flag validation"""
        # Test multiple exclusive flags
        with patch('sys.argv', ['cert-spreader.py', '--cert-only', '--services-only']):
            with self.assertRaises(SystemExit) as cm:
                with patch('sys.stderr', new_callable=StringIO):
                    from cert_spreader import main
                    main()
            
            self.assertEqual(cm.exception.code, ExitCodes.USAGE)


class TestDryRunMode(unittest.TestCase):
    """Test dry-run functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_config = os.path.join(self.temp_dir, "test-config.conf")
        self.test_cert_dir = os.path.join(self.temp_dir, "certs")
        os.makedirs(self.test_cert_dir)
        
        # Create test certificate files
        for filename in ["privkey.pem", "cert.pem", "fullchain.pem"]:
            with open(os.path.join(self.test_cert_dir, filename), 'w') as f:
                f.write(f"fake {filename} content")
        
        # Create test config
        config_content = f'''
DOMAIN="test.example.com"
CERT_DIR="{self.test_cert_dir}"
HOSTS="host1 host2"
'''
        with open(self.test_config, 'w') as f:
            f.write(config_content)
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_dry_run_mode_basic(self):
        """Test basic dry-run mode functionality"""
        spreader = CertSpreader(self.test_config)
        spreader.dry_run = True
        
        with patch('os.path.isdir', return_value=True), \
             patch('os.access', return_value=True):
            spreader.load_config()
        


class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_config = os.path.join(self.temp_dir, "test-config.conf")
        self.test_cert_dir = os.path.join(self.temp_dir, "certs")
        os.makedirs(self.test_cert_dir)
        
        # Create test certificate files
        for filename in ["privkey.pem", "cert.pem", "fullchain.pem"]:
            with open(os.path.join(self.test_cert_dir, filename), 'w') as f:
                f.write(f"fake {filename} content")
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_script_executable(self):
        """Test that the script can be executed"""
        script_path = os.path.join(os.path.dirname(__file__), "cert-spreader.py")
        
        # Test help output
        result = subprocess.run([sys.executable, script_path, "--help"], 
                              capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Usage:", result.stdout)
        
        # Test invalid config file
        result = subprocess.run([sys.executable, script_path, "nonexistent.conf", "--dry-run"], 
                              capture_output=True, text=True)
        self.assertEqual(result.returncode, ExitCodes.CONFIG)


class TestCustomCertificates(unittest.TestCase):
    """Test the new flexible certificate generation system"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_cert_dir = os.path.join(self.temp_dir, 'certs')
        self.test_config = os.path.join(self.temp_dir, 'test.conf')
        os.makedirs(self.test_cert_dir)
        
        # Create test certificate files
        for filename in ["privkey.pem", "cert.pem", "fullchain.pem"]:
            with open(os.path.join(self.test_cert_dir, filename), 'w') as f:
                f.write(f"fake {filename} content")
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_custom_certificate_array_parsing(self):
        """Test parsing of CUSTOM_CERTIFICATES array"""
        config_content = f'''
DOMAIN="test.example.com"
CERT_DIR="{self.test_cert_dir}"
HOSTS="host1"
CUSTOM_CERTIFICATES=(
    "pkcs12:password123:myapp.pfx"
    "concatenated:/etc/ssl/dhparam.pem:nginx.pem"
    "concatenated::simple.pem"
)
'''
        with open(self.test_config, 'w') as f:
            f.write(config_content)
        
        spreader = CertSpreader(self.test_config)
        with patch('os.path.isdir', return_value=True), \
             patch('os.access', return_value=True):
            spreader.load_config()
        
        expected_certs = [
            "pkcs12:password123:myapp.pfx",
            "concatenated:/etc/ssl/dhparam.pem:nginx.pem", 
            "concatenated::simple.pem"
        ]
        self.assertEqual(spreader.config.custom_certificates, expected_certs)
    
    def test_individual_certificate_settings(self):
        """Test individual PKCS12 and concatenated settings"""
        config_content = f'''
DOMAIN="test.example.com"
CERT_DIR="{self.test_cert_dir}"
HOSTS="host1"
PKCS12_ENABLED=true
PKCS12_PASSWORD="test-password"
PKCS12_FILENAME="application.pfx"
CONCATENATED_ENABLED=true
CONCATENATED_DHPARAM_FILE="/etc/ssl/dhparam.pem"
CONCATENATED_FILENAME="server.pem"
'''
        with open(self.test_config, 'w') as f:
            f.write(config_content)
        
        spreader = CertSpreader(self.test_config)
        with patch('os.path.isdir', return_value=True), \
             patch('os.access', return_value=True):
            spreader.load_config()
        
        self.assertTrue(spreader.config.pkcs12_enabled)
        self.assertEqual(spreader.config.pkcs12_password, "test-password")
        self.assertEqual(spreader.config.pkcs12_filename, "application.pfx")
        self.assertTrue(spreader.config.concatenated_enabled)
        self.assertEqual(spreader.config.concatenated_dhparam_file, "/etc/ssl/dhparam.pem")
        self.assertEqual(spreader.config.concatenated_filename, "server.pem")
    
    @patch('subprocess.run')
    def test_generate_pkcs12_certificate(self, mock_subprocess):
        """Test PKCS12 certificate generation"""
        config_content = f'''
DOMAIN="test.example.com"
CERT_DIR="{self.test_cert_dir}"
HOSTS="host1"
PKCS12_ENABLED=true
PKCS12_PASSWORD="test123"
PKCS12_FILENAME="test.pfx"
'''
        with open(self.test_config, 'w') as f:
            f.write(config_content)
        
        spreader = CertSpreader(self.test_config)
        with patch('os.path.isdir', return_value=True), \
             patch('os.access', return_value=True), \
             patch('sys.exit'):  # Prevent sys.exit during validation
            spreader.load_config()
        
        # Mock successful subprocess run
        mock_subprocess.return_value = Mock(returncode=0)
        
        with patch('os.chmod') as mock_chmod:
            spreader.generate_service_certificates()
        
        # Verify OpenSSL command was called
        mock_subprocess.assert_called()
        call_args = mock_subprocess.call_args[0][0]
        self.assertIn('openssl', call_args)
        self.assertIn('pkcs12', call_args)
        self.assertIn('-export', call_args)
        
        # Verify permissions were set
        mock_chmod.assert_called()
    
    def test_generate_concatenated_certificate(self):
        """Test concatenated certificate generation"""
        config_content = f'''
DOMAIN="test.example.com"
CERT_DIR="{self.test_cert_dir}"
HOSTS="host1"
CONCATENATED_ENABLED=true
CONCATENATED_FILENAME="combined.pem"
'''
        with open(self.test_config, 'w') as f:
            f.write(config_content)
        
        spreader = CertSpreader(self.test_config)
        with patch('os.path.isdir', return_value=True), \
             patch('os.access', return_value=True):
            spreader.load_config()
        
        with patch('os.chmod') as mock_chmod:
            spreader.generate_service_certificates()
        
        # Check if concatenated file was created
        combined_path = os.path.join(self.test_cert_dir, "combined.pem")
        self.assertTrue(os.path.exists(combined_path))
        
        # Verify content contains both private key and certificate
        with open(combined_path, 'r') as f:
            content = f.read()
        self.assertIn("fake privkey.pem content", content)
        self.assertIn("fake fullchain.pem content", content)
        
        # Verify permissions were set
        mock_chmod.assert_called()
    
    def test_backward_compatibility(self):
        """Test that old PLEX_CERT and ZNC_CERT settings still work"""
        config_content = f'''
DOMAIN="test.example.com"
CERT_DIR="{self.test_cert_dir}"
HOSTS="host1"
PLEX_CERT_ENABLED=true
PLEX_CERT_PASSWORD="legacy-password"
ZNC_CERT_ENABLED=true
ZNC_DHPARAM_FILE="/etc/ssl/dhparam.pem"
'''
        with open(self.test_config, 'w') as f:
            f.write(config_content)
        
        spreader = CertSpreader(self.test_config)
        with patch('os.path.isdir', return_value=True), \
             patch('os.access', return_value=True):
            spreader.load_config()
        
        # Verify backward compatibility conversion
        self.assertTrue(spreader.config.pkcs12_enabled)
        self.assertEqual(spreader.config.pkcs12_password, "legacy-password")
        self.assertEqual(spreader.config.pkcs12_filename, "plex-certificate.pfx")
        self.assertTrue(spreader.config.concatenated_enabled)
        self.assertEqual(spreader.config.concatenated_dhparam_file, "/etc/ssl/dhparam.pem")
        self.assertEqual(spreader.config.concatenated_filename, "znc.pem")


if __name__ == '__main__':
    # Set up test runner with verbose output
    unittest.main(verbosity=2, buffer=True)