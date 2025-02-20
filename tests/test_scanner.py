import unittest
import json
from src.scanner import VulnerabilityScanner

class TestVulnerabilityScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = VulnerabilityScanner()

    def test_sensitive_keys_detection(self):
        config = {"password": "weakpassword"}
        vulns = self.scanner.check_sensitive_keys(config)
        self.assertTrue(any(v["type"] == "SensitiveInformationExposure" for v in vulns))

    def test_debug_flag_detection(self):
        config = {"debug": True}
        vulns = self.scanner.check_debug_flags(config)
        self.assertTrue(any(v["type"] == "DebugModeEnabled" for v in vulns))

    def test_insecure_configuration_detection(self):
        config = {"use_eval": True}
        vulns = self.scanner.check_insecure_configurations(config)
        self.assertTrue(any(v["type"] == "InsecureConfiguration" for v in vulns))

    def test_aws_ec2_vulnerabilities(self):
        config = {
            "resources": [
                {
                    "type": "ec2_instance",
                    "name": "web-server",
                    "open_ports": [22, 3389],
                    "password": "weakpassword",
                    "encryption": False,
                    "mfa_enabled": False,
                    "allow_root_login": True
                }
            ]
        }
        vulns = self.scanner.scan_resources(config)
        types = [v["type"] for v in vulns]
        self.assertIn("WeakPassword", types)
        self.assertIn("EncryptionDisabled", types)
        self.assertIn("MFADisabled", types)
        self.assertIn("InsecureConfiguration", types)  # for allow_root_login
        self.assertIn("OpenPortExposure", types)

    def test_aws_s3_bucket_vulnerabilities(self):
        config = {
            "resources": [
                {
                    "type": "s3_bucket",
                    "name": "insecure-bucket",
                    "public_read_access": True,
                    "public_write_access": True,
                    "encryption": False
                }
            ]
        }
        vulns = self.scanner.scan_resources(config)
        types = [v["type"] for v in vulns]
        self.assertIn("PublicAccessEnabled", types)
        self.assertIn("EncryptionDisabled", types)

    def test_azure_storage_account_vulnerabilities(self):
        config = {
            "resources": [
                {
                    "type": "storage_account",
                    "name": "insecurestorage",
                    "public_access": "Blob",
                    "encryption_enabled": False,
                    "soft_delete_enabled": False
                }
            ]
        }
        vulns = self.scanner.scan_resources(config)
        types = [v["type"] for v in vulns]
        self.assertIn("PublicAccessEnabled", types)
        self.assertIn("EncryptionDisabled", types)

    def test_azure_vm_vulnerabilities(self):
        config = {
            "resources": [
                {
                    "type": "virtual_machine",
                    "name": "vm1",
                    "password": "P@ss123",
                    "os_disk_encryption_enabled": False,
                    "boot_diagnostics_enabled": False,
                    "just_in_time_access_enabled": False,
                    "open_ports": [3389, 22]
                }
            ]
        }
        vulns = self.scanner.scan_resources(config)
        types = [v["type"] for v in vulns]
        self.assertIn("WeakPassword", types)
        self.assertIn("EncryptionDisabled", types)
        self.assertIn("OpenPortExposure", types)

    def test_azure_key_vault_vulnerabilities(self):
        config = {
            "resources": [
                {
                    "type": "key_vault",
                    "name": "public-vault",
                    "public_network_access": True,
                    "firewall_enabled": False,
                    "soft_delete_enabled": False
                }
            ]
        }
        vulns = self.scanner.scan_resources(config)
        types = [v["type"] for v in vulns]
        self.assertIn("PublicAccessEnabled", types)
        self.assertIn("InsecureConfiguration", types)

    def test_gcp_compute_instance_vulnerabilities(self):
        config = {
            "resources": [
                {
                    "type": "compute_instance",
                    "name": "unsecured-vm",
                    "open_ports": [22, 80],
                    "password": "WeakPass123!",
                    "disk_encryption": False,
                    "mfa_enabled": False
                }
            ]
        }
        vulns = self.scanner.scan_resources(config)
        types = [v["type"] for v in vulns]
        self.assertIn("WeakPassword", types)
        self.assertIn("EncryptionDisabled", types)
        self.assertIn("MFADisabled", types)
        self.assertIn("OpenPortExposure", types)

    def test_gcp_firewall_rule_vulnerabilities(self):
        config = {
            "resources": [
                {
                    "type": "firewall_rule",
                    "name": "wide-open-fw",
                    "rules": [
                        {"protocol": "tcp", "port": 22, "source": "0.0.0.0/0"},
                        {"protocol": "tcp", "port": 80, "source": "0.0.0.0/0"}
                    ]
                }
            ]
        }
        vulns = self.scanner.scan_resources(config)
        types = [v["type"] for v in vulns]
        self.assertIn("WideOpenSecurityGroup", types)

    def test_gcp_logging_monitoring_vulnerabilities(self):
        config = {
            "resources": [
                {
                    "type": "cloud_logging",
                    "name": "disabled-logging",
                    "enabled": False
                },
                {
                    "type": "cloud_monitoring",
                    "name": "disabled-monitoring",
                    "enabled": False
                }
            ]
        }
        vulns = self.scanner.scan_resources(config)
        types = [v["type"] for v in vulns]
        self.assertIn("LoggingMonitoringDisabled", types)

    def test_gcp_container_cluster_vulnerabilities(self):
        config = {
            "resources": [
                {
                    "type": "container_cluster",
                    "name": "legacy-gke",
                    "legacy_abac_enabled": True,
                    "basic_auth_enabled": True
                }
            ]
        }
        vulns = self.scanner.scan_resources(config)
        types = [v["type"] for v in vulns]
        self.assertIn("LegacyABACEnabled", types)

    def test_full_scan_with_no_vulns(self):
        config = {
            "resources": [
                {
                    "type": "virtual_machine",
                    "name": "vm-secure",
                    "open_ports": [],
                    "password": "ENC(verysecureencryptedvalue)",
                    "encryption": True,
                    "mfa_enabled": True
                }
            ],
            "debug": False
        }
        vulns = self.scanner.scan(config)
        self.assertEqual(len(vulns), 0)

if __name__ == '__main__':
    unittest.main()
