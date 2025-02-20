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

    def test_resource_vm_vulnerabilities(self):
        config = {
            "resources": [
                {
                    "type": "virtual_machine",
                    "name": "vm1",
                    "open_ports": [22, 80],
                    "password": "weakpassword",
                    "encryption": False,
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
