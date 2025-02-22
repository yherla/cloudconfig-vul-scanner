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

    #aws tests
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
        self.assertIn("InsecureConfiguration", types)
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

    def test_aws_cloudtrail_misconfigured(self):
        config = {
            "resources": [
                {
                    "type": "cloudtrail",
                    "name": "trail1",
                    "multi_region_trail": False,
                    "log_file_validation_enabled": False,
                    "encrypted": False
                }
            ]
        }
        vulns = self.scanner.scan_resources(config)
        types = [v["type"] for v in vulns]
        self.assertIn("CloudTrailMisconfigured", types)
        self.assertIn("EncryptionDisabled", types)

    def test_aws_cloudfront_insecure(self):
        config = {
            "resources": [
                {
                    "type": "cloudfront_distribution",
                    "name": "my-dist",
                    "viewer_protocol_policy": "allow-all"
                }
            ]
        }
        vulns = self.scanner.scan_resources(config)
        types = [v["type"] for v in vulns]
        self.assertIn("CloudFrontInsecure", types)

    def test_aws_cloud_config_insecure(self):
        config = {
            "resources": [
                {
                    "type": "cloud_config",
                    "name": "my-cloud-config",
                    "recording_all_resources": False
                }
            ]
        }
        vulns = self.scanner.scan_resources(config)
        types = [v["type"] for v in vulns]
        self.assertIn("InsecureConfiguration", types)

    def test_aws_iam_user_inline_policies(self):
        config = {
            "resources": [
                {
                    "type": "iam_user",
                    "name": "someuser",
                    "mfa_enabled": False,
                    "inline_policies": [
                        {
                            "PolicyName": "admin-all",
                            "PolicyDocument": {
                                "Statement": [
                                    {"Effect": "Allow", "Action": "*", "Resource": "*"}
                                ]
                            }
                        }
                    ]
                }
            ]
        }
        vulns = self.scanner.scan_resources(config)
        types = [v["type"] for v in vulns]
        self.assertIn("MFADisabled", types)
        self.assertIn("OverlyPermissiveIAMRole", types)

    #azure tests
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

    #gcp tests
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

    #other cases
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

    def test_unknown_resource_type(self):
        config = {
            "resources": [
                {
                    "type": "unknown_resource",
                    "name": "mysterious"
                }
            ]
        }
        vulns = self.scanner.scan_resources(config)
        self.assertEqual(len(vulns), 0)

    def test_scan_txt_format(self):
        """Test generating a text report from scan."""
        config = {
            "resources": [
                {
                    "type": "virtual_machine",
                    "name": "vm1",
                    "password": "weakpwd",
                    "open_ports": [22],
                    "encryption": False,
                    "mfa_enabled": False
                }
            ]
        }
        txt_report = self.scanner.scan(config, report_format="txt")
        self.assertIn("Vulnerability 1:", txt_report)
        self.assertIn("WeakPassword", txt_report)
        self.assertIn("EncryptionDisabled", txt_report)

    def test_scan_json_format(self):
        """Test generating a JSON report from scan."""
        config = {
            "resources": [
                {
                    "type": "storage_account",
                    "name": "insecurestorage",
                    "public_access": "Blob",
                    "encryption_enabled": False
                }
            ]
        }
        json_report = self.scanner.scan(config, report_format="json")
        self.assertIn('"type": "PublicAccessEnabled"', json_report)
        self.assertIn('"type": "EncryptionDisabled"', json_report)

    def test_no_resources_key(self):
        config = {}
        vulns = self.scanner.scan_resources(config)
        self.assertEqual(vulns, [])

        config2 = {"resources": "not_a_list"}
        vulns2 = self.scanner.scan_resources(config2)
        self.assertEqual(vulns2, [])

    #knative tests
    def test_knative_service_vulnerabilities(self):
        knative_json = {
            "apiVersion": "serving.knative.dev/v1",
            "kind": "Service",
            "metadata": {
                "name": "nginx-service",
                "namespace": "default",
                "annotations": {
                    "autoscaling.knative.dev/minScale": "1",
                    "autoscaling.knative.dev/maxScale": "10",
                    "security.knative.dev/mfaEnabled": "false"
                }
            },
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "autoscaling.knative.dev/minScale": "1",
                            "autoscaling.knative.dev/maxScale": "10"
                        }
                    },
                    "spec": {
                        "containers": [
                            {
                                "image": "nginx:latest",
                                "ports": [
                                    {"containerPort": 80}
                                ],
                                "env": [
                                    {"name": "ENVIRONMENT", "value": "production"},
                                    {"name": "SECRET_KEY", "value": "mysecretkey"},
                                    {"name": "PUBLIC_BUCKET_URL", "value": "http://public-bucket.example.com/data"}
                                ],
                                "securityContext": {
                                    "runAsUser": 0,
                                    "runAsGroup": 0,
                                    "privileged": True
                                    # missing readOnlyRootFilesystem => vulnerability
                                }
                                # missing resources => MissingResourceLimits
                            }
                        ]
                    }
                }
            }
        }
        vulns = self.scanner.scan(knative_json)
        types = [v["type"] for v in vulns]

        self.assertIn("MFADisabled", types)
        self.assertIn("LatestTagUsed", types)
        self.assertIn("SensitiveInformationExposure", types)
        self.assertIn("PrivilegedContainer", types)
        self.assertIn("RunAsRoot", types)
        self.assertIn("MissingReadOnlyRootFilesystem", types)
        self.assertIn("MissingResourceLimits", types)

if __name__ == '__main__':
    unittest.main()
