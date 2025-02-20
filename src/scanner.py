import json

class VulnerabilityScanner:
    def __init__(self, opa_policy_url=None):
        self.opa_policy_url = opa_policy_url

    def add_remediation(self, vuln):
        remediation_dict = {
            "SensitiveInformationExposure": "Use encryption or a secret manager to store sensitive data; do not use plain text values.",
            "DebugModeEnabled": "Disable debug mode in production to prevent exposure of internal details.",
            "InsecureConfiguration": "Review your configuration and disable insecure options such as eval, dynamic loading, or root login.",
            "EncryptionDisabled": "Enable encryption to protect data at rest.",
            "MFADisabled": "Enable MFA to secure access.",
            "WeakPassword": "Use a stronger password or integrate with a secrets management system.",
            "OpenPortExposure": "Restrict access to open ports using firewalls or security groups.",
            "PrivilegedContainer": "Avoid running containers in privileged mode; run with the least privileges.",
            "PublicAccessEnabled": "Restrict public access by applying proper access controls and encryption.",
            "OverlyPermissiveIAMRole": "Limit permissions to only what is necessary.",
            "WideOpenSecurityGroup": "Restrict inbound/outbound traffic to specific IP ranges.",
            "IAMPolicyOverlyPermissive": "Review and tighten IAM policy bindings.",
            "CloudFrontInsecure": "Configure CloudFront to enforce HTTPS.",
            "OSLoginDisabled": "Enable OS Login for compute instances.",
            "ShieldedVMDisabled": "Enable Shielded VM features.",
            "SerialPortDebugEnabled": "Disable serial port debugging.",
            "LoggingMonitoringDisabled": "Enable logging and monitoring for better observability.",
            "LegacyABACEnabled": "Disable legacy ABAC; enable RBAC and network policies.",
            "NoKeyRotation": "Enable key rotation for improved key security.",
            "CloudTrailMisconfigured": "Enable multi-region trails, log file validation, and encryption for CloudTrail."
        }
        vtype = vuln.get("type")
        vuln["remediation"] = remediation_dict.get(vtype, "Review configuration and apply security best practices.")
        return vuln

    # --- General Vulnerability Checks ---

    def check_sensitive_keys(self, config, parent_key=""):
        vulnerabilities = []
        if isinstance(config, dict):
            for key, value in config.items():
                key_path = f"{parent_key}.{key}" if parent_key else key
                lower_key = key.lower()
                if any(term in lower_key for term in ["password", "secret", "api_key", "token"]):
                    if isinstance(value, str):
                        if len(value) < 20 or not value.startswith("ENC("):
                            vuln = {
                                "type": "SensitiveInformationExposure",
                                "key": key_path,
                                "message": f"Key '{key_path}' may contain sensitive data in plain text.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                vulnerabilities.extend(self.check_sensitive_keys(value, key_path))
        elif isinstance(config, list):
            for index, item in enumerate(config):
                key_path = f"{parent_key}[{index}]"
                vulnerabilities.extend(self.check_sensitive_keys(item, key_path))
        return vulnerabilities

    def check_debug_flags(self, config, parent_key=""):
        vulnerabilities = []
        if isinstance(config, dict):
            for key, value in config.items():
                key_path = f"{parent_key}.{key}" if parent_key else key
                if key.lower() == "debug" and isinstance(value, bool) and value:
                    vuln = {
                        "type": "DebugModeEnabled",
                        "key": key_path,
                        "message": f"Debug mode is enabled at '{key_path}'.",
                        "severity": "Medium"
                    }
                    vulnerabilities.append(self.add_remediation(vuln))
                vulnerabilities.extend(self.check_debug_flags(value, key_path))
        elif isinstance(config, list):
            for index, item in enumerate(config):
                key_path = f"{parent_key}[{index}]"
                vulnerabilities.extend(self.check_debug_flags(item, key_path))
        return vulnerabilities

    def check_insecure_configurations(self, config, parent_key=""):
        vulnerabilities = []
        if isinstance(config, dict):
            for key, value in config.items():
                key_path = f"{parent_key}.{key}" if parent_key else key
                if key.lower() in ["use_eval", "allow_dynamic_loading", "allow_root_login"] and value is True:
                    vuln = {
                        "type": "InsecureConfiguration",
                        "key": key_path,
                        "message": f"Key '{key_path}' is set to True, indicating an insecure configuration.",
                        "severity": "High"
                    }
                    vulnerabilities.append(self.add_remediation(vuln))
                vulnerabilities.extend(self.check_insecure_configurations(value, key_path))
        elif isinstance(config, list):
            for index, item in enumerate(config):
                key_path = f"{parent_key}[{index}]"
                vulnerabilities.extend(self.check_insecure_configurations(item, key_path))
        return vulnerabilities

    def scan_general(self, config, parent_key=""):
        vulns = []
        vulns.extend(self.check_sensitive_keys(config, parent_key))
        vulns.extend(self.check_debug_flags(config, parent_key))
        vulns.extend(self.check_insecure_configurations(config, parent_key))
        return vulns

    # --- Resource-Specific Vulnerability Checks ---

    def scan_resources(self, config):
        vulnerabilities = []
        resources = config.get("resources", [])
        if isinstance(resources, list):
            for idx, res in enumerate(resources):
                res_key = f"resources[{idx}]"
                rtype = res.get("type", "").lower()
                match rtype:
                    #aws
                    case "s3_bucket":
                        if res.get("public_read_access") is True or res.get("public_write_access") is True:
                            vuln = {
                                "type": "PublicAccessEnabled",
                                "key": res_key,
                                "message": f"S3 Bucket '{res.get('name')}' has public access enabled.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("encryption") is False:
                            vuln = {
                                "type": "EncryptionDisabled",
                                "key": f"{res_key}.encryption",
                                "message": f"S3 Bucket '{res.get('name')}' is not encrypted.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                    case "ec2_instance":
                        password = res.get("password", "")
                        if password and (len(password) < 8 or "weak" in password.lower()):
                            vuln = {
                                "type": "WeakPassword",
                                "key": f"{res_key}.password",
                                "message": f"EC2 Instance '{res.get('name')}' is using a weak password.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("encryption") is False:
                            vuln = {
                                "type": "EncryptionDisabled",
                                "key": f"{res_key}.encryption",
                                "message": f"EC2 Instance '{res.get('name')}' is not encrypted.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("mfa_enabled") is False:
                            vuln = {
                                "type": "MFADisabled",
                                "key": f"{res_key}.mfa_enabled",
                                "message": f"EC2 Instance '{res.get('name')}' does not have MFA enabled.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("allow_root_login") is True:
                            vuln = {
                                "type": "InsecureConfiguration",
                                "key": f"{res_key}.allow_root_login",
                                "message": f"EC2 Instance '{res.get('name')}' allows root login.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        open_ports = res.get("open_ports", [])
                        if any(port in open_ports for port in [22, 3389]):
                            vuln = {
                                "type": "OpenPortExposure",
                                "key": f"{res_key}.open_ports",
                                "message": f"EC2 Instance '{res.get('name')}' has sensitive ports open (SSH/RDP).",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "security_group":
                        rules = res.get("rules", [])
                        for rule in rules:
                            source = rule.get("source") or rule.get("destination")
                            if source == "0.0.0.0/0":
                                vuln = {
                                    "type": "WideOpenSecurityGroup",
                                    "key": f"{res_key}.rules",
                                    "message": f"Security Group '{res.get('name')}' allows unrestricted access.",
                                    "severity": "High"
                                }
                                vulnerabilities.append(self.add_remediation(vuln))

                    case "iam_role":
                        permissions = res.get("permissions", [])
                        for perm in permissions:
                            actions = perm.get("Action")
                            if isinstance(actions, str):
                                actions = [actions]
                            if "*" in actions:
                                vuln = {
                                    "type": "OverlyPermissiveIAMRole",
                                    "key": f"{res_key}.permissions",
                                    "message": f"IAM Role '{res.get('name')}' grants overly permissive access.",
                                    "severity": "High"
                                }
                                vulnerabilities.append(self.add_remediation(vuln))

                    case "rds_instance":
                        if res.get("storage_encrypted") is False:
                            vuln = {
                                "type": "EncryptionDisabled",
                                "key": f"{res_key}.storage_encrypted",
                                "message": f"RDS Instance '{res.get('name')}' is not encrypted.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("public_access") is True:
                            vuln = {
                                "type": "PublicAccessEnabled",
                                "key": f"{res_key}.public_access",
                                "message": f"RDS Instance '{res.get('name')}' is publicly accessible.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("mfa_enabled") is False:
                            vuln = {
                                "type": "MFADisabled",
                                "key": f"{res_key}.mfa_enabled",
                                "message": f"RDS Instance '{res.get('name')}' does not have MFA enabled.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    # GCP Resources
                    case "gcs_bucket":
                        if res.get("public_access") is True:
                            vuln = {
                                "type": "PublicAccessEnabled",
                                "key": f"{res_key}.public_access",
                                "message": f"GCS Bucket '{res.get('name')}' is publicly accessible.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("encryption") is False:
                            vuln = {
                                "type": "EncryptionDisabled",
                                "key": f"{res_key}.encryption",
                                "message": f"GCS Bucket '{res.get('name')}' is not encrypted.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "compute_instance":
                        password = res.get("password", "")
                        if password and (len(password) < 8 or "weak" in password.lower()):
                            vuln = {
                                "type": "WeakPassword",
                                "key": f"{res_key}.password",
                                "message": f"Compute Instance '{res.get('name')}' is using a weak password.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("disk_encryption") is False:
                            vuln = {
                                "type": "EncryptionDisabled",
                                "key": f"{res_key}.disk_encryption",
                                "message": f"Compute Instance '{res.get('name')}' is not encrypted.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("mfa_enabled") is False:
                            vuln = {
                                "type": "MFADisabled",
                                "key": f"{res_key}.mfa_enabled",
                                "message": f"Compute Instance '{res.get('name')}' does not have MFA enabled.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        open_ports = res.get("open_ports", [])
                        if any(port in open_ports for port in [22, 3389]):
                            vuln = {
                                "type": "OpenPortExposure",
                                "key": f"{res_key}.open_ports",
                                "message": f"Compute Instance '{res.get('name')}' has sensitive ports open (SSH/RDP).",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    #azure
                    case "storage_account":
                        if res.get("public_access") not in [None, "None"]:
                            vuln = {
                                "type": "PublicAccessEnabled",
                                "key": f"{res_key}.public_access",
                                "message": f"Storage Account '{res.get('name')}' has public access enabled.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("encryption_enabled") is False:
                            vuln = {
                                "type": "EncryptionDisabled",
                                "key": f"{res_key}.encryption_enabled",
                                "message": f"Storage Account '{res.get('name')}' is not encrypted.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("soft_delete_enabled") is False:
                            vuln = {
                                "type": "InsecureConfiguration",
                                "key": f"{res_key}.soft_delete_enabled",
                                "message": f"Storage Account '{res.get('name')}' does not have soft delete enabled.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "virtual_machine":
                        
                        if res.get("password") and (len(res.get("password")) < 8 or "weak" in res.get("password").lower()):
                            vuln = {
                                "type": "WeakPassword",
                                "key": f"{res_key}.password",
                                "message": f"Virtual Machine '{res.get('name')}' is using a weak password.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("os_disk_encryption_enabled") is False:
                            vuln = {
                                "type": "EncryptionDisabled",
                                "key": f"{res_key}.os_disk_encryption_enabled",
                                "message": f"Virtual Machine '{res.get('name')}' has OS disk unencrypted.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("boot_diagnostics_enabled") is False:
                            vuln = {
                                "type": "InsecureConfiguration",
                                "key": f"{res_key}.boot_diagnostics_enabled",
                                "message": f"Virtual Machine '{res.get('name')}' does not have boot diagnostics enabled.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("just_in_time_access_enabled") is False:
                            vuln = {
                                "type": "InsecureConfiguration",
                                "key": f"{res_key}.just_in_time_access_enabled",
                                "message": f"Virtual Machine '{res.get('name')}' does not have JIT access enabled.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        open_ports = res.get("open_ports", [])
                        if any(port in open_ports for port in [3389, 22]):
                            vuln = {
                                "type": "OpenPortExposure",
                                "key": f"{res_key}.open_ports",
                                "message": f"Virtual Machine '{res.get('name')}' has sensitive ports open.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "network_security_group":
                        rules = res.get("rules", [])
                        for rule in rules:
                            source = rule.get("source")
                            if source == "0.0.0.0/0":
                                vuln = {
                                    "type": "WideOpenSecurityGroup",
                                    "key": f"{res_key}.rules",
                                    "message": f"Network Security Group '{res.get('name')}' allows unrestricted access.",
                                    "severity": "High"
                                }
                                vulnerabilities.append(self.add_remediation(vuln))

                    case "role_assignment":
                        if res.get("role").lower() in ["owner"] and res.get("assigned_to").lower() in ["everyone", "allusers"]:
                            vuln = {
                                "type": "OverlyPermissiveIAMRole",
                                "key": f"{res_key}.role_assignment",
                                "message": f"Role Assignment '{res.get('name')}' grants overly permissive access.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "policy_assignment":
                        if res.get("policy_definition_name") is None:
                            vuln = {
                                "type": "IAMPolicyOverlyPermissive",
                                "key": f"{res_key}.policy_assignment",
                                "message": f"Policy Assignment '{res.get('name')}' does not enforce a security baseline.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "key_vault":
                        if res.get("public_network_access") is True:
                            vuln = {
                                "type": "PublicAccessEnabled",
                                "key": f"{res_key}.public_network_access",
                                "message": f"Key Vault '{res.get('name')}' has public network access enabled.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("firewall_enabled") is False:
                            vuln = {
                                "type": "InsecureConfiguration",
                                "key": f"{res_key}.firewall_enabled",
                                "message": f"Key Vault '{res.get('name')}' does not have a firewall enabled.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("soft_delete_enabled") is False:
                            vuln = {
                                "type": "InsecureConfiguration",
                                "key": f"{res_key}.soft_delete_enabled",
                                "message": f"Key Vault '{res.get('name')}' does not have soft delete enabled.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "log_analytics_workspace":
                        if res.get("retention_in_days", 0) == 0:
                            vuln = {
                                "type": "InsecureConfiguration",
                                "key": f"{res_key}.retention_in_days",
                                "message": f"Log Analytics Workspace '{res.get('name')}' has no data retention configured.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "sql_server":
                        if res.get("azure_ad_admin_configured") is False:
                            vuln = {
                                "type": "InsecureConfiguration",
                                "key": f"{res_key}.azure_ad_admin_configured",
                                "message": f"SQL Server '{res.get('name')}' does not have an Azure AD admin configured.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("audit_enabled") is False:
                            vuln = {
                                "type": "InsecureConfiguration",
                                "key": f"{res_key}.audit_enabled",
                                "message": f"SQL Server '{res.get('name')}' does not have auditing enabled.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("threat_detection_enabled") is False:
                            vuln = {
                                "type": "InsecureConfiguration",
                                "key": f"{res_key}.threat_detection_enabled",
                                "message": f"SQL Server '{res.get('name')}' does not have threat detection enabled.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("transparent_data_encryption") is False:
                            vuln = {
                                "type": "EncryptionDisabled",
                                "key": f"{res_key}.transparent_data_encryption",
                                "message": f"SQL Server '{res.get('name')}' does not have transparent data encryption enabled.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "sql_database":
                        if res.get("encryption_enabled") is False:
                            vuln = {
                                "type": "EncryptionDisabled",
                                "key": f"{res_key}.encryption_enabled",
                                "message": f"SQL Database '{res.get('name')}' is not encrypted.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("public_access") is True:
                            vuln = {
                                "type": "PublicAccessEnabled",
                                "key": f"{res_key}.public_access",
                                "message": f"SQL Database '{res.get('name')}' is publicly accessible.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("mfa_enabled") is False:
                            vuln = {
                                "type": "MFADisabled",
                                "key": f"{res_key}.mfa_enabled",
                                "message": f"SQL Database '{res.get('name')}' does not have MFA enabled.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "app_service":
                        if res.get("https_only") is False:
                            vuln = {
                                "type": "InsecureConfiguration",
                                "key": f"{res_key}.https_only",
                                "message": f"App Service '{res.get('name')}' does not enforce HTTPS.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("ftps_state") == "AllAllowed":
                            vuln = {
                                "type": "InsecureConfiguration",
                                "key": f"{res_key}.ftps_state",
                                "message": f"App Service '{res.get('name')}' allows FTPS, which might expose credentials.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("client_cert_enabled") is False:
                            vuln = {
                                "type": "InsecureConfiguration",
                                "key": f"{res_key}.client_cert_enabled",
                                "message": f"App Service '{res.get('name')}' does not require client certificates.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("remote_debug_enabled") is True:
                            vuln = {
                                "type": "InsecureConfiguration",
                                "key": f"{res_key}.remote_debug_enabled",
                                "message": f"App Service '{res.get('name')}' has remote debugging enabled.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "aks_cluster":
                        if res.get("rbac_enabled") is False:
                            vuln = {
                                "type": "LegacyABACEnabled",
                                "key": f"{res_key}.rbac_enabled",
                                "message": f"AKS Cluster '{res.get('name')}' does not have RBAC enabled.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("network_policy_enabled") is False:
                            vuln = {
                                "type": "InsecureConfiguration",
                                "key": f"{res_key}.network_policy_enabled",
                                "message": f"AKS Cluster '{res.get('name')}' does not have network policies enabled.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    #gcp
                    case "compute_instance":
                        password = res.get("password", "")
                        if password and (len(password) < 8 or "weak" in password.lower()):
                            vuln = {
                                "type": "WeakPassword",
                                "key": f"{res_key}.password",
                                "message": f"Compute Instance '{res.get('name')}' is using a weak password.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("disk_encryption") is False:
                            vuln = {
                                "type": "EncryptionDisabled",
                                "key": f"{res_key}.disk_encryption",
                                "message": f"Compute Instance '{res.get('name')}' is not encrypted.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("mfa_enabled") is False:
                            vuln = {
                                "type": "MFADisabled",
                                "key": f"{res_key}.mfa_enabled",
                                "message": f"Compute Instance '{res.get('name')}' does not have MFA enabled.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        open_ports = res.get("open_ports", [])
                        if any(port in open_ports for port in [22, 3389]):
                            vuln = {
                                "type": "OpenPortExposure",
                                "key": f"{res_key}.open_ports",
                                "message": f"Compute Instance '{res.get('name')}' has sensitive ports open (SSH/RDP).",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "firewall_rule":
                        rules = res.get("rules", [])
                        for rule in rules:
                            source = rule.get("source")
                            if source == "0.0.0.0/0":
                                vuln = {
                                    "type": "WideOpenSecurityGroup",
                                    "key": f"{res_key}.rules",
                                    "message": f"Firewall Rule '{res.get('name')}' allows unrestricted access.",
                                    "severity": "High"
                                }
                                vulnerabilities.append(self.add_remediation(vuln))

                    case "iam_policy":
                        bindings = res.get("bindings", [])
                        for binding in bindings:
                            role = binding.get("role", "").lower()
                            members = binding.get("members", [])
                            if role == "roles/owner" and any(m.lower() in ["allusers", "everyone"] for m in members):
                                vuln = {
                                    "type": "OverlyPermissiveIAMRole",
                                    "key": f"{res_key}.iam_policy",
                                    "message": f"IAM Policy '{res.get('name')}' grants overly permissive access.",
                                    "severity": "High"
                                }
                                vulnerabilities.append(self.add_remediation(vuln))

                    case "cloud_logging":
                        if res.get("enabled") is False:
                            vuln = {
                                "type": "LoggingMonitoringDisabled",
                                "key": f"{res_key}.enabled",
                                "message": f"Cloud Logging '{res.get('name')}' is disabled.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "cloud_monitoring":
                        if res.get("enabled") is False:
                            vuln = {
                                "type": "LoggingMonitoringDisabled",
                                "key": f"{res_key}.enabled",
                                "message": f"Cloud Monitoring '{res.get('name')}' is disabled.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "container_cluster":
                        if res.get("legacy_abac_enabled") is True:
                            vuln = {
                                "type": "LegacyABACEnabled",
                                "key": f"{res_key}.legacy_abac_enabled",
                                "message": f"Container Cluster '{res.get('name')}' has legacy ABAC enabled.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("basic_auth_enabled") is True:
                            vuln = {
                                "type": "InsecureConfiguration",
                                "key": f"{res_key}.basic_auth_enabled",
                                "message": f"Container Cluster '{res.get('name')}' uses basic auth, which is insecure.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "service_account":
                        if res.get("key_rotation_enabled") is False:
                            vuln = {
                                "type": "NoKeyRotation",
                                "key": f"{res_key}.key_rotation_enabled",
                                "message": f"Service Account '{res.get('name')}' does not have key rotation enabled.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        roles = res.get("roles", [])
                        if any("owner" in role.lower() for role in roles):
                            vuln = {
                                "type": "OverlyPermissiveIAMRole",
                                "key": f"{res_key}.roles",
                                "message": f"Service Account '{res.get('name')}' has overly permissive roles assigned.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "cloud_sql":
                        if res.get("disk_encryption") is False:
                            vuln = {
                                "type": "EncryptionDisabled",
                                "key": f"{res_key}.disk_encryption",
                                "message": f"Cloud SQL Instance '{res.get('name')}' is not encrypted.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("public_access") is True:
                            vuln = {
                                "type": "PublicAccessEnabled",
                                "key": f"{res_key}.public_access",
                                "message": f"Cloud SQL Instance '{res.get('name')}' is publicly accessible.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("require_ssl") is False:
                            vuln = {
                                "type": "InsecureConfiguration",
                                "key": f"{res_key}.require_ssl",
                                "message": f"Cloud SQL Instance '{res.get('name')}' does not require SSL.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("root_password") and (len(res.get("root_password")) < 8 or "weak" in res.get("root_password").lower()):
                            vuln = {
                                "type": "WeakPassword",
                                "key": f"{res_key}.root_password",
                                "message": f"Cloud SQL Instance '{res.get('name')}' is using a weak root password.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("mfa_enabled") is False:
                            vuln = {
                                "type": "MFADisabled",
                                "key": f"{res_key}.mfa_enabled",
                                "message": f"Cloud SQL Instance '{res.get('name')}' does not have MFA enabled.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "bigquery_dataset":
                        if res.get("public_access") is True:
                            vuln = {
                                "type": "PublicAccessEnabled",
                                "key": f"{res_key}.public_access",
                                "message": f"BigQuery Dataset '{res.get('name')}' is publicly accessible.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("encryption") == "NONE":
                            vuln = {
                                "type": "EncryptionDisabled",
                                "key": f"{res_key}.encryption",
                                "message": f"BigQuery Dataset '{res.get('name')}' is not encrypted.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "dns_managed_zone":
                        if res.get("visibility", "").lower() == "public":
                            vuln = {
                                "type": "PublicAccessEnabled",
                                "key": f"{res_key}.visibility",
                                "message": f"DNS Managed Zone '{res.get('name')}' is publicly visible.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "iam_policy":
                        bindings = res.get("bindings", [])
                        for binding in bindings:
                            role = binding.get("role", "").lower()
                            members = binding.get("members", [])
                            if role == "roles/owner" and any(m.lower() in ["allusers", "everyone"] for m in members):
                                vuln = {
                                    "type": "OverlyPermissiveIAMRole",
                                    "key": f"{res_key}.iam_policy",
                                    "message": f"IAM Policy '{res.get('name')}' grants overly permissive access.",
                                    "severity": "High"
                                }
                                vulnerabilities.append(self.add_remediation(vuln))

                    case "cloudtrail":
                        if res.get("multi_region_trail") is False:
                            vuln = {
                                "type": "CloudTrailMisconfigured",
                                "key": f"{res_key}.multi_region_trail",
                                "message": f"CloudTrail '{res.get('name')}' is not configured for multi-region trails.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("log_file_validation_enabled") is False:
                            vuln = {
                                "type": "CloudTrailMisconfigured",
                                "key": f"{res_key}.log_file_validation_enabled",
                                "message": f"CloudTrail '{res.get('name')}' does not have log file validation enabled.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        if res.get("encrypted") is False:
                            vuln = {
                                "type": "EncryptionDisabled",
                                "key": f"{res_key}.encrypted",
                                "message": f"CloudTrail '{res.get('name')}' is not encrypted.",
                                "severity": "High"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "kms_key":
                        if res.get("rotation_enabled") is False:
                            vuln = {
                                "type": "NoKeyRotation",
                                "key": f"{res_key}.rotation_enabled",
                                "message": f"KMS Key '{res.get('name')}' does not have key rotation enabled.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "iam_user":
                        if res.get("mfa_enabled") is False:
                            vuln = {
                                "type": "MFADisabled",
                                "key": f"{res_key}.mfa_enabled",
                                "message": f"IAM User '{res.get('name')}' does not have MFA enabled.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))
                        inline_policies = res.get("inline_policies", [])
                        for policy in inline_policies:
                            doc = policy.get("PolicyDocument", {})
                            statements = doc.get("Statement", [])
                            for stmt in statements:
                                action = stmt.get("Action")
                                if isinstance(action, str):
                                    action = [action]
                                if "*" in action:
                                    vuln = {
                                        "type": "OverlyPermissiveIAMRole",
                                        "key": f"{res_key}.inline_policies",
                                        "message": f"IAM User '{res.get('name')}' has an overly permissive inline policy.",
                                        "severity": "High"
                                    }
                                    vulnerabilities.append(self.add_remediation(vuln))

                    case "lambda_function":
                        permissions = res.get("lambda_permissions", [])
                        for perm in permissions:
                            action = perm.get("Action")
                            if isinstance(action, str):
                                action = [action]
                            if "*" in action:
                                vuln = {
                                    "type": "OverlyPermissiveIAMRole",
                                    "key": f"{res_key}.lambda_permissions",
                                    "message": f"Lambda Function '{res.get('name')}' has overly permissive permissions.",
                                    "severity": "High"
                                }
                                vulnerabilities.append(self.add_remediation(vuln))

                    case "cloudfront_distribution":
                        if res.get("viewer_protocol_policy", "").lower() != "redirect-to-https":
                            vuln = {
                                "type": "CloudFrontInsecure",
                                "key": f"{res_key}.viewer_protocol_policy",
                                "message": f"CloudFront Distribution '{res.get('name')}' does not enforce HTTPS.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case "cloud_config":
                        if res.get("recording_all_resources") is False:
                            vuln = {
                                "type": "InsecureConfiguration",
                                "key": f"{res_key}.recording_all_resources",
                                "message": f"Cloud Config '{res.get('name')}' is not recording all resources.",
                                "severity": "Medium"
                            }
                            vulnerabilities.append(self.add_remediation(vuln))

                    case _:
                        # Unrecognized resource types – no specific checks.
                        pass

        return vulnerabilities

    def scan(self, config, report_format="dict"):
        vulnerabilities = []
        vulnerabilities.extend(self.scan_general(config))
        vulnerabilities.extend(self.scan_resources(config))
        unique_vulns = { (v["type"], v["key"]): v for v in vulnerabilities }.values()
        if report_format == "dict":
            return list(unique_vulns)
        elif report_format == "txt":
            return self.generate_text_report(list(unique_vulns))
        elif report_format == "json":
            return json.dumps({"vulnerabilities": list(unique_vulns)}, indent=2)
        else:
            return list(unique_vulns)

    def generate_text_report(self, vulnerabilities):
        lines = []
        lines.append("Vulnerability Scan Report")
        lines.append("")
        if not vulnerabilities:
            lines.append("No vulnerabilities found.")
        else:
            for idx, vuln in enumerate(vulnerabilities, start=1):
                lines.append(f"Vulnerability {idx}:")
                lines.append(f"  Type        : {vuln.get('type', 'N/A')}")
                lines.append(f"  Location    : {vuln.get('key', 'N/A')}")
                lines.append(f"  Severity    : {vuln.get('severity', 'N/A')}")
                lines.append(f"  Description : {vuln.get('message', 'N/A')}")
                lines.append(f"  Remediation : {vuln.get('remediation', 'N/A')}")
                lines.append("")
        return "\n".join(lines)
