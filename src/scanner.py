import json

class VulnerabilityScanner:
    def __init__(self, opa_policy_url=None):
        self.opa_policy_url = opa_policy_url

    def add_remediation(self, vuln):
        remediation_dict = {
            "SensitiveInformationExposure": "Use encryption or a secret manager to store sensitive data; do not use plain text values.",
            "DebugModeEnabled": "Disable debug mode in production to prevent exposure of internal details.",
            "InsecureConfiguration": "Review and disable insecure options (e.g., eval, dynamic loading, root login).",
            "EncryptionDisabled": "Enable encryption to protect data at rest.",
            "MFADisabled": "Enable MFA to secure access.",
            "WeakPassword": "Use a stronger password or integrate with a secrets management system.",
            "OpenPortExposure": "Restrict access to open ports using firewalls or security groups.",
            "PrivilegedContainer": "Avoid running containers in privileged mode; run with least privileges.",
            "PublicAccessEnabled": "Restrict public access by applying proper access controls and encryption.",
            "OverlyPermissiveIAMRole": "Limit permissions to only what is strictly necessary.",
            "WideOpenSecurityGroup": "Restrict inbound/outbound traffic to specific IP ranges.",
            "IAMPolicyOverlyPermissive": "Review and tighten IAM policy bindings.",
            "CloudFrontInsecure": "Configure CloudFront to enforce HTTPS.",
            "OSLoginDisabled": "Enable OS Login on compute instances for better security.",
            "ShieldedVMDisabled": "Enable Shielded VM features.",
            "SerialPortDebugEnabled": "Disable serial port debugging in production.",
            "LoggingMonitoringDisabled": "Enable logging and monitoring for better observability.",
            "LegacyABACEnabled": "Disable legacy ABAC; enable RBAC and network policies on container clusters.",
            "NoKeyRotation": "Enable key rotation to improve key security.",
            "CloudTrailMisconfigured": "Enable multi-region trails, log file validation, and encryption for CloudTrail.",
            "RunAsRoot": "Avoid running containers as root (use non-root UID).",
            "LatestTagUsed": "Avoid using ':latest' tag; pin a specific version.",
            "MissingResourceLimits": "Set container resource limits (CPU/Memory).",
            "MissingReadOnlyRootFilesystem": "Enable readOnlyRootFilesystem in container securityContext."
        }
        vtype = vuln.get("type")
        vuln["remediation"] = remediation_dict.get(vtype, "Review configuration and apply security best practices.")
        return vuln

    def create_vulnerability(self, vuln_type, key_path, message, severity):
        vuln = {
            "type": vuln_type,
            "key": key_path,
            "message": message,
            "severity": severity
        }
        return self.add_remediation(vuln)

    #general checks

    def check_sensitive_keys(self, config, parent_key=""):
        """
        Recursively checks for short plain-text secrets (password, secret, api_key, token).
        """
        vulnerabilities = []
        if isinstance(config, dict):
            for key, value in config.items():
                key_path = f"{parent_key}.{key}" if parent_key else key
                lower_key = key.lower()
                if any(term in lower_key for term in ["password", "secret", "api_key", "token"]):
                    if isinstance(value, str):
                        # If length <20 or not "ENC(" => SensitiveInformationExposure
                        if len(value) < 20 or not value.startswith("ENC("):
                            vulnerabilities.append(self.create_vulnerability(
                                "SensitiveInformationExposure",
                                key_path,
                                f"Key '{key_path}' may contain sensitive data in plain text.",
                                "High"
                            ))
                vulnerabilities.extend(self.check_sensitive_keys(value, key_path))
        elif isinstance(config, list):
            for index, item in enumerate(config):
                key_path = f"{parent_key}[{index}]"
                vulnerabilities.extend(self.check_sensitive_keys(item, key_path))
        return vulnerabilities

    def check_debug_flags(self, config, parent_key=""):
        """
        Recursively checks for "debug": true
        """
        vulnerabilities = []
        if isinstance(config, dict):
            for key, value in config.items():
                key_path = f"{parent_key}.{key}" if parent_key else key
                if key.lower() == "debug" and isinstance(value, bool) and value:
                    vulnerabilities.append(self.create_vulnerability(
                        "DebugModeEnabled",
                        key_path,
                        f"Debug mode is enabled at '{key_path}'.",
                        "Medium"
                    ))
                vulnerabilities.extend(self.check_debug_flags(value, key_path))
        elif isinstance(config, list):
            for index, item in enumerate(config):
                key_path = f"{parent_key}[{index}]"
                vulnerabilities.extend(self.check_debug_flags(item, key_path))
        return vulnerabilities

    def check_insecure_configurations(self, config, parent_key=""):
        """
        Checks for use_eval, allow_dynamic_loading, allow_root_login => InsecureConfiguration
        """
        vulnerabilities = []
        if isinstance(config, dict):
            for key, value in config.items():
                key_path = f"{parent_key}.{key}" if parent_key else key
                if key.lower() in ["use_eval", "allow_dynamic_loading", "allow_root_login"] and value is True:
                    vulnerabilities.append(self.create_vulnerability(
                        "InsecureConfiguration",
                        key_path,
                        f"Key '{key_path}' is set to True, indicating an insecure configuration.",
                        "High"
                    ))
                vulnerabilities.extend(self.check_insecure_configurations(value, key_path))
        elif isinstance(config, list):
            for index, item in enumerate(config):
                key_path = f"{parent_key}[{index}]"
                vulnerabilities.extend(self.check_insecure_configurations(item, key_path))
        return vulnerabilities

    def scan_general(self, config, parent_key=""):
        """
        Combines all general checks: sensitive keys, debug flags, insecure configs
        """
        vulns = []
        vulns.extend(self.check_sensitive_keys(config, parent_key))
        vulns.extend(self.check_debug_flags(config, parent_key))
        vulns.extend(self.check_insecure_configurations(config, parent_key))
        return vulns

    #resources checks

    def scan_resources(self, config):
        """
        Scans known "resources" array for AWS/Azure/GCP resource misconfigurations
        """
        vulnerabilities = []
        resources = config.get("resources", [])
        if not isinstance(resources, list):
            return vulnerabilities

        for idx, res in enumerate(resources):
            res_key = f"resources[{idx}]"
            rtype = str(res.get("type", "")).lower().strip()

            #aws ec2 instances
            if rtype == "ec2_instance":
                password = res.get("password", "")
                if password and (len(password) < 8 or "weak" in password.lower()):
                    vulnerabilities.append(self.create_vulnerability(
                        "WeakPassword",
                        f"{res_key}.password",
                        f"EC2 Instance '{res.get('name')}' is using a weak password.",
                        "High"
                    ))
                if res.get("encryption") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "EncryptionDisabled",
                        f"{res_key}.encryption",
                        f"EC2 Instance '{res.get('name')}' is not encrypted.",
                        "High"
                    ))
                if res.get("mfa_enabled") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "MFADisabled",
                        f"{res_key}.mfa_enabled",
                        f"EC2 Instance '{res.get('name')}' does not have MFA enabled.",
                        "Medium"
                    ))
                if res.get("allow_root_login") is True:
                    vulnerabilities.append(self.create_vulnerability(
                        "InsecureConfiguration",
                        f"{res_key}.allow_root_login",
                        f"EC2 Instance '{res.get('name')}' allows root login.",
                        "High"
                    ))
                open_ports = res.get("open_ports", [])
                if any(port in open_ports for port in [22, 3389]):
                    vulnerabilities.append(self.create_vulnerability(
                        "OpenPortExposure",
                        f"{res_key}.open_ports",
                        f"EC2 Instance '{res.get('name')}' has sensitive ports open (SSH/RDP).",
                        "Medium"
                    ))

            #aws s3 buckets
            elif rtype == "s3_bucket":
                if res.get("public_read_access") is True or res.get("public_write_access") is True:
                    vulnerabilities.append(self.create_vulnerability(
                        "PublicAccessEnabled",
                        res_key,
                        f"S3 Bucket '{res.get('name')}' has public access enabled.",
                        "High"
                    ))
                if res.get("encryption") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "EncryptionDisabled",
                        f"{res_key}.encryption",
                        f"S3 Bucket '{res.get('name')}' is not encrypted.",
                        "High"
                    ))

            #aws iam roles
            elif rtype == "iam_role":
                permissions = res.get("permissions", [])
                for perm in permissions:
                    actions = perm.get("Action")
                    if isinstance(actions, str):
                        actions = [actions]
                    if actions and "*" in actions:
                        vulnerabilities.append(self.create_vulnerability(
                            "OverlyPermissiveIAMRole",
                            f"{res_key}.permissions",
                            f"IAM Role '{res.get('name')}' grants overly permissive access.",
                            "High"
                        ))

            #aws rds instances
            elif rtype == "rds_instance":
                if res.get("storage_encrypted") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "EncryptionDisabled",
                        f"{res_key}.storage_encrypted",
                        f"RDS Instance '{res.get('name')}' is not encrypted.",
                        "High"
                    ))
                if res.get("public_access") is True:
                    vulnerabilities.append(self.create_vulnerability(
                        "PublicAccessEnabled",
                        f"{res_key}.public_access",
                        f"RDS Instance '{res.get('name')}' is publicly accessible.",
                        "High"
                    ))
                if res.get("mfa_enabled") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "MFADisabled",
                        f"{res_key}.mfa_enabled",
                        f"RDS Instance '{res.get('name')}' does not have MFA enabled.",
                        "Medium"
                    ))

            #aws security groups
            elif rtype == "security_group":
                rules = res.get("rules", [])
                for rule in rules:
                    source = rule.get("source") or rule.get("destination")
                    if source == "0.0.0.0/0":
                        vulnerabilities.append(self.create_vulnerability(
                            "WideOpenSecurityGroup",
                            f"{res_key}.rules",
                            f"Security Group '{res.get('name')}' allows unrestricted access.",
                            "High"
                        ))

            #azure storage
            elif rtype == "storage_account":
                public_access = str(res.get("public_access", "")).lower()
                if public_access not in ["none", ""]:
                    vulnerabilities.append(self.create_vulnerability(
                        "PublicAccessEnabled",
                        f"{res_key}.public_access",
                        f"Storage Account '{res.get('name')}' has public access '{res.get('public_access')}'.",
                        "High"
                    ))
                if res.get("encryption_enabled") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "EncryptionDisabled",
                        f"{res_key}.encryption_enabled",
                        f"Storage Account '{res.get('name')}' is not encrypted.",
                        "High"
                    ))
                if res.get("soft_delete_enabled") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "InsecureConfiguration",
                        f"{res_key}.soft_delete_enabled",
                        f"Storage Account '{res.get('name')}' does not have soft delete enabled.",
                        "Medium"
                    ))

            #azure key vault
            elif rtype == "key_vault":
                if res.get("public_network_access") is True:
                    vulnerabilities.append(self.create_vulnerability(
                        "PublicAccessEnabled",
                        f"{res_key}.public_network_access",
                        f"Key Vault '{res.get('name')}' has public network access enabled.",
                        "High"
                    ))
                if res.get("firewall_enabled") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "InsecureConfiguration",
                        f"{res_key}.firewall_enabled",
                        f"Key Vault '{res.get('name')}' does not have a firewall enabled.",
                        "Medium"
                    ))
                if res.get("soft_delete_enabled") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "InsecureConfiguration",
                        f"{res_key}.soft_delete_enabled",
                        f"Key Vault '{res.get('name')}' does not have soft delete enabled.",
                        "Medium"
                    ))

            #azure vm
            elif rtype == "virtual_machine":
                password = res.get("password", "")
                if password and (len(password) < 8 or "weak" in password.lower()):
                    vulnerabilities.append(self.create_vulnerability(
                        "WeakPassword",
                        f"{res_key}.password",
                        f"Virtual Machine '{res.get('name')}' is using a weak password.",
                        "High"
                    ))
                encryption_flag = res.get("encryption")
                os_disk_flag = res.get("os_disk_encryption_enabled")
                if encryption_flag is False or os_disk_flag is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "EncryptionDisabled",
                        f"{res_key}.encryption",
                        f"Virtual Machine '{res.get('name')}' is not encrypted.",
                        "High"
                    ))
                if res.get("boot_diagnostics_enabled") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "InsecureConfiguration",
                        f"{res_key}.boot_diagnostics_enabled",
                        f"Virtual Machine '{res.get('name')}' does not have boot diagnostics enabled.",
                        "Medium"
                    ))
                if res.get("just_in_time_access_enabled") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "InsecureConfiguration",
                        f"{res_key}.just_in_time_access_enabled",
                        f"Virtual Machine '{res.get('name')}' does not have JIT access enabled.",
                        "Medium"
                    ))
                open_ports = res.get("open_ports", [])
                if any(port in open_ports for port in [22, 3389]):
                    vulnerabilities.append(self.create_vulnerability(
                        "OpenPortExposure",
                        f"{res_key}.open_ports",
                        f"Virtual Machine '{res.get('name')}' has sensitive ports open.",
                        "Medium"
                    ))

            #gcp compute instance
            elif rtype == "compute_instance":
                password = res.get("password", "")
                if password and (len(password) < 8 or "weak" in password.lower()):
                    vulnerabilities.append(self.create_vulnerability(
                        "WeakPassword",
                        f"{res_key}.password",
                        f"Compute Instance '{res.get('name')}' is using a weak password.",
                        "High"
                    ))
                if res.get("disk_encryption") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "EncryptionDisabled",
                        f"{res_key}.disk_encryption",
                        f"Compute Instance '{res.get('name')}' is not encrypted.",
                        "High"
                    ))
                if res.get("mfa_enabled") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "MFADisabled",
                        f"{res_key}.mfa_enabled",
                        f"Compute Instance '{res.get('name')}' does not have MFA enabled.",
                        "Medium"
                    ))
                open_ports = res.get("open_ports", [])
                if any(port in open_ports for port in [22, 3389]):
                    vulnerabilities.append(self.create_vulnerability(
                        "OpenPortExposure",
                        f"{res_key}.open_ports",
                        f"Compute Instance '{res.get('name')}' has sensitive ports open (SSH/RDP).",
                        "Medium"
                    ))

            #gcp firewall
            elif rtype == "firewall_rule":
                rules = res.get("rules", [])
                for rule in rules:
                    source = rule.get("source")
                    if source == "0.0.0.0/0":
                        vulnerabilities.append(self.create_vulnerability(
                            "WideOpenSecurityGroup",
                            f"{res_key}.rules",
                            f"Firewall Rule '{res.get('name')}' allows unrestricted access.",
                            "High"
                        ))

            #gcp container cluster
            elif rtype == "container_cluster":
                if res.get("legacy_abac_enabled") is True:
                    vulnerabilities.append(self.create_vulnerability(
                        "LegacyABACEnabled",
                        f"{res_key}.legacy_abac_enabled",
                        f"Container Cluster '{res.get('name')}' has legacy ABAC enabled.",
                        "High"
                    ))
                if res.get("basic_auth_enabled") is True:
                    vulnerabilities.append(self.create_vulnerability(
                        "InsecureConfiguration",
                        f"{res_key}.basic_auth_enabled",
                        f"Container Cluster '{res.get('name')}' uses basic auth, which is insecure.",
                        "High"
                    ))

            #gcp logging and monitoring
            elif rtype == "cloud_logging":
                if res.get("enabled") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "LoggingMonitoringDisabled",
                        f"{res_key}.enabled",
                        f"Cloud Logging '{res.get('name')}' is disabled.",
                        "Medium"
                    ))
            elif rtype == "cloud_monitoring":
                if res.get("enabled") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "LoggingMonitoringDisabled",
                        f"{res_key}.enabled",
                        f"Cloud Monitoring '{res.get('name')}' is disabled.",
                        "Medium"
                    ))

            #gcp iam policy
            elif rtype == "iam_policy":
                bindings = res.get("bindings", [])
                for binding in bindings:
                    role = binding.get("role", "").lower()
                    members = binding.get("members", [])
                    if role == "roles/owner" and any(m.lower() in ["allusers", "everyone"] for m in members):
                        vulnerabilities.append(self.create_vulnerability(
                            "OverlyPermissiveIAMRole",
                            f"{res_key}.iam_policy",
                            f"IAM Policy '{res.get('name')}' grants overly permissive access.",
                            "High"
                        ))

            #gcp cloud sql
            elif rtype == "cloud_sql":
                if res.get("disk_encryption") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "EncryptionDisabled",
                        f"{res_key}.disk_encryption",
                        f"Cloud SQL Instance '{res.get('name')}' is not encrypted.",
                        "High"
                    ))
                if res.get("public_access") is True:
                    vulnerabilities.append(self.create_vulnerability(
                        "PublicAccessEnabled",
                        f"{res_key}.public_access",
                        f"Cloud SQL Instance '{res.get('name')}' is publicly accessible.",
                        "High"
                    ))
                if res.get("require_ssl") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "InsecureConfiguration",
                        f"{res_key}.require_ssl",
                        f"Cloud SQL Instance '{res.get('name')}' does not require SSL.",
                        "Medium"
                    ))
                if res.get("root_password") and (len(res.get("root_password")) < 8 or "weak" in res.get("root_password").lower()):
                    vulnerabilities.append(self.create_vulnerability(
                        "WeakPassword",
                        f"{res_key}.root_password",
                        f"Cloud SQL Instance '{res.get('name')}' is using a weak root password.",
                        "High"
                    ))
                if res.get("mfa_enabled") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "MFADisabled",
                        f"{res_key}.mfa_enabled",
                        f"Cloud SQL Instance '{res.get('name')}' does not have MFA enabled.",
                        "Medium"
                    ))

            #gcp bq
            elif rtype == "bigquery_dataset":
                if res.get("public_access") is True:
                    vulnerabilities.append(self.create_vulnerability(
                        "PublicAccessEnabled",
                        f"{res_key}.public_access",
                        f"BigQuery Dataset '{res.get('name')}' is publicly accessible.",
                        "High"
                    ))
                if str(res.get("encryption", "")).upper() == "NONE":
                    vulnerabilities.append(self.create_vulnerability(
                        "EncryptionDisabled",
                        f"{res_key}.encryption",
                        f"BigQuery Dataset '{res.get('name')}' is not encrypted.",
                        "High"
                    ))

            #gcp dns mz
            elif rtype == "dns_managed_zone":
                if str(res.get("visibility", "")).lower().strip() == "public":
                    vulnerabilities.append(self.create_vulnerability(
                        "PublicAccessEnabled",
                        f"{res_key}.visibility",
                        f"DNS Managed Zone '{res.get('name')}' is publicly visible.",
                        "Medium"
                    ))

            #aws cloud trail
            elif rtype == "cloudtrail":
                if res.get("multi_region_trail") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "CloudTrailMisconfigured",
                        f"{res_key}.multi_region_trail",
                        f"CloudTrail '{res.get('name')}' is not configured for multi-region trails.",
                        "Medium"
                    ))
                if res.get("log_file_validation_enabled") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "CloudTrailMisconfigured",
                        f"{res_key}.log_file_validation_enabled",
                        f"CloudTrail '{res.get('name')}' does not have log file validation enabled.",
                        "Medium"
                    ))
                if res.get("encrypted") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "EncryptionDisabled",
                        f"{res_key}.encrypted",
                        f"CloudTrail '{res.get('name')}' is not encrypted.",
                        "High"
                    ))

            #aws kms keys
            elif rtype == "kms_key":
                if res.get("rotation_enabled") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "NoKeyRotation",
                        f"{res_key}.rotation_enabled",
                        f"KMS Key '{res.get('name')}' does not have key rotation enabled.",
                        "Medium"
                    ))

            #aws iam users
            elif rtype == "iam_user":
                if res.get("mfa_enabled") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "MFADisabled",
                        f"{res_key}.mfa_enabled",
                        f"IAM User '{res.get('name')}' does not have MFA enabled.",
                        "Medium"
                    ))
                inline_policies = res.get("inline_policies", [])
                for policy in inline_policies:
                    doc = policy.get("PolicyDocument", {})
                    statements = doc.get("Statement", [])
                    for stmt in statements:
                        action = stmt.get("Action")
                        if isinstance(action, str):
                            action = [action]
                        if action and "*" in action:
                            vulnerabilities.append(self.create_vulnerability(
                                "OverlyPermissiveIAMRole",
                                f"{res_key}.inline_policies",
                                f"IAM User '{res.get('name')}' has an overly permissive inline policy.",
                                "High"
                            ))

            #aws lambda function
            elif rtype == "lambda_function":
                permissions = res.get("lambda_permissions", [])
                for perm in permissions:
                    action = perm.get("Action")
                    if isinstance(action, str):
                        action = [action]
                    if action and "*" in action:
                        vulnerabilities.append(self.create_vulnerability(
                            "OverlyPermissiveIAMRole",
                            f"{res_key}.lambda_permissions",
                            f"Lambda Function '{res.get('name')}' has overly permissive permissions.",
                            "High"
                        ))

            #aws cloudfront dist
            elif rtype == "cloudfront_distribution":
                if str(res.get("viewer_protocol_policy", "")).lower() != "redirect-to-https":
                    vulnerabilities.append(self.create_vulnerability(
                        "CloudFrontInsecure",
                        f"{res_key}.viewer_protocol_policy",
                        f"CloudFront Distribution '{res.get('name')}' does not enforce HTTPS.",
                        "Medium"
                    ))

            #aws cloud config
            elif rtype == "cloud_config":
                if res.get("recording_all_resources") is False:
                    vulnerabilities.append(self.create_vulnerability(
                        "InsecureConfiguration",
                        f"{res_key}.recording_all_resources",
                        f"Cloud Config '{res.get('name')}' is not recording all resources.",
                        "Medium"
                    ))

            else:
                #resrouce type not recognized
                pass

        return vulnerabilities

    #Knative service objects
    def check_knative_service(self, config):
        vulnerabilities = []

        metadata = config.get("metadata", {})
        ann = metadata.get("annotations", {})
        mfa_value = ann.get("security.knative.dev/mfaEnabled")
        if isinstance(mfa_value, str) and mfa_value.lower() == "false":
            vulnerabilities.append(self.create_vulnerability(
                "MFADisabled",
                "metadata.annotations.security.knative.dev/mfaEnabled",
                "Knative Service has MFA disabled in annotation.",
                "Medium"
            ))

        template = config.get("spec", {}).get("template", {})
        container_spec = template.get("spec", {})
        containers = container_spec.get("containers", [])
        for idx, c in enumerate(containers):
            c_key = f"spec.template.spec.containers[{idx}]"
            image = c.get("image", "")
            #image ends with ":latest"?
            if image.endswith(":latest"):
                vulnerabilities.append(self.create_vulnerability(
                    "LatestTagUsed",
                    f"{c_key}.image",
                    "Container uses ':latest' tag => not pinned to version.",
                    "Medium"
                ))
            security_ctx = c.get("securityContext", {})
            privileged = security_ctx.get("privileged", False)
            if privileged:
                vulnerabilities.append(self.create_vulnerability(
                    "PrivilegedContainer",
                    f"{c_key}.securityContext.privileged",
                    "Container is running in privileged mode.",
                    "High"
                ))
            run_as_user = security_ctx.get("runAsUser")
            if run_as_user == 0:
                vulnerabilities.append(self.create_vulnerability(
                    "RunAsRoot",
                    f"{c_key}.securityContext.runAsUser",
                    "Container is running as root (UID 0).",
                    "High"
                ))
            #readOnlyRootFilesystem?
            ro_fs = security_ctx.get("readOnlyRootFilesystem")
            if ro_fs is not True:
                vulnerabilities.append(self.create_vulnerability(
                    "MissingReadOnlyRootFilesystem",
                    f"{c_key}.securityContext.readOnlyRootFilesystem",
                    "Container filesystem is not read-only.",
                    "Medium"
                ))
            #SECRET_KEY in env?
            envs = c.get("env", [])
            for env_item in envs:
                if env_item.get("name", "").lower() == "secret_key":
                    secret_val = env_item.get("value", "")
                    if len(secret_val) < 20 or not secret_val.startswith("ENC("):
                        vulnerabilities.append(self.create_vulnerability(
                            "SensitiveInformationExposure",
                            f"{c_key}.env SECRET_KEY",
                            "Knative container has plain-text SECRET_KEY environment variable.",
                            "High"
                        ))
            #res limits?
            resources_block = c.get("resources", {})
            limits = resources_block.get("limits")
            if not limits:
                vulnerabilities.append(self.create_vulnerability(
                    "MissingResourceLimits",
                    f"{c_key}.resources.limits",
                    "Container is missing resource limits (CPU/Memory).",
                    "Medium"
                ))

        return vulnerabilities

    def scan(self, config, report_format="dict"):
        vulnerabilities = []
        vulnerabilities.extend(self.scan_general(config))
        vulnerabilities.extend(self.scan_resources(config))

        if (config.get("kind") == "Service"
            and isinstance(config.get("apiVersion"), str)
            and config["apiVersion"].startswith("serving.knative.dev/")):
            vulnerabilities.extend(self.check_knative_service(config))

        #de-duplicate vuls
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
        lines = ["Vulnerability Scan Report\n"]
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
