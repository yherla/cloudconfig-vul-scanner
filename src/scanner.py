import json

class VulnerabilityScanner:
    def __init__(self, opa_policy_url=None):
        self.opa_policy_url = opa_policy_url

    def add_remediation(self, vuln):
        remediation_dict = {
            "SensitiveInformationExposure": "Use encryption or a secret manager to store sensitive data; do not use plain text values.",
            "DebugModeEnabled": "Disable debug mode in production to prevent exposure of internal details.",
            "InsecureConfiguration": "Review your configuration and disable insecure options such as eval or dynamic loading.",
            "EncryptionDisabled": "Enable encryption to protect data at rest.",
            "MFADisabled": "Enable MFA to secure access.",
            "WeakPassword": "Use a stronger password or integrate with a secrets management system.",
            "OpenPortExposure": "Restrict access to open ports using firewalls or security groups.",
            "PrivilegedContainer": "Avoid running containers in privileged mode; ensure the container runs with the least privileges."
        }
        vtype = vuln.get("type")
        vuln["remediation"] = remediation_dict.get(vtype, "Review configuration and apply security best practices.")
        return vuln

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
                if key.lower() in ["use_eval", "allow_dynamic_loading"] and value is True:
                    vuln = {
                        "type": "InsecureConfiguration",
                        "key": key_path,
                        "message": f"Key '{key_path}' is set to True, which may indicate an insecure configuration.",
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

    def scan_resources(self, config):
        vulnerabilities = []
        resources = config.get("resources")
        if isinstance(resources, list):
            for idx, res in enumerate(resources):
                res_key = f"resources[{idx}]"
                rtype = res.get("type", "").lower()
                if rtype == "virtual_machine":
                    password = res.get("password", "")
                    if password and (len(password) < 8 or "weak" in password.lower()):
                        vuln = {
                            "type": "WeakPassword",
                            "key": f"{res_key}.password",
                            "message": f"VM '{res.get('name')}' is using a weak password.",
                            "severity": "High"
                        }
                        vulnerabilities.append(self.add_remediation(vuln))
                    if res.get("encryption") is False:
                        vuln = {
                            "type": "EncryptionDisabled",
                            "key": f"{res_key}.encryption",
                            "message": f"VM '{res.get('name')}' is not encrypted.",
                            "severity": "High"
                        }
                        vulnerabilities.append(self.add_remediation(vuln))
                    if res.get("mfa_enabled") is False:
                        vuln = {
                            "type": "MFADisabled",
                            "key": f"{res_key}.mfa_enabled",
                            "message": f"VM '{res.get('name')}' does not have MFA enabled.",
                            "severity": "Medium"
                        }
                        vulnerabilities.append(self.add_remediation(vuln))
                    open_ports = res.get("open_ports", [])
                    if 22 in open_ports:
                        vuln = {
                            "type": "OpenPortExposure",
                            "key": f"{res_key}.open_ports",
                            "message": f"VM '{res.get('name')}' has port 22 open, which may expose SSH access.",
                            "severity": "Medium"
                        }
                        vulnerabilities.append(self.add_remediation(vuln))
                elif rtype == "storage_account":
                    if res.get("encryption") is False:
                        vuln = {
                            "type": "EncryptionDisabled",
                            "key": f"{res_key}.encryption",
                            "message": f"Storage account '{res.get('name')}' is not encrypted.",
                            "severity": "High"
                        }
                        vulnerabilities.append(self.add_remediation(vuln))
                elif rtype == "database":
                    if res.get("encryption") is False:
                        vuln = {
                            "type": "EncryptionDisabled",
                            "key": f"{res_key}.encryption",
                            "message": f"Database '{res.get('name')}' is not encrypted.",
                            "severity": "High"
                        }
                        vulnerabilities.append(self.add_remediation(vuln))
                    if res.get("mfa_enabled") is False:
                        vuln = {
                            "type": "MFADisabled",
                            "key": f"{res_key}.mfa_enabled",
                            "message": f"Database '{res.get('name')}' does not have MFA enabled.",
                            "severity": "Medium"
                        }
                        vulnerabilities.append(self.add_remediation(vuln))
                    open_ports = res.get("open_ports", [])
                    if open_ports:
                        vuln = {
                            "type": "OpenPortExposure",
                            "key": f"{res_key}.open_ports",
                            "message": f"Database '{res.get('name')}' has open ports, which may expose it to attacks.",
                            "severity": "Medium"
                        }
                        vulnerabilities.append(self.add_remediation(vuln))
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
            import json
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
