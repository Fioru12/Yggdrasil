import json
from typing import Dict, Any, List

class ADAuditor:
    """
    Audits Windows Active Directory and local security policies
    for misconfigurations, weak password policies, and privileged accounts.
    """

    def __init__(self):
        pass

    def audit_password_policy(self, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        min_length = policy.get("min_password_length", 0)
        max_age = policy.get("maximum_password_age", 0)
        complexity = policy.get("password_complexity", False)
        lockout_threshold = policy.get("account_lockout_threshold", 0)

        if min_length < 8:
            findings.append({
                "category": "Password Policy",
                "severity": "HIGH",
                "title": "Minimum Password Length Too Short",
                "description": f"Minimum password length is set to {min_length} (Recommended: >= 12)."
            })
        elif min_length < 12:
            findings.append({
                "category": "Password Policy",
                "severity": "MEDIUM",
                "title": "Suboptimal Password Length",
                "description": f"Minimum password length is set to {min_length} (Recommended: >= 12)."
            })

        if not complexity:
            findings.append({
                "category": "Password Policy",
                "severity": "HIGH",
                "title": "Password Complexity Disabled",
                "description": "Domain password complexity requirement is disabled."
            })

        if lockout_threshold == 0 or lockout_threshold > 10:
            findings.append({
                "category": "Account Lockout",
                "severity": "MEDIUM",
                "title": "Insecure Account Lockout Threshold",
                "description": f"Lockout threshold is {lockout_threshold} (Recommended: 5 attempts)."
            })

        return findings

    def audit_privileged_accounts(self, accounts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for acc in accounts:
            name = acc.get("name", "Unknown")
            never_expires = acc.get("password_never_expires", False)
            last_logon_days = acc.get("inactive_days", 0)
            is_admin = acc.get("is_domain_admin", False)

            if is_admin and never_expires:
                findings.append({
                    "category": "Privileged Accounts",
                    "severity": "HIGH",
                    "title": f"Domain Admin Password Never Expires: {name}",
                    "description": f"Privileged account {name} has 'Password Never Expires' enabled."
                })

            if last_logon_days > 90:
                findings.append({
                    "category": "Stale Accounts",
                    "severity": "MEDIUM",
                    "title": f"Stale Privileged Account: {name}",
                    "description": f"Account {name} has been inactive for {last_logon_days} days."
                })

        return findings

    def run_full_audit(self, target_data: Dict[str, Any]) -> Dict[str, Any]:
        pwd_policy = target_data.get("password_policy", {})
        accounts = target_data.get("accounts", [])

        pwd_findings = self.audit_password_policy(pwd_policy)
        acc_findings = self.audit_privileged_accounts(accounts)

        all_findings = pwd_findings + acc_findings

        high_count = sum(1 for f in all_findings if f["severity"] == "HIGH")
        medium_count = sum(1 for f in all_findings if f["severity"] == "MEDIUM")

        score = max(0, 100 - (high_count * 20) - (medium_count * 10))

        return {
            "score": score,
            "total_findings": len(all_findings),
            "high_severity": high_count,
            "medium_severity": medium_count,
            "findings": all_findings
        }
