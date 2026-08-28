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

        if max_age == 0:
            findings.append({
                "category": "Password Policy",
                "severity": "HIGH",
                "title": "Password Never Expires (Domain-wide)",
                "description": (
                    "The domain password policy has 'maximum password age' set to 0 "
                    "(passwords never expire). Combined with weak monitoring, a single "
                    "compromised credential can remain valid indefinitely. Recommended: "
                    "enforce a rotation interval of 60-90 days per NIST SP 800-63B, or, "
                    "if adopting NIST's modern non-expiration guidance, ensure this is "
                    "paired with mandatory MFA, breach-based forced resets, and active "
                    "credential monitoring rather than left unmanaged by default."
                )
            })
        elif max_age > 90:
            findings.append({
                "category": "Password Policy",
                "severity": "MEDIUM",
                "title": "Password Rotation Interval Too Long",
                "description": (
                    f"Maximum password age is set to {max_age} days (Recommended: 60-90 "
                    "days per NIST SP 800-63B). Long rotation windows increase the "
                    "exposure window for a compromised credential; if the domain instead "
                    "intends to rely on non-expiring passwords, this should be an explicit "
                    "decision backed by MFA and compromise-detection controls, not simply "
                    "a large default value."
                )
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

        # --- Score calculation ---
        # Domain-wide findings (password policy / account lockout) apply equally
        # regardless of domain size, so they keep a flat per-finding weight.
        pwd_high = sum(1 for f in pwd_findings if f["severity"] == "HIGH")
        pwd_medium = sum(1 for f in pwd_findings if f["severity"] == "MEDIUM")

        # Per-account findings (Privileged Accounts / Stale Accounts) are
        # normalized against the size of the audited account population: two
        # compromised admins out of 10 accounts is a far worse security posture
        # than the same two compromised admins out of 10,000 accounts, so a flat
        # per-finding weight would understate risk for small domains and
        # overstate it for large ones. We scale the per-finding weight by
        # ACCOUNT_SCORE_REFERENCE / total_accounts, capped at 1.0, so domains at
        # or below the reference size keep the historical flat-weight scoring,
        # while larger domains see proportionally reduced penalties for the same
        # absolute number of compromised accounts.
        ACCOUNT_SCORE_REFERENCE = 10
        acc_high = sum(1 for f in acc_findings if f["severity"] == "HIGH")
        acc_medium = sum(1 for f in acc_findings if f["severity"] == "MEDIUM")
        total_accounts = max(1, len(accounts))
        account_scale = min(1.0, ACCOUNT_SCORE_REFERENCE / total_accounts)

        penalty = (pwd_high * 20) + (pwd_medium * 10) \
            + (acc_high * 20 * account_scale) + (acc_medium * 10 * account_scale)

        score = max(0, round(100 - penalty))

        return {
            "score": score,
            "total_findings": len(all_findings),
            "high_severity": high_count,
            "medium_severity": medium_count,
            "findings": all_findings
        }
