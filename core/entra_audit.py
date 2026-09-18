"""
Yggdrasil - Microsoft 365 & Entra ID Security Posture Auditor.

Assesses cloud identity security in hybrid/cloud SME environments:
  - MFA Enforcement (Privileged Admins & Regular Users)
  - Global Administrator count and privilege sprawl (Least Privilege)
  - Legacy Authentication protocol exposure (Basic Auth / POP / IMAP)
  - Guest and orphan account management (>90 days inactive)
  - Alignment with CIS Microsoft 365 Foundations Benchmark & NIS2 Art. 21
"""

import datetime
from typing import Dict, List, Any, Optional


class EntraSecurityAuditor:
    """
    Audits Microsoft Entra ID (Azure AD) and Microsoft 365 tenant configurations.

    Operates only on data you already have: a JSON export you provide via
    --input, or simulated data if you don't. There is no Microsoft Graph API
    connector anywhere in this module or the suite - it does not fetch
    anything from a live tenant on its own. Producing that JSON export today
    requires a separate script/PowerShell (e.g. via Microsoft Graph
    PowerShell SDK) that this suite does not currently provide.
    """

    def __init__(self, tenant_domain: str = "tenant.onmicrosoft.com"):
        self.tenant_domain = tenant_domain

    def audit_tenant(
        self,
        users: List[Dict[str, Any]],
        roles: Optional[List[Dict[str, Any]]] = None,
        tenant_policies: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Executes a comprehensive cloud identity audit over provided tenant data.
        """
        roles = roles or []
        tenant_policies = tenant_policies or {}

        findings: List[Dict[str, Any]] = []
        score_deductions = 0

        # 1. Audit Global Admins & Privileged Roles
        admin_finding, admin_penalty = self._audit_admins(users, roles)
        if admin_finding:
            findings.extend(admin_finding)
            score_deductions += admin_penalty

        # 2. Audit MFA Enforcement
        mfa_findings, mfa_penalty = self._audit_mfa(users)
        findings.extend(mfa_findings)
        score_deductions += mfa_penalty

        # 3. Audit Legacy Authentication Protocols
        legacy_finding, legacy_penalty = self._audit_legacy_auth(tenant_policies)
        if legacy_finding:
            findings.append(legacy_finding)
            score_deductions += legacy_penalty

        # 4. Audit Inactive Guests / Stale Accounts
        guest_findings, guest_penalty = self._audit_guests_and_stale(users)
        findings.extend(guest_findings)
        score_deductions += guest_penalty

        final_score = max(0, 100 - score_deductions)

        return {
            "tenant_domain": self.tenant_domain,
            "audit_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "score": final_score,
            "posture": "ECCELLENTE" if final_score >= 85 else ("SUFFICIENTE" if final_score >= 60 else "CRITICO"),
            "total_users": len(users),
            "findings_count": len(findings),
            "findings": findings,
            "summary": {
                "critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
                "high": sum(1 for f in findings if f.get("severity") == "HIGH"),
                "medium": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
                "low": sum(1 for f in findings if f.get("severity") == "LOW"),
            }
        }

    def _audit_admins(
        self, users: List[Dict[str, Any]], roles: List[Dict[str, Any]]
    ) -> tuple[List[Dict[str, Any]], int]:
        findings = []
        deductions = 0

        global_admins = []
        for role in roles:
            if role.get("displayName") in ["Global Administrator", "Amministratore globale"]:
                global_admins = role.get("members", [])
                break

        # Also check direct user flags
        for u in users:
            if u.get("is_global_admin") and u.get("userPrincipalName") not in [m.get("userPrincipalName") for m in global_admins]:
                global_admins.append(u)

        admin_count = len(global_admins)
        if admin_count > 5:
            findings.append({
                "id": "M365-ADMIN-01",
                "title": "Eccesso di Amministratori Globali (Privilege Sprawl)",
                "severity": "HIGH",
                "description": f"Rilevati {admin_count} Amministratori Globali. La best-practice CIS/Microsoft raccomanda tra 2 e 4 admin.",
                "remediation": "Revocare il ruolo di Global Administrator agli account che non ne necessitano e assegnare ruoli con minimi privilegi (es. Helpdesk Admin, User Admin).",
                "affected_entities": [a.get("userPrincipalName") for a in global_admins],
            })
            deductions += 15
        elif admin_count == 0:
            # Fallback warning if no admin mapped
            pass

        # Check if any admin lacks MFA
        for admin in global_admins:
            upn = admin.get("userPrincipalName", "")
            # Cross-reference with users list for MFA status
            user_obj = next((u for u in users if u.get("userPrincipalName") == upn), admin)
            if not user_obj.get("mfa_enabled", False):
                findings.append({
                    "id": "M365-ADMIN-02",
                    "title": f"Amministratore senza MFA obbligatoria ({upn})",
                    "severity": "CRITICAL",
                    "description": f"L'account amministrativo '{upn}' non ha il Multi-Factor Authentication abilitato.",
                    "remediation": "Applicare immediatamente una policy di Conditional Access che imponga Phishing-Resistant MFA su tutti i ruoli amministrativi.",
                    "affected_entities": [upn],
                })
                deductions += 25

        return findings, deductions

    def _audit_mfa(self, users: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], int]:
        findings = []
        deductions = 0
        if not users:
            return findings, deductions

        no_mfa_users = [u for u in users if not u.get("mfa_enabled", False) and u.get("accountEnabled", True)]
        pct_no_mfa = (len(no_mfa_users) / len(users)) * 100

        if pct_no_mfa > 30:
            findings.append({
                "id": "M365-MFA-01",
                "title": "Bassa Adozione Multi-Factor Authentication (MFA)",
                "severity": "HIGH",
                "description": f"Il {pct_no_mfa:.1f}% degli utenti ({len(no_mfa_users)}/{len(users)}) non ha MFA abilitato.",
                "remediation": "Abilitare i Security Defaults di Microsoft Entra o creare una Conditional Access Policy per richiedere MFA a tutti gli utenti.",
                "affected_entities": [u.get("userPrincipalName") for u in no_mfa_users[:10]],
            })
            deductions += 20
        elif pct_no_mfa > 0:
            findings.append({
                "id": "M365-MFA-02",
                "title": "Account Attivi Senza MFA",
                "severity": "MEDIUM",
                "description": f"{len(no_mfa_users)} account aziendali attivi non hanno ancora configurato l'MFA.",
                "remediation": "Notificare gli utenti per la registrazione di Microsoft Authenticator o FIDO2 token.",
                "affected_entities": [u.get("userPrincipalName") for u in no_mfa_users[:5]],
            })
            deductions += 10

        return findings, deductions

    def _audit_legacy_auth(self, policies: Dict[str, Any]) -> tuple[Optional[Dict[str, Any]], int]:
        if policies.get("legacy_auth_allowed", False):
            return {
                "id": "M365-AUTH-01",
                "title": "Autenticazione Legacy Abilitata (POP3/IMAP/SMTP Basic)",
                "severity": "HIGH",
                "description": "Il tenant consente l'autenticazione tramite protocolli legacy che bypassano l'MFA ed espongono a password-spray attack.",
                "remediation": "Bloccare i protocolli Legacy Authentication tramite Criteri di Accesso Condizionale (Conditional Access).",
                "affected_entities": ["Tenant Authentication Policy"],
            }, 20
        return None, 0

    def _audit_guests_and_stale(self, users: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], int]:
        findings = []
        deductions = 0

        stale_guests = []
        for u in users:
            if u.get("userType") == "Guest" or "#EXT#" in u.get("userPrincipalName", ""):
                days_inactive = u.get("days_since_last_signin", 0)
                if days_inactive > 90:
                    stale_guests.append(u.get("userPrincipalName"))

        if stale_guests:
            findings.append({
                "id": "M365-GUEST-01",
                "title": "Account Guest Esterni Inattivi (>90 Giorni)",
                "severity": "MEDIUM",
                "description": f"Rilevati {len(stale_guests)} account guest esterni non utilizzati da oltre 90 giorni.",
                "remediation": "Configurare le Microsoft Entra Access Reviews per rimuovere automaticamente gli accessi guest scaduti.",
                "affected_entities": stale_guests[:10],
            })
            deductions += 10

        return findings, deductions
