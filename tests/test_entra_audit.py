import pytest
from core.entra_audit import EntraSecurityAuditor


@pytest.fixture
def auditor():
    return EntraSecurityAuditor(tenant_domain="acme-corp.onmicrosoft.com")


def test_clean_tenant(auditor):
    users = [
        {"userPrincipalName": "admin@acme-corp.com", "mfa_enabled": True, "accountEnabled": True, "is_global_admin": True},
        {"userPrincipalName": "user1@acme-corp.com", "mfa_enabled": True, "accountEnabled": True, "is_global_admin": False},
        {"userPrincipalName": "user2@acme-corp.com", "mfa_enabled": True, "accountEnabled": True, "is_global_admin": False},
    ]
    roles = [
        {"displayName": "Global Administrator", "members": [users[0]]}
    ]
    policies = {"legacy_auth_allowed": False}

    res = auditor.audit_tenant(users, roles, policies)
    assert res["score"] == 100
    assert res["posture"] == "ECCELLENTE"
    assert len(res["findings"]) == 0


def test_admin_without_mfa_triggers_critical(auditor):
    users = [
        {"userPrincipalName": "superadmin@acme-corp.com", "mfa_enabled": False, "accountEnabled": True, "is_global_admin": True},
        {"userPrincipalName": "user1@acme-corp.com", "mfa_enabled": True, "accountEnabled": True, "is_global_admin": False},
    ]
    roles = [
        {"displayName": "Global Administrator", "members": [users[0]]}
    ]
    res = auditor.audit_tenant(users, roles)

    assert res["score"] < 100
    criticals = [f for f in res["findings"] if f["severity"] == "CRITICAL"]
    assert len(criticals) == 1
    assert criticals[0]["id"] == "M365-ADMIN-02"
    assert "superadmin@acme-corp.com" in criticals[0]["affected_entities"]


def test_admin_sprawl_triggers_high(auditor):
    users = [
        {"userPrincipalName": f"admin{i}@acme-corp.com", "mfa_enabled": True, "accountEnabled": True, "is_global_admin": True}
        for i in range(7)
    ]
    roles = [
        {"displayName": "Global Administrator", "members": users}
    ]
    res = auditor.audit_tenant(users, roles)

    high_findings = [f for f in res["findings"] if f["id"] == "M365-ADMIN-01"]
    assert len(high_findings) == 1
    assert "7" in high_findings[0]["description"]


def test_legacy_auth_penalty(auditor):
    users = [{"userPrincipalName": "u@a.com", "mfa_enabled": True, "accountEnabled": True}]
    policies = {"legacy_auth_allowed": True}

    res = auditor.audit_tenant(users, tenant_policies=policies)
    legacy_findings = [f for f in res["findings"] if f["id"] == "M365-AUTH-01"]
    assert len(legacy_findings) == 1
    assert res["score"] == 80


def test_stale_guests(auditor):
    users = [
        {"userPrincipalName": "john_vendor#EXT#@acme-corp.com", "userType": "Guest", "days_since_last_signin": 120, "mfa_enabled": True},
        {"userPrincipalName": "staff@acme-corp.com", "userType": "Member", "days_since_last_signin": 2, "mfa_enabled": True},
    ]
    res = auditor.audit_tenant(users)
    guest_findings = [f for f in res["findings"] if f["id"] == "M365-GUEST-01"]
    assert len(guest_findings) == 1
    assert "john_vendor#EXT#@acme-corp.com" in guest_findings[0]["affected_entities"]
