import pytest
import os
import sys
import tempfile
from core.auditor import ADAuditor
from core.reporter import ADReporter


def test_password_policy_weak_length():
    auditor = ADAuditor()
    policy = {"min_password_length": 6, "password_complexity": False, "account_lockout_threshold": 0, "maximum_password_age": 90}
    findings = auditor.audit_password_policy(policy)
    titles = [f["title"] for f in findings]
    assert "Minimum Password Length Too Short" in titles
    assert "Password Complexity Disabled" in titles
    assert "Insecure Account Lockout Threshold" in titles


def test_password_policy_strong():
    auditor = ADAuditor()
    policy = {"min_password_length": 16, "password_complexity": True, "account_lockout_threshold": 5, "maximum_password_age": 60}
    findings = auditor.audit_password_policy(policy)
    assert len(findings) == 0


def test_password_policy_medium_length():
    auditor = ADAuditor()
    policy = {"min_password_length": 10, "password_complexity": True, "account_lockout_threshold": 5, "maximum_password_age": 90}
    findings = auditor.audit_password_policy(policy)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert "Suboptimal" in findings[0]["title"]


def test_privileged_accounts_admin_never_expires():
    auditor = ADAuditor()
    accounts = [
        {"name": "Admin1", "password_never_expires": True, "inactive_days": 10, "is_domain_admin": True},
        {"name": "User1", "password_never_expires": True, "inactive_days": 5, "is_domain_admin": False}
    ]
    findings = auditor.audit_privileged_accounts(accounts)
    assert len(findings) == 1
    assert "Admin1" in findings[0]["title"]
    assert findings[0]["severity"] == "HIGH"


def test_privileged_accounts_stale():
    auditor = ADAuditor()
    accounts = [
        {"name": "StaleUser", "password_never_expires": False, "inactive_days": 120, "is_domain_admin": True}
    ]
    findings = auditor.audit_privileged_accounts(accounts)
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"
    assert "Stale" in findings[0]["title"]


def test_full_audit_score():
    auditor = ADAuditor()
    target_data = {
        "password_policy": {"min_password_length": 6, "maximum_password_age": 90, "password_complexity": False, "account_lockout_threshold": 0},
        "accounts": [
            {"name": "Administrator", "password_never_expires": True, "inactive_days": 10, "is_domain_admin": True},
            {"name": "BackupAdmin", "password_never_expires": True, "inactive_days": 120, "is_domain_admin": True},
            {"name": "john.doe", "password_never_expires": False, "inactive_days": 5, "is_domain_admin": False}
        ]
    }
    result = auditor.run_full_audit(target_data)
    assert result["score"] == 0
    assert result["high_severity"] == 4
    assert result["medium_severity"] == 2
    assert result["total_findings"] == 6


def test_full_audit_clean():
    auditor = ADAuditor()
    target_data = {
        "password_policy": {"min_password_length": 16, "maximum_password_age": 60, "password_complexity": True, "account_lockout_threshold": 5},
        "accounts": [
            {"name": "User1", "password_never_expires": False, "inactive_days": 5, "is_domain_admin": False}
        ]
    }
    result = auditor.run_full_audit(target_data)
    assert result["score"] == 100
    assert result["total_findings"] == 0


def test_reporter_generates_file():
    reporter = ADReporter(output_dir=tempfile.mkdtemp())
    audit_result = {
        "score": 0, "total_findings": 2, "high_severity": 1, "medium_severity": 1,
        "findings": [
            {"category": "Password Policy", "severity": "HIGH", "title": "Weak Password", "description": "Too short"},
            {"category": "Lockout", "severity": "MEDIUM", "title": "No Lockout", "description": "Threshold 0"}
        ]
    }
    path = reporter.generate_report("test.local", audit_result)
    assert os.path.exists(path)
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    assert "test.local" in content
    assert "Weak Password" in content
    assert "CRITICAL" in content
    os.remove(path)
