import pytest
import os
import sys
import tempfile
from core.auditor import ADAuditor
from core.reporter import ADReporter, _sanitize_domain_name
import main as yggdrasil_main


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


def test_password_policy_max_age_never_expires():
    auditor = ADAuditor()
    policy = {"min_password_length": 16, "password_complexity": True, "account_lockout_threshold": 5, "maximum_password_age": 0}
    findings = auditor.audit_password_policy(policy)
    titles = [f["title"] for f in findings]
    assert "Password Never Expires (Domain-wide)" in titles
    match = next(f for f in findings if f["title"] == "Password Never Expires (Domain-wide)")
    assert match["severity"] == "HIGH"


def test_password_policy_max_age_too_long():
    auditor = ADAuditor()
    policy = {"min_password_length": 16, "password_complexity": True, "account_lockout_threshold": 5, "maximum_password_age": 180}
    findings = auditor.audit_password_policy(policy)
    titles = [f["title"] for f in findings]
    assert "Password Rotation Interval Too Long" in titles
    match = next(f for f in findings if f["title"] == "Password Rotation Interval Too Long")
    assert match["severity"] == "MEDIUM"
    assert "180" in match["description"]


def test_password_policy_max_age_within_recommended_range():
    auditor = ADAuditor()
    policy = {"min_password_length": 16, "password_complexity": True, "account_lockout_threshold": 5, "maximum_password_age": 90}
    findings = auditor.audit_password_policy(policy)
    titles = [f["title"] for f in findings]
    assert "Password Never Expires (Domain-wide)" not in titles
    assert "Password Rotation Interval Too Long" not in titles


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


def test_score_normalized_by_domain_size():
    """The same absolute number of compromised privileged accounts should hurt
    the score of a small domain more than a large one, since two compromised
    admins out of 10 accounts is a far worse posture than two out of 10,000."""
    auditor = ADAuditor()
    clean_policy = {"min_password_length": 16, "maximum_password_age": 60, "password_complexity": True, "account_lockout_threshold": 5}
    compromised_admins = [
        {"name": "Administrator", "password_never_expires": True, "inactive_days": 10, "is_domain_admin": True},
        {"name": "BackupAdmin", "password_never_expires": True, "inactive_days": 10, "is_domain_admin": True},
    ]

    small_domain_accounts = compromised_admins + [
        {"name": f"user{i}", "password_never_expires": False, "inactive_days": 5, "is_domain_admin": False}
        for i in range(8)
    ]  # 10 accounts total
    large_domain_accounts = compromised_admins + [
        {"name": f"user{i}", "password_never_expires": False, "inactive_days": 5, "is_domain_admin": False}
        for i in range(9998)
    ]  # 10,000 accounts total

    small_result = auditor.run_full_audit({"password_policy": clean_policy, "accounts": small_domain_accounts})
    large_result = auditor.run_full_audit({"password_policy": clean_policy, "accounts": large_domain_accounts})

    assert small_result["high_severity"] == 2
    assert large_result["high_severity"] == 2
    assert small_result["score"] < large_result["score"]
    assert large_result["score"] >= 95


def test_score_pwd_policy_findings_not_normalized_by_domain_size():
    """Domain-wide password-policy findings apply regardless of how many
    accounts exist, so they must keep their flat weight even in a huge domain."""
    auditor = ADAuditor()
    weak_policy = {"min_password_length": 6, "maximum_password_age": 90, "password_complexity": False, "account_lockout_threshold": 0}
    accounts = [
        {"name": f"user{i}", "password_never_expires": False, "inactive_days": 5, "is_domain_admin": False}
        for i in range(9999)
    ]
    result = auditor.run_full_audit({"password_policy": weak_policy, "accounts": accounts})
    # min length HIGH (20) + complexity HIGH (20) + lockout MEDIUM (10) = 50 penalty, flat.
    assert result["score"] == 50


def test_sanitize_domain_name_strips_unsafe_characters():
    assert _sanitize_domain_name("corp.asgard.local") == "corp.asgard.local"
    assert _sanitize_domain_name("../../etc/passwd") == ".._.._etc_passwd"
    assert _sanitize_domain_name("corp local; rm -rf /") == "corp_local__rm_-rf__"
    assert _sanitize_domain_name('weird"name<>|?*') == "weird_name_____"


def test_reporter_sanitizes_domain_name_in_filename():
    reporter = ADReporter(output_dir=tempfile.mkdtemp())
    audit_result = {
        "score": 100, "total_findings": 0, "high_severity": 0, "medium_severity": 0,
        "findings": []
    }
    path = reporter.generate_report("../../evil/domain", audit_result)
    try:
        assert os.path.exists(path)
        # No path separators may survive sanitization: the report must land
        # directly inside reporter.output_dir, never traverse out of it.
        assert os.sep not in _sanitize_domain_name("../../evil/domain")
        assert "/" not in _sanitize_domain_name("../../evil/domain")
        assert os.path.dirname(os.path.abspath(path)) == os.path.abspath(reporter.output_dir)
    finally:
        os.remove(path)


def test_fail_under_exits_with_error_when_score_below_threshold(monkeypatch, tmp_path):
    monkeypatch.setattr(yggdrasil_main, "ADReporter", lambda: ADReporter(output_dir=str(tmp_path)))
    with pytest.raises(SystemExit) as exc_info:
        yggdrasil_main.run_audit("corp.asgard.local", simulate=True, fail_under=90)
    assert exc_info.value.code == 1


def test_fail_under_does_not_exit_when_score_meets_threshold(monkeypatch, tmp_path):
    monkeypatch.setattr(yggdrasil_main, "ADReporter", lambda: ADReporter(output_dir=str(tmp_path)))
    # Simulated mock data yields a low score, so a low threshold must not trigger exit.
    yggdrasil_main.run_audit("corp.asgard.local", simulate=True, fail_under=0)


def test_fail_under_none_never_exits(monkeypatch, tmp_path):
    monkeypatch.setattr(yggdrasil_main, "ADReporter", lambda: ADReporter(output_dir=str(tmp_path)))
    yggdrasil_main.run_audit("corp.asgard.local", simulate=True, fail_under=None)


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
