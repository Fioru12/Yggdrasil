import pytest
from ldap3 import Server, Connection, MOCK_SYNC, OFFLINE_AD_2012_R2, SUBTREE

from core.collector import LDAPCollector, ADConnectionError

BASE_DN = "DC=corp,DC=local"
BIND_DN = "CN=svc-audit,OU=Service Accounts,DC=corp,DC=local"
BIND_PASSWORD = "correct-horse-battery-staple"
DOMAIN_ADMINS_DN = "CN=Domain Admins,CN=Users,DC=corp,DC=local"


def _make_mock_connection(bind_password=BIND_PASSWORD):
    """Build an in-memory mock LDAP server/connection using ldap3's built-in
    offline testing support (no network, no real AD required)."""
    server = Server("dc01.corp.local", get_info=OFFLINE_AD_2012_R2)
    connection = Connection(
        server,
        user=BIND_DN,
        password=bind_password,
        client_strategy=MOCK_SYNC,
    )
    # The bind account itself, so authentication can succeed/fail realistically.
    connection.strategy.add_entry(BIND_DN, {
        "objectClass": "user",
        "userPassword": BIND_PASSWORD,
    })
    # Domain object carrying the password policy attributes.
    connection.strategy.add_entry(BASE_DN, {
        "objectClass": "domain",
        "minPwdLength": 6,
        "maxPwdAge": -78883200000000,   # ~ -91.25 days in 100ns units
        "pwdProperties": 1,              # DOMAIN_PASSWORD_COMPLEX bit set
        "lockoutThreshold": 5,
    })
    connection.strategy.add_entry(DOMAIN_ADMINS_DN, {
        "objectClass": "group",
        "cn": "Domain Admins",
    })
    # A Domain Admin with DONT_EXPIRE_PASSWORD (0x10000) + NORMAL_ACCOUNT (0x200) set.
    connection.strategy.add_entry("CN=Administrator,CN=Users,DC=corp,DC=local", {
        "objectClass": "user",
        "sAMAccountName": "Administrator",
        "userAccountControl": 66048,  # 0x10200
        "pwdLastSet": 132000000000000000,
        "memberOf": DOMAIN_ADMINS_DN,
    })
    # A Domain Admin whose password DOES expire (no DONT_EXPIRE_PASSWORD bit).
    connection.strategy.add_entry("CN=BackupAdmin,CN=Users,DC=corp,DC=local", {
        "objectClass": "user",
        "sAMAccountName": "BackupAdmin",
        "userAccountControl": 512,  # NORMAL_ACCOUNT only
        "pwdLastSet": 132000000000000000,
        "memberOf": DOMAIN_ADMINS_DN,
    })
    return connection


def _collector_with_mock(monkeypatch, connection):
    """Return an LDAPCollector wired to a pre-built mock connection instead
    of opening a real network connection."""
    collector = LDAPCollector(
        host="dc01.corp.local",
        base_dn=BASE_DN,
        bind_dn=BIND_DN,
        password=BIND_PASSWORD,
        use_ssl=True,
    )

    def fake_connect():
        if collector._connection is None:
            if not connection.bind():
                result = connection.result
                raise ADConnectionError(
                    f"LDAP bind to dc01.corp.local:636 failed as '{BIND_DN}': "
                    f"{result.get('description')} - {result.get('message')}"
                )
            collector._connection = connection
        return collector._connection

    monkeypatch.setattr(collector, "connect", fake_connect)
    return collector


def test_fetch_password_policy_maps_ad_attributes(monkeypatch):
    connection = _make_mock_connection()
    collector = _collector_with_mock(monkeypatch, connection)

    policy = collector.fetch_password_policy()

    assert policy["min_password_length"] == 6
    assert policy["password_complexity"] is True
    assert policy["account_lockout_threshold"] == 5
    # -78883200000000 (100ns units) -> ~91 days
    assert policy["maximum_password_age"] == 91


def test_fetch_privileged_accounts_detects_dont_expire_password(monkeypatch):
    connection = _make_mock_connection()
    collector = _collector_with_mock(monkeypatch, connection)

    accounts = collector.fetch_privileged_accounts(group_dn=DOMAIN_ADMINS_DN)

    by_name = {acc["name"]: acc for acc in accounts}
    assert "Administrator" in by_name
    assert "BackupAdmin" in by_name

    assert by_name["Administrator"]["password_never_expires"] is True
    assert by_name["Administrator"]["is_domain_admin"] is True

    assert by_name["BackupAdmin"]["password_never_expires"] is False
    assert by_name["BackupAdmin"]["is_domain_admin"] is True


def test_bind_failure_raises_ad_connection_error_not_empty_data(monkeypatch):
    # Wrong password -> the mock server will reject the bind.
    connection = _make_mock_connection(bind_password="totally-wrong-password")
    collector = _collector_with_mock(monkeypatch, connection)

    with pytest.raises(ADConnectionError):
        collector.fetch_password_policy()

    with pytest.raises(ADConnectionError):
        collector.fetch_privileged_accounts()


def test_collect_combines_policy_and_accounts(monkeypatch):
    connection = _make_mock_connection()
    collector = _collector_with_mock(monkeypatch, connection)

    data = collector.collect(group_dn=DOMAIN_ADMINS_DN)

    assert "password_policy" in data
    assert "accounts" in data
    assert len(data["accounts"]) == 2
    assert data["password_policy"]["min_password_length"] == 6
