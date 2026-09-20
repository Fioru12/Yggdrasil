"""Tests for main.py's argparse dispatch and run_entra_audit - previously
untested (main.py was at 31% coverage: only run_audit's simulate/fail_under
paths were exercised, via direct calls, not through main()'s own wiring)."""
import argparse
import pytest

import main


def test_main_dispatches_audit_subcommand(monkeypatch):
    called = {}
    monkeypatch.setattr(main, "run_audit", lambda domain, simulate, ldap_args, fail_under: called.update(locals()))
    monkeypatch.setattr("sys.argv", ["main.py", "audit", "--domain", "test.local", "--fail-under", "50"])
    main.main()
    assert called["domain"] == "test.local"
    assert called["fail_under"] == 50


def test_main_dispatches_entra_subcommand(monkeypatch):
    called = {}
    monkeypatch.setattr(
        main, "run_entra_audit",
        lambda tenant, input_file, simulate, live, graph_args: called.update(locals()),
    )
    monkeypatch.setattr("sys.argv", ["main.py", "entra", "--tenant", "test.onmicrosoft.com"])
    main.main()
    assert called["tenant"] == "test.onmicrosoft.com"
    assert called["live"] is False


def test_main_defaults_to_audit_when_no_subcommand(monkeypatch):
    called = {}
    monkeypatch.setattr(main, "run_audit", lambda domain, simulate: called.update(locals()))
    monkeypatch.setattr("sys.argv", ["main.py"])
    main.main()
    assert called["domain"] == "corp.asgard.local"
    assert called["simulate"] is True


def test_run_entra_audit_simulate_mode(capsys):
    main.run_entra_audit("test.onmicrosoft.com", input_file=None, simulate=True, live=False, graph_args=None)
    out = capsys.readouterr().out
    assert "Cloud Security Score" in out
    assert "simulazione" in out


def test_run_entra_audit_from_input_file(tmp_path, capsys):
    import json
    input_path = tmp_path / "tenant.json"
    input_path.write_text(json.dumps({
        "users": [{"userPrincipalName": "a@x.com", "mfa_enabled": True, "accountEnabled": True}],
        "roles": [],
        "policies": {"legacy_auth_allowed": False},
    }), encoding="utf-8")

    main.run_entra_audit("test.onmicrosoft.com", input_file=str(input_path), simulate=False, live=False, graph_args=None)
    out = capsys.readouterr().out
    assert "Utenti analizzati: 1" in out


def test_run_entra_audit_live_requires_tenant_and_client_id(capsys):
    graph_args = argparse.Namespace(tenant_id=None, client_id=None, client_secret=None)
    with pytest.raises(SystemExit) as exc:
        main.run_entra_audit("test.onmicrosoft.com", live=True, graph_args=graph_args)
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "--tenant-id and --client-id" in out


def test_run_entra_audit_live_requires_client_secret(capsys, monkeypatch):
    monkeypatch.delenv("YGGDRASIL_GRAPH_CLIENT_SECRET", raising=False)
    graph_args = argparse.Namespace(tenant_id="t", client_id="c", client_secret=None)
    with pytest.raises(SystemExit) as exc:
        main.run_entra_audit("test.onmicrosoft.com", live=True, graph_args=graph_args)
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "client secret" in out


def test_run_entra_audit_live_calls_graph_collector(monkeypatch, capsys):
    calls = {}

    class FakeCollector:
        def __init__(self, tenant_id, client_id, client_secret):
            calls["init"] = (tenant_id, client_id, client_secret)

        def collect(self):
            return {
                "users": [{"userPrincipalName": "a@x.com", "mfa_enabled": True, "accountEnabled": True}],
                "roles": [],
                "policies": {"legacy_auth_allowed": False},
            }

    monkeypatch.setattr("core.graph_collector.GraphCollector", FakeCollector)
    graph_args = argparse.Namespace(tenant_id="tid", client_id="cid", client_secret="secret")
    main.run_entra_audit("test.onmicrosoft.com", live=True, graph_args=graph_args)

    assert calls["init"] == ("tid", "cid", "secret")
    out = capsys.readouterr().out
    assert "Utenti analizzati: 1" in out


def test_run_entra_audit_live_graph_connection_error_exits_cleanly(monkeypatch, capsys):
    from core.graph_collector import GraphConnectionError

    class FailingCollector:
        def __init__(self, tenant_id, client_id, client_secret):
            pass

        def collect(self):
            raise GraphConnectionError("permission denied")

    monkeypatch.setattr("core.graph_collector.GraphCollector", FailingCollector)
    graph_args = argparse.Namespace(tenant_id="tid", client_id="cid", client_secret="secret")
    with pytest.raises(SystemExit) as exc:
        main.run_entra_audit("test.onmicrosoft.com", live=True, graph_args=graph_args)
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "permission denied" in out


def test_run_audit_no_simulate_success_with_mocked_ldap(monkeypatch, capsys):
    fake_target_data = {
        "password_policy": {"min_password_length": 14, "password_complexity": True, "account_lockout_threshold": 5, "maximum_password_age": 60},
        "accounts": [],
    }

    class FakeCollector:
        def __init__(self, **kwargs):
            pass

        def collect(self):
            return fake_target_data

        def disconnect(self):
            pass

    monkeypatch.setattr(main, "LDAPCollector", FakeCollector)
    ldap_args = argparse.Namespace(
        ldap_host="dc01.corp.local", ldap_port=636, base_dn="DC=corp,DC=local",
        bind_dn=None, bind_password=None, no_ssl=False,
    )
    main.run_audit("corp.local", simulate=False, ldap_args=ldap_args, fail_under=None)
    out = capsys.readouterr().out
    assert "Audit complete" in out


def test_run_audit_no_simulate_connection_error_exits_cleanly(monkeypatch, capsys):
    from core.collector import ADConnectionError

    class FailingCollector:
        def __init__(self, **kwargs):
            pass

        def collect(self):
            raise ADConnectionError("bind failed")

        def disconnect(self):
            pass

    monkeypatch.setattr(main, "LDAPCollector", FailingCollector)
    ldap_args = argparse.Namespace(
        ldap_host="dc01.corp.local", ldap_port=636, base_dn="DC=corp,DC=local",
        bind_dn=None, bind_password=None, no_ssl=False,
    )
    with pytest.raises(SystemExit) as exc:
        main.run_audit("corp.local", simulate=False, ldap_args=ldap_args, fail_under=None)
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "bind failed" in out
