import pytest

from core.graph_collector import GraphCollector, GraphConnectionError, _iso_to_days_ago

TENANT_ID = "11111111-1111-1111-1111-111111111111"
CLIENT_ID = "22222222-2222-2222-2222-222222222222"
CLIENT_SECRET = "s3cr3t"


class FakeMsalApp:
    """Stands in for msal.ConfidentialClientApplication. token_result is
    whatever acquire_token_for_client() should return for the test."""

    call_count = 0

    def __init__(self, client_id, authority, client_credential):
        self.client_id = client_id
        self.authority = authority
        self.client_credential = client_credential

    def acquire_token_for_client(self, scopes):
        FakeMsalApp.call_count += 1
        return FakeMsalApp.token_result


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json_data = json_data or {}
        self.text = text
        self.ok = 200 <= status_code < 300

    def json(self):
        return self._json_data


@pytest.fixture(autouse=True)
def reset_fake_msal(monkeypatch):
    FakeMsalApp.call_count = 0
    FakeMsalApp.token_result = {"access_token": "fake-access-token"}
    monkeypatch.setattr("msal.ConfidentialClientApplication", FakeMsalApp)


def _collector():
    return GraphCollector(tenant_id=TENANT_ID, client_id=CLIENT_ID, client_secret=CLIENT_SECRET)


def test_acquire_token_success_returns_and_caches_token(monkeypatch):
    collector = _collector()
    calls = []

    def fake_get(url, headers=None, params=None, timeout=None):
        calls.append(headers)
        return FakeResponse(200, {"value": []})

    monkeypatch.setattr("core.graph_collector.requests.get", fake_get)

    collector._get(f"{collector.graph_base_url}/users")
    collector._get(f"{collector.graph_base_url}/users")

    assert FakeMsalApp.call_count == 1, "token must be acquired once and reused, not re-fetched per call"
    assert all(h["Authorization"] == "Bearer fake-access-token" for h in calls)


def test_acquire_token_failure_raises_graph_connection_error():
    FakeMsalApp.token_result = {"error": "invalid_client", "error_description": "AADSTS7000215: bad secret"}
    collector = _collector()
    with pytest.raises(GraphConnectionError, match="invalid_client"):
        collector._acquire_token()


def test_acquire_token_wraps_msal_construction_valueerror(monkeypatch):
    """
    Regression test: msal.ConfidentialClientApplication's constructor itself
    (not just acquire_token_for_client's return value) raises a raw
    ValueError when the tenant ID/authority can't be resolved - e.g. an
    invalid or nonexistent tenant. Found by running `entra --live` end to
    end with a fake tenant ID, which previously crashed with an unhandled
    MSAL traceback instead of the clean GraphConnectionError every other
    auth failure path in this module produces.
    """

    class RaisingMsalApp:
        def __init__(self, client_id, authority, client_credential):
            raise ValueError(f"Unable to get authority configuration for {authority}")

    monkeypatch.setattr("msal.ConfidentialClientApplication", RaisingMsalApp)
    collector = _collector()
    with pytest.raises(GraphConnectionError, match="Unable to get authority configuration"):
        collector._acquire_token()


def test_get_raises_clear_error_on_403(monkeypatch):
    def fake_get(url, headers=None, params=None, timeout=None):
        return FakeResponse(403, {}, text="Forbidden")

    monkeypatch.setattr("core.graph_collector.requests.get", fake_get)
    collector = _collector()
    with pytest.raises(GraphConnectionError, match="permission"):
        collector._get(f"{collector.graph_base_url}/users")


def test_get_raises_on_other_error_status(monkeypatch):
    def fake_get(url, headers=None, params=None, timeout=None):
        return FakeResponse(500, {}, text="Internal Server Error")

    monkeypatch.setattr("core.graph_collector.requests.get", fake_get)
    collector = _collector()
    with pytest.raises(GraphConnectionError, match="500"):
        collector._get(f"{collector.graph_base_url}/users")


def test_get_all_pages_follows_odata_next_link(monkeypatch):
    base = _collector().graph_base_url
    page1_url = f"{base}/users"
    page2_url = f"{base}/users?%24skiptoken=abc"

    responses_by_url = {
        page1_url: FakeResponse(200, {"value": [{"userPrincipalName": "a@x.com"}], "@odata.nextLink": page2_url}),
        page2_url: FakeResponse(200, {"value": [{"userPrincipalName": "b@x.com"}]}),
    }

    def fake_get(url, headers=None, params=None, timeout=None):
        return responses_by_url[url]

    monkeypatch.setattr("core.graph_collector.requests.get", fake_get)
    collector = _collector()
    items = collector._get_all_pages(page1_url)
    assert [i["userPrincipalName"] for i in items] == ["a@x.com", "b@x.com"]


def test_fetch_mfa_registration_maps_upn_to_bool(monkeypatch):
    base = _collector().graph_base_url

    def fake_get(url, headers=None, params=None, timeout=None):
        assert url == f"{base}/reports/authenticationMethods/userRegistrationDetails"
        return FakeResponse(200, {"value": [
            {"userPrincipalName": "admin@x.com", "isMfaRegistered": True},
            {"userPrincipalName": "user1@x.com", "isMfaRegistered": False},
        ]})

    monkeypatch.setattr("core.graph_collector.requests.get", fake_get)
    result = _collector().fetch_mfa_registration()
    assert result == {"admin@x.com": True, "user1@x.com": False}


def test_fetch_users_merges_mfa_status_and_computes_signin_age(monkeypatch):
    base = _collector().graph_base_url

    def fake_get(url, headers=None, params=None, timeout=None):
        if "userRegistrationDetails" in url:
            return FakeResponse(200, {"value": [{"userPrincipalName": "admin@x.com", "isMfaRegistered": True}]})
        assert url == f"{base}/users"
        return FakeResponse(200, {"value": [
            {
                "userPrincipalName": "admin@x.com",
                "accountEnabled": True,
                "userType": "Member",
                "signInActivity": {"lastSignInDateTime": "2020-01-01T00:00:00Z"},
            },
            {
                "userPrincipalName": "guest@x.com",
                "accountEnabled": True,
                "userType": "Guest",
                "signInActivity": None,
            },
        ]})

    monkeypatch.setattr("core.graph_collector.requests.get", fake_get)
    users = _collector().fetch_users()

    admin = next(u for u in users if u["userPrincipalName"] == "admin@x.com")
    guest = next(u for u in users if u["userPrincipalName"] == "guest@x.com")

    assert admin["mfa_enabled"] is True
    assert admin["days_since_last_signin"] > 365  # signed in back in 2020
    assert guest["mfa_enabled"] is False  # not present in registration report -> default False
    assert guest["userType"] == "Guest"
    assert guest["days_since_last_signin"] == 0  # no signInActivity -> unknown, reported as 0 not fabricated


def test_fetch_directory_roles_returns_members(monkeypatch):
    base = _collector().graph_base_url

    def fake_get(url, headers=None, params=None, timeout=None):
        if url == f"{base}/directoryRoles":
            return FakeResponse(200, {"value": [{"id": "role-1", "displayName": "Global Administrator"}]})
        if url == f"{base}/directoryRoles/role-1/members":
            return FakeResponse(200, {"value": [{"userPrincipalName": "admin@x.com"}]})
        raise AssertionError(f"unexpected URL {url}")

    monkeypatch.setattr("core.graph_collector.requests.get", fake_get)
    roles = _collector().fetch_directory_roles()
    assert roles == [{"displayName": "Global Administrator", "members": [{"userPrincipalName": "admin@x.com"}]}]


def test_fetch_legacy_auth_policy_detects_blocking_policy(monkeypatch):
    base = _collector().graph_base_url

    def fake_get(url, headers=None, params=None, timeout=None):
        return FakeResponse(200, {"value": [{
            "state": "enabled",
            "conditions": {"clientAppTypes": ["exchangeActiveSync", "other"]},
            "grantControls": {"builtInControls": ["block"]},
        }]})

    monkeypatch.setattr("core.graph_collector.requests.get", fake_get)
    result = _collector().fetch_legacy_auth_policy()
    assert result == {"legacy_auth_allowed": False}


def test_fetch_legacy_auth_policy_defaults_to_allowed_when_no_blocking_policy(monkeypatch):
    base = _collector().graph_base_url

    def fake_get(url, headers=None, params=None, timeout=None):
        return FakeResponse(200, {"value": []})

    monkeypatch.setattr("core.graph_collector.requests.get", fake_get)
    result = _collector().fetch_legacy_auth_policy()
    assert result == {"legacy_auth_allowed": True}


def test_fetch_legacy_auth_policy_ignores_disabled_policy(monkeypatch):
    def fake_get(url, headers=None, params=None, timeout=None):
        return FakeResponse(200, {"value": [{
            "state": "disabled",
            "conditions": {"clientAppTypes": ["exchangeActiveSync", "other"]},
            "grantControls": {"builtInControls": ["block"]},
        }]})

    monkeypatch.setattr("core.graph_collector.requests.get", fake_get)
    result = _collector().fetch_legacy_auth_policy()
    assert result == {"legacy_auth_allowed": True}


def test_collect_wires_users_roles_and_policies_together(monkeypatch):
    base = _collector().graph_base_url

    def fake_get(url, headers=None, params=None, timeout=None):
        if "userRegistrationDetails" in url:
            return FakeResponse(200, {"value": []})
        if url == f"{base}/users":
            return FakeResponse(200, {"value": [{"userPrincipalName": "a@x.com", "accountEnabled": True, "userType": "Member"}]})
        if url == f"{base}/directoryRoles":
            return FakeResponse(200, {"value": []})
        if "conditionalAccess" in url:
            return FakeResponse(200, {"value": []})
        raise AssertionError(f"unexpected URL {url}")

    monkeypatch.setattr("core.graph_collector.requests.get", fake_get)
    data = _collector().collect()

    assert set(data.keys()) == {"users", "roles", "policies"}
    assert data["users"][0]["userPrincipalName"] == "a@x.com"
    assert data["roles"] == []
    assert data["policies"] == {"legacy_auth_allowed": True}


def test_iso_to_days_ago_returns_none_for_missing_timestamp():
    assert _iso_to_days_ago(None) is None
    assert _iso_to_days_ago("") is None


def test_iso_to_days_ago_returns_none_for_malformed_timestamp():
    assert _iso_to_days_ago("not-a-date") is None


def test_network_error_raises_graph_connection_error(monkeypatch):
    import requests as requests_module

    def fake_get(url, headers=None, params=None, timeout=None):
        raise requests_module.ConnectionError("DNS resolution failed")

    monkeypatch.setattr("core.graph_collector.requests.get", fake_get)
    collector = _collector()
    with pytest.raises(GraphConnectionError, match="Network error"):
        collector._get(f"{collector.graph_base_url}/users")
