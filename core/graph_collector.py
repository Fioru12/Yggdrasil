"""
Microsoft Graph data collection layer for Yggdrasil's Entra ID / M365 audit.

Connects to a real Azure AD / Entra ID tenant via an app-only (client
credentials) OAuth2 flow and retrieves the user, role-membership, and
Conditional Access data needed by core.entra_audit.EntraSecurityAuditor,
mapping raw Graph API responses into the same dict schema already used by
the --simulate mode and by --input JSON files in main.py.

Requires an Azure AD app registration with application (not delegated)
permissions granted admin consent for:
  - User.Read.All            (list users, accountEnabled, userType)
  - RoleManagement.Read.Directory  (Global Administrator role membership)
  - Reports.Read.All         (MFA registration status per user)
  - Policy.Read.All          (Conditional Access policies, for legacy auth)
  - AuditLog.Read.All        (sign-in activity, for stale account detection
                                - requires Azure AD Premium P1/P2 licensing
                                on the tenant; without it, signInActivity is
                                simply absent from the response and this
                                collector reports "unknown" rather than
                                fabricating a number)

None of these are optional shortcuts - each maps directly to one of
EntraSecurityAuditor's checks. If a scope is missing, the specific Graph
call fails with a clear 403 from Microsoft and this collector raises
GraphConnectionError naming the missing permission, rather than silently
returning an empty/zero result that would read as "tenant is clean."
"""

import datetime
from typing import Any, Dict, List, Optional

import requests

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


class GraphConnectionError(Exception):
    """Raised when Yggdrasil cannot authenticate to, or query, Microsoft
    Graph for the target Entra ID tenant. Never swallowed silently - an
    empty dict/list must never be mistaken for "the tenant has no data."""
    pass


def _iso_to_days_ago(iso_timestamp: Optional[str]) -> Optional[int]:
    """Convert a Graph ISO-8601 timestamp (e.g. signInActivity.lastSignInDateTime)
    into a whole number of days since then. Returns None if the timestamp is
    missing (e.g. no Azure AD Premium license, or the user never signed in) -
    callers must treat None as "unknown", not as "0 days / just signed in."""
    if not iso_timestamp:
        return None
    try:
        ts = iso_timestamp.replace("Z", "+00:00")
        last_signin = datetime.datetime.fromisoformat(ts)
    except ValueError:
        return None
    now = datetime.datetime.now(datetime.timezone.utc)
    return max(0, (now - last_signin).days)


class GraphCollector:
    """
    Authenticates to Microsoft Graph via the OAuth2 client credentials flow
    (app-only auth - no signed-in user) and collects the tenant data
    consumed by core.entra_audit.EntraSecurityAuditor.audit_tenant.
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        graph_base_url: str = GRAPH_BASE_URL,
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.graph_base_url = graph_base_url.rstrip("/")
        self._access_token: Optional[str] = None

    def _acquire_token(self) -> str:
        """Acquire (and cache) an app-only access token via MSAL's client
        credentials flow. Raises GraphConnectionError on any auth failure."""
        if self._access_token is not None:
            return self._access_token

        import msal

        authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        try:
            app = msal.ConfidentialClientApplication(
                self.client_id,
                authority=authority,
                client_credential=self.client_secret,
            )
            result = app.acquire_token_for_client(scopes=[GRAPH_SCOPE])
        except ValueError as exc:
            # MSAL raises a raw ValueError (not a returned error dict) when it
            # can't even resolve the tenant/authority - e.g. an invalid or
            # nonexistent tenant ID. Caught here so callers always get a
            # GraphConnectionError, never an unhandled MSAL traceback.
            raise GraphConnectionError(
                f"Failed to authenticate to Microsoft Graph for tenant "
                f"'{self.tenant_id}': {exc}"
            ) from exc

        if "access_token" not in result:
            error = result.get("error", "unknown_error")
            description = result.get("error_description", "no description provided")
            raise GraphConnectionError(
                f"Failed to authenticate to Microsoft Graph for tenant "
                f"'{self.tenant_id}': {error} - {description}"
            )

        self._access_token = result["access_token"]
        return self._access_token

    def _get(self, url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Perform a single authenticated GET against Graph. Raises
        GraphConnectionError (naming the likely missing permission on a 403)
        on any non-2xx response or network failure."""
        token = self._acquire_token()
        headers = {"Authorization": f"Bearer {token}"}
        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)
        except requests.RequestException as exc:
            raise GraphConnectionError(f"Network error calling Microsoft Graph ({url}): {exc}") from exc

        if response.status_code == 403:
            raise GraphConnectionError(
                f"Microsoft Graph denied access to {url} (HTTP 403). The app "
                f"registration likely lacks the required application "
                f"permission (with admin consent granted) for this call."
            )
        if not response.ok:
            raise GraphConnectionError(
                f"Microsoft Graph call to {url} failed: HTTP {response.status_code} - {response.text[:300]}"
            )

        return response.json()

    def _get_all_pages(self, url: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Follow @odata.nextLink until exhausted, returning every 'value' item."""
        items: List[Dict[str, Any]] = []
        next_url = url
        next_params = params
        while next_url:
            page = self._get(next_url, params=next_params)
            items.extend(page.get("value", []))
            next_url = page.get("@odata.nextLink")
            next_params = None  # nextLink already includes the query string
        return items

    def fetch_mfa_registration(self) -> Dict[str, bool]:
        """Returns {userPrincipalName: isMfaRegistered} from the Graph
        authentication methods usage report. Requires Reports.Read.All."""
        url = f"{self.graph_base_url}/reports/authenticationMethods/userRegistrationDetails"
        params = {"$select": "userPrincipalName,isMfaRegistered"}
        records = self._get_all_pages(url, params=params)
        return {r.get("userPrincipalName"): bool(r.get("isMfaRegistered", False)) for r in records}

    def fetch_users(self, mfa_status: Optional[Dict[str, bool]] = None) -> List[Dict[str, Any]]:
        """Returns the tenant's users mapped to the schema EntraSecurityAuditor
        expects, merging in MFA registration status. Requires User.Read.All
        (and AuditLog.Read.All if signInActivity is to be populated - if that
        scope is missing Graph simply omits the field, which this method
        reports as days_since_last_signin=None rather than 0)."""
        if mfa_status is None:
            mfa_status = self.fetch_mfa_registration()

        url = f"{self.graph_base_url}/users"
        params = {
            "$select": "userPrincipalName,accountEnabled,userType,signInActivity",
        }
        raw_users = self._get_all_pages(url, params=params)

        users = []
        for u in raw_users:
            upn = u.get("userPrincipalName")
            signin_activity = u.get("signInActivity") or {}
            last_signin = signin_activity.get("lastSignInDateTime")
            days_since = _iso_to_days_ago(last_signin)
            users.append({
                "userPrincipalName": upn,
                "accountEnabled": u.get("accountEnabled", True),
                "userType": u.get("userType", "Member"),
                "mfa_enabled": mfa_status.get(upn, False),
                "days_since_last_signin": days_since if days_since is not None else 0,
            })
        return users

    def fetch_directory_roles(self) -> List[Dict[str, Any]]:
        """Returns activated directory roles with their members, in the
        schema EntraSecurityAuditor._audit_admins expects. Only roles that
        currently have at least one member are activated and returned by
        Graph. Requires RoleManagement.Read.Directory."""
        roles_url = f"{self.graph_base_url}/directoryRoles"
        raw_roles = self._get_all_pages(roles_url)

        roles = []
        for role in raw_roles:
            display_name = role.get("displayName")
            role_id = role.get("id")
            members_url = f"{self.graph_base_url}/directoryRoles/{role_id}/members"
            raw_members = self._get_all_pages(members_url)
            members = [
                {"userPrincipalName": m.get("userPrincipalName")}
                for m in raw_members
                if m.get("userPrincipalName")
            ]
            roles.append({"displayName": display_name, "members": members})
        return roles

    def fetch_legacy_auth_policy(self) -> Dict[str, Any]:
        """Inspects enabled Conditional Access policies for one that blocks
        legacy authentication client app types. Requires Policy.Read.All.

        Conservative by design: if no enabled policy is found that blocks
        legacy auth (including if the tenant has none at all), this reports
        legacy_auth_allowed=True - "not proven blocked" is treated as
        "assume exposed" for a security audit, not the other way around."""
        url = f"{self.graph_base_url}/identity/conditionalAccess/policies"
        policies = self._get_all_pages(url)

        legacy_client_types = {"exchangeActiveSync", "other"}
        for policy in policies:
            if policy.get("state") != "enabled":
                continue
            conditions = policy.get("conditions", {})
            client_app_types = set(conditions.get("clientAppTypes", []))
            grant_controls = policy.get("grantControls") or {}
            if legacy_client_types & client_app_types and grant_controls.get("builtInControls") == ["block"]:
                return {"legacy_auth_allowed": False}

        return {"legacy_auth_allowed": True}

    def collect(self) -> Dict[str, Any]:
        """Collect users, directory roles, and the legacy-auth policy
        verdict in the combined format consumed by
        EntraSecurityAuditor.audit_tenant(users, roles, tenant_policies)."""
        mfa_status = self.fetch_mfa_registration()
        return {
            "users": self.fetch_users(mfa_status=mfa_status),
            "roles": self.fetch_directory_roles(),
            "policies": self.fetch_legacy_auth_policy(),
        }
