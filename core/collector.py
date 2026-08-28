"""
LDAP data collection layer for Yggdrasil.

Connects to a real Active Directory Domain Controller over LDAP/LDAPS and
retrieves the password policy and privileged account data needed by
core.auditor.ADAuditor, mapping raw AD attributes into the same dict schema
already used by the simulation mode in main.py.
"""

import datetime
from typing import Any, Dict, List, Optional

import ldap3
from ldap3.core.exceptions import LDAPException

from core.colors import Colors

# AD userAccountControl bit flags
UAC_DONT_EXPIRE_PASSWORD = 0x10000  # 65536

# AD pwdProperties bit flags (on the domain object)
DOMAIN_PASSWORD_COMPLEX = 0x1  # 1


class ADConnectionError(Exception):
    """Raised when Yggdrasil cannot connect to, bind to, or query the target
    Active Directory Domain Controller. Never swallowed silently -- an empty
    dict/list must never be mistaken for "the domain has no data"."""
    pass


def _large_int_to_days(value: Any) -> int:
    """Convert an AD 'large integer' negative interval (100-nanosecond units,
    e.g. maxPwdAge, lockoutDuration) into a positive number of days.

    ldap3 sometimes pre-formats these into a datetime.timedelta when it has
    schema information for the attribute (e.g. real AD, or OFFLINE_AD_*
    mocks); handle both the pre-formatted and the raw-integer case."""
    if isinstance(value, datetime.timedelta):
        return abs(value.days)
    try:
        ivalue = int(value)
    except (TypeError, ValueError):
        return 0
    if ivalue == 0:
        return 0
    # AD stores these as negative intervals relative to "now".
    ivalue = abs(ivalue)
    return int(ivalue / 864000000000)


def _filetime_to_inactive_days(value: Any) -> int:
    """Convert an AD FILETIME (100-nanosecond intervals since 1601-01-01,
    e.g. pwdLastSet, lastLogonTimestamp) into the number of days since then.

    Handles both a raw large-integer value and a value ldap3 has already
    formatted into a datetime.datetime (which it does when AD schema
    information for the attribute is available)."""
    if isinstance(value, datetime.datetime):
        last_set = value
        now = datetime.datetime.now(value.tzinfo) if value.tzinfo else datetime.datetime.utcnow()
        delta = now - last_set
        return max(0, delta.days)

    try:
        ivalue = int(value)
    except (TypeError, ValueError):
        return 0
    if ivalue <= 0:
        return 0
    epoch_start = datetime.datetime(1601, 1, 1)
    try:
        last_set = epoch_start + datetime.timedelta(microseconds=ivalue / 10)
    except OverflowError:
        return 0
    delta = datetime.datetime.utcnow() - last_set
    return max(0, delta.days)


class LDAPCollector:
    """
    Connects to an Active Directory Domain Controller over LDAP/LDAPS and
    collects the password policy and privileged account data consumed by
    core.auditor.ADAuditor.run_full_audit.
    """

    def __init__(
        self,
        host: str,
        base_dn: str,
        bind_dn: Optional[str] = None,
        password: Optional[str] = None,
        port: Optional[int] = None,
        use_ssl: bool = True,
    ):
        self.host = host
        self.base_dn = base_dn
        self.bind_dn = bind_dn
        self.password = password
        self.use_ssl = use_ssl
        self.port = port if port is not None else (636 if use_ssl else 389)

        if not use_ssl:
            print(
                f"{Colors.WARNING}[!]{Colors.ENDC} LDAPS is disabled (--no-ssl): "
                f"traffic to {host}:{self.port} (including the bind password) "
                f"will NOT be encrypted. Use this only for testing."
            )

        self._connection: Optional[ldap3.Connection] = None

    def connect(self) -> ldap3.Connection:
        """Establish (and cache) the LDAP connection/bind. Raises
        ADConnectionError on any connection or authentication failure."""
        if self._connection is not None:
            return self._connection

        try:
            server = ldap3.Server(self.host, port=self.port, use_ssl=self.use_ssl, get_info=ldap3.ALL)
            connection = ldap3.Connection(
                server,
                user=self.bind_dn,
                password=self.password,
                authentication=ldap3.SIMPLE if self.bind_dn else ldap3.ANONYMOUS,
                auto_bind=False,
            )
            if not connection.bind():
                result = connection.result
                connection.unbind()
                raise ADConnectionError(
                    f"LDAP bind to {self.host}:{self.port} failed as '{self.bind_dn}': "
                    f"{result.get('description', 'unknown error')} - {result.get('message', '')}"
                )
        except LDAPException as exc:
            raise ADConnectionError(
                f"Unable to connect to Active Directory at {self.host}:{self.port}: {exc}"
            ) from exc

        self._connection = connection
        return connection

    def disconnect(self) -> None:
        if self._connection is not None:
            try:
                self._connection.unbind()
            except LDAPException:
                pass
            self._connection = None

    def fetch_password_policy(self) -> Dict[str, Any]:
        """Query the domain object for the default domain password policy
        and map it to the schema expected by ADAuditor.audit_password_policy."""
        connection = self.connect()
        try:
            success = connection.search(
                search_base=self.base_dn,
                search_filter="(objectClass=domain)",
                search_scope=ldap3.BASE,
                attributes=["minPwdLength", "maxPwdAge", "pwdProperties", "lockoutThreshold"],
            )
        except LDAPException as exc:
            raise ADConnectionError(f"LDAP search for domain password policy failed: {exc}") from exc

        if not success or not connection.entries:
            raise ADConnectionError(
                f"No domain object found at base DN '{self.base_dn}'. "
                f"Verify --base-dn is correct and the bind account has read access."
            )

        entry = connection.entries[0]

        min_length = int(entry.minPwdLength.value) if "minPwdLength" in entry else 0
        max_age_days = _large_int_to_days(entry.maxPwdAge.value) if "maxPwdAge" in entry else 0
        pwd_properties = int(entry.pwdProperties.value) if "pwdProperties" in entry else 0
        complexity = bool(pwd_properties & DOMAIN_PASSWORD_COMPLEX)
        lockout_threshold = int(entry.lockoutThreshold.value) if "lockoutThreshold" in entry else 0

        return {
            "min_password_length": min_length,
            "maximum_password_age": max_age_days,
            "password_complexity": complexity,
            "account_lockout_threshold": lockout_threshold,
        }

    def fetch_privileged_accounts(self, group_dn: Optional[str] = None) -> List[Dict[str, Any]]:
        """Query direct members of the 'Domain Admins' group (or an
        explicitly supplied group DN) and map each to the schema expected by
        ADAuditor.audit_privileged_accounts."""
        connection = self.connect()

        if group_dn is None:
            group_dn = f"CN=Domain Admins,CN=Users,{self.base_dn}"

        search_filter = f"(&(objectClass=user)(memberOf={group_dn}))"

        try:
            success = connection.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=["sAMAccountName", "cn", "userAccountControl", "pwdLastSet", "lastLogonTimestamp"],
            )
        except LDAPException as exc:
            raise ADConnectionError(f"LDAP search for privileged accounts failed: {exc}") from exc

        if not success:
            raise ADConnectionError(
                f"LDAP search for members of '{group_dn}' failed. "
                f"Verify the group DN and the bind account's read access."
            )

        accounts = []
        for entry in connection.entries:
            name = None
            if "sAMAccountName" in entry and entry.sAMAccountName.value:
                name = entry.sAMAccountName.value
            elif "cn" in entry and entry.cn.value:
                name = entry.cn.value
            else:
                name = str(entry.entry_dn)

            uac = int(entry.userAccountControl.value) if "userAccountControl" in entry else 0
            never_expires = bool(uac & UAC_DONT_EXPIRE_PASSWORD)

            if "pwdLastSet" in entry and entry.pwdLastSet.value:
                inactive_days = _filetime_to_inactive_days(entry.pwdLastSet.value)
            elif "lastLogonTimestamp" in entry and entry.lastLogonTimestamp.value:
                inactive_days = _filetime_to_inactive_days(entry.lastLogonTimestamp.value)
            else:
                inactive_days = 0

            accounts.append({
                "name": name,
                "password_never_expires": never_expires,
                "inactive_days": inactive_days,
                "is_domain_admin": True,
            })

        return accounts

    def collect(self, group_dn: Optional[str] = None) -> Dict[str, Any]:
        """Collect both the password policy and privileged account data in
        the combined format consumed by ADAuditor.run_full_audit."""
        return {
            "password_policy": self.fetch_password_policy(),
            "accounts": self.fetch_privileged_accounts(group_dn=group_dn),
        }
