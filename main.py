import os
import sys
import argparse
import getpass
from core.auditor import ADAuditor
from core.reporter import ADReporter
from core.colors import Colors
from core.collector import LDAPCollector, ADConnectionError

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

def run_audit(domain: str, simulate: bool = True, ldap_args=None, fail_under: int = None):
    print(Colors.CYAN + "=" * 65 + Colors.ENDC)
    print(f"{Colors.BOLD} Yggdrasil - Active Directory & Windows Security Auditor{Colors.ENDC}")
    print(Colors.CYAN + "=" * 65 + Colors.ENDC)
    print(f"{Colors.CYAN}[*]{Colors.ENDC} Target Domain: {domain}")

    auditor = ADAuditor()
    reporter = ADReporter()

    if simulate:
        print(f"{Colors.WARNING}[!]{Colors.ENDC} SIMULATION MODE: Using mock AD domain configuration...")
        target_data = {
            "password_policy": {
                "min_password_length": 6,
                "maximum_password_age": 90,
                "password_complexity": False,
                "account_lockout_threshold": 0
            },
            "accounts": [
                {"name": "Administrator", "password_never_expires": True, "inactive_days": 10, "is_domain_admin": True},
                {"name": "BackupAdmin", "password_never_expires": True, "inactive_days": 120, "is_domain_admin": True},
                {"name": "john.doe", "password_never_expires": False, "inactive_days": 5, "is_domain_admin": False}
            ]
        }
    else:
        if not ldap_args.ldap_host or not ldap_args.base_dn:
            print(f"{Colors.RED}[ERROR]{Colors.ENDC} --no-simulate requires --ldap-host and --base-dn.")
            sys.exit(1)

        bind_password = ldap_args.bind_password or os.environ.get("YGGDRASIL_BIND_PASSWORD")
        if ldap_args.bind_dn and not bind_password:
            bind_password = getpass.getpass(f"Password for {ldap_args.bind_dn}: ")

        print(f"{Colors.CYAN}[*]{Colors.ENDC} Connecting to Active Directory at "
              f"{ldap_args.ldap_host}:{ldap_args.ldap_port} "
              f"({'LDAPS' if not ldap_args.no_ssl else 'LDAP (unencrypted)'})...")

        collector = LDAPCollector(
            host=ldap_args.ldap_host,
            port=ldap_args.ldap_port,
            base_dn=ldap_args.base_dn,
            bind_dn=ldap_args.bind_dn,
            password=bind_password,
            use_ssl=not ldap_args.no_ssl,
        )

        try:
            target_data = collector.collect()
        except ADConnectionError as exc:
            print(f"{Colors.RED}[ERROR]{Colors.ENDC} {exc}")
            sys.exit(1)
        finally:
            collector.disconnect()

    print(f"{Colors.CYAN}[*]{Colors.ENDC} Analyzing security posture and GPO policies...")
    result = auditor.run_full_audit(target_data)

    print(f"{Colors.CYAN}[*]{Colors.ENDC} Audit complete. Security Score: {Colors.BOLD}{result['score']}/100{Colors.ENDC}")
    print(f"    - High Severity Findings: {result['high_severity']}")
    print(f"    - Medium Severity Findings: {result['medium_severity']}")

    print(f"{Colors.CYAN}[*]{Colors.ENDC} Generating Executive Audit Report...")
    path = reporter.generate_report(domain, result)
    print(f"{Colors.GREEN}[SUCCESS]{Colors.ENDC} Report saved at: {path}")

    print("\n" + Colors.CYAN + "=" * 65 + Colors.ENDC)
    print(f"{Colors.BOLD} SUMMARY OF FINDINGS:{Colors.ENDC}")
    for f in result["findings"]:
        sev_color = Colors.RED if f['severity'] == 'HIGH' else Colors.YELLOW
        print(f" - {sev_color}[{f['severity']}]{Colors.ENDC} {f['title']}")
    print(Colors.CYAN + "=" * 65 + Colors.ENDC)

    if fail_under is not None and result["score"] < fail_under:
        print(f"{Colors.RED}[FAIL]{Colors.ENDC} Security score {result['score']} is below "
              f"the required threshold of {fail_under}.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Yggdrasil: Active Directory & Windows Security Auditor")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    audit_parser = subparsers.add_parser("audit", help="Run AD security audit")
    audit_parser.add_argument("--domain", default="corp.asgard.local", help="Target domain name")
    audit_parser.add_argument("--simulate", action=argparse.BooleanOptionalAction, default=True, help="Use mock domain audit data (use --no-simulate to attempt a live AD audit)")
    audit_parser.add_argument("--ldap-host", default=None, help="Domain Controller hostname or IP (required for --no-simulate)")
    audit_parser.add_argument("--ldap-port", type=int, default=636, help="LDAP port (default: 636 for LDAPS)")
    audit_parser.add_argument("--bind-dn", default=None, help="DN of the account to bind with (read-only account recommended)")
    audit_parser.add_argument("--bind-password", default=None, help="Bind password (prefer YGGDRASIL_BIND_PASSWORD env var, or omit to be prompted)")
    audit_parser.add_argument("--base-dn", default=None, help="Base DN of the domain, e.g. DC=corp,DC=local (required for --no-simulate)")
    audit_parser.add_argument("--no-ssl", action="store_true", help="Disable LDAPS and use unencrypted LDAP (not recommended)")
    audit_parser.add_argument("--fail-under", type=int, default=None, metavar="SCORE",
                               help="Exit with status 1 if the final security score is below SCORE "
                                    "(after generating the report). Useful for CI/CD pipeline gating.")

    args = parser.parse_args()

    if args.command == "audit":
        run_audit(args.domain, simulate=args.simulate, ldap_args=args, fail_under=args.fail_under)
    else:
        run_audit("corp.asgard.local", simulate=True)

if __name__ == "__main__":
    main()
