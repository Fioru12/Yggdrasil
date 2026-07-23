import sys
import argparse
from core.auditor import ADAuditor
from core.reporter import ADReporter
from core.colors import Colors

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

def run_audit(domain: str, simulate: bool = True):
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
        target_data = {"password_policy": {}, "accounts": []}

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

def main():
    parser = argparse.ArgumentParser(description="Yggdrasil: Active Directory & Windows Security Auditor")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    audit_parser = subparsers.add_parser("audit", help="Run AD security audit")
    audit_parser.add_argument("--domain", default="corp.asgard.local", help="Target domain name")
    audit_parser.add_argument("--simulate", action="store_true", default=True, help="Use mock domain audit data")

    args = parser.parse_args()

    if args.command == "audit":
        run_audit(args.domain, simulate=args.simulate)
    else:
        run_audit("corp.asgard.local", simulate=True)

if __name__ == "__main__":
    main()
