"""
Command-line interface: argument parsing, dependency verification,
and the main scan-stage coordinator.

This module is the entry point for both "osint-recon" (installed
console script) and "python -m osint_recon". It deliberately performs
a friendly dependency check at import time so a user missing a
third-party library sees a helpful install command instead of a raw
ImportError traceback.
"""

import argparse
import sys
from datetime import datetime
from typing import Any

# ----------------------------------------------------------------------------
# DEPENDENCY VERIFICATION
# ----------------------------------------------------------------------------

# Map of import-name -> pip-install-name. Most of these match, but
# python-whois imports as "whois", and dnspython imports as "dns",
# so the package names differ from the import names.
_REQUIRED_DEPS: dict[str, str] = {
    "whoisit": "whoisit",
    "whois":   "python-whois",
    "dns":     "dnspython",
    "requests": "requests",
}


def _check_dependencies() -> None:
    """
    Verify all third-party runtime dependencies are importable.

    Runs at module-import time, before any submodules that depend on
    these libraries are imported. If any are missing, prints a friendly
    install command and exits the process with status 1.
    """
    missing: list[str] = []
    for module_name, pip_name in _REQUIRED_DEPS.items():
        try:
            __import__(module_name)
        except ImportError:
            missing.append(pip_name)
    if missing:
        print("[!] Missing dependencies:")
        for pkg in missing:
            print(f"    - {pkg}")
        print(f"\n    Run: pip install {' '.join(missing)}")
        sys.exit(1)


# Run the check NOW, before importing the submodules that depend on
# these libraries. If the check fails the process exits before any
# ImportError gets raised below.
_check_dependencies()

# ----------------------------------------------------------------------------
# SCAN STAGE IMPORTS
# ----------------------------------------------------------------------------

# These imports rely on the dependencies verified above. Putting them
# after the check ensures dependency errors surface with friendly
# messages rather than as raw ImportError tracebacks.
from .validation import print_banner, validate_domain
from .dns_enum import resolve_ip, get_dns_records
from .registration import get_registration
from .email_security import get_email_security
from .http_probe import check_http_status
from .reporting import save_report


# ----------------------------------------------------------------------------
# MAIN ENTRY POINT
# ----------------------------------------------------------------------------

def main() -> None:
    """Parse CLI arguments, run each scan stage in order, optionally write report."""
    print_banner()

    parser = argparse.ArgumentParser(
        prog="osint-recon",
        description=(
            "OSINT Domain Recon Tool. Automated domain reconnaissance via "
            "RDAP, DNS, email-auth, and HTTP probing."
        ),
    )
    parser.add_argument(
        "domain",
        help="Target domain to scan (e.g., example.com)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Save report to a file",
        default=None,
    )
    parser.add_argument(
        "--no-http",
        action="store_true",
        help="Skip HTTP/HTTPS probing",
    )
    parser.add_argument(
        "--no-email-security",
        action="store_true",
        help="Skip email-authentication audit (SPF/DMARC/DKIM/BIMI)",
    )
    args = parser.parse_args()

    # Normalize and validate the target. Exits on malformed input.
    domain = validate_domain(args.domain)

    print(f"[*] Target : {domain}")
    print(f"[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Run each scan stage in order. The order here defines the report
    # section order and the on-screen output order.
    ip       = resolve_ip(domain)
    reg_data = get_registration(domain)
    dns_data = get_dns_records(domain)

    email_data: dict[str, Any] = {}
    if not args.no_email_security:
        email_data = get_email_security(domain)

    http_data: dict[str, Any] = {}
    if not args.no_http:
        http_data = check_http_status(domain)

    # Optionally serialize results to disk.
    if args.output:
        save_report(domain, ip, reg_data, dns_data, email_data, http_data, args.output)

    print(f"\n[*] Scan complete: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("[*] Remember: only run this tool against domains you own or have permission to test.\n")
