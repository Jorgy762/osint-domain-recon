#!/usr/bin/env python3
"""
OSINT Domain Recon Tool
Author: Jorgy762
GitHub: https://github.com/Jorgy762/osint-domain-recon

Description:
    A command-line tool for automated domain reconnaissance.
    Given a target domain, it pulls WHOIS registration data,
    enumerates DNS records, resolves IP addresses, and probes
    HTTP/HTTPS availability -- all in one run.

Usage:
    python osint_recon.py example.com
    python osint_recon.py example.com -o report.txt
    python osint_recon.py example.com --no-http

Dependencies:
    pip install python-whois dnspython requests
"""

import argparse
import socket
import sys
from datetime import datetime

# Dependency checks with helpful error messages for beginners
try:
    import whois
except ImportError:
    print("[!] Missing dependency: python-whois")
    print("    Run: pip install python-whois")
    sys.exit(1)

try:
    import dns.resolver
except ImportError:
    print("[!] Missing dependency: dnspython")
    print("    Run: pip install dnspython")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("[!] Missing dependency: requests")
    print("    Run: pip install requests")
    sys.exit(1)


# ─── Banner ──────────────────────────────────────────────────────────────────

def print_banner():
    """Print the tool banner on startup."""
    banner = """
╔══════════════════════════════════════════════╗
║          OSINT Domain Recon Tool             ║
║          github.com/Jorgy762                 ║
║          For authorized use only             ║
╚══════════════════════════════════════════════╝
    """
    print(banner)


# ─── Reconnaissance Functions ────────────────────────────────────────────────

def resolve_ip(domain):
    """
    Resolve a domain name to its IP address using a standard DNS lookup.
    Returns the IP string, or None if resolution fails.
    """
    print("\n[*] Resolving IP Address...")
    try:
        ip = socket.gethostbyname(domain)
        print(f"    [+] IP Address : {ip}")
        return ip
    except socket.gaierror as e:
        print(f"    [-] Could not resolve IP: {e}")
        return None


def get_whois(domain):
    """
    Retrieve WHOIS registration data for the target domain.
    Extracts registrar, dates, name servers, country, and DNSSEC status.
    Returns a dict of the extracted fields.
    """
    print("\n[*] Running WHOIS Lookup...")
    try:
        w = whois.whois(domain)

        # Fields we care about
        fields = {
            "Registrar"          : w.registrar,
            "Creation Date"      : w.creation_date,
            "Expiration Date"    : w.expiration_date,
            "Last Updated"       : w.updated_date,
            "Name Servers"       : w.name_servers,
            "Registrant Country" : w.country,
            "DNSSEC"             : w.dnssec,
        }

        for key, value in fields.items():
            if value:
                # Some fields return lists (e.g. name servers, dates) -- clean them up
                if isinstance(value, list):
                    value = value[0] if len(value) == 1 else ", ".join(str(v) for v in value[:3])
                print(f"    [+] {key}: {value}")

        return fields

    except Exception as e:
        print(f"    [-] WHOIS lookup failed: {e}")
        return {}


def get_dns_records(domain):
    """
    Enumerate common DNS record types for the target domain.
    Checks: A, AAAA, MX, NS, TXT, CNAME, SOA.
    Returns a dict of record type -> list of record strings.
    """
    print("\n[*] Enumerating DNS Records...")

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    dns_results = {}

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records = [str(r) for r in answers]
            dns_results[record_type] = records

            print(f"    [+] {record_type} Records:")
            for record in records:
                print(f"          - {record}")

        except dns.resolver.NoAnswer:
            # No records of this type -- not an error, just nothing to show
            print(f"    [-] No {record_type} records found")

        except dns.resolver.NXDOMAIN:
            # Domain genuinely doesn't exist
            print(f"    [-] Domain does not exist (NXDOMAIN)")
            break

        except dns.resolver.Timeout:
            print(f"    [-] {record_type} lookup timed out")

        except Exception as e:
            print(f"    [-] {record_type} lookup error: {e}")

    return dns_results


def check_http_status(domain):
    """
    Probe the domain over HTTP and HTTPS.
    Captures status code, server header, and final URL (after redirects).
    Returns a dict with results for each scheme.
    """
    print("\n[*] Checking HTTP/HTTPS Status...")
    results = {}

    for scheme in ["http", "https"]:
        url = f"{scheme}://{domain}"
        try:
            # allow_redirects=True follows redirects (e.g. HTTP -> HTTPS)
            response = requests.get(url, timeout=5, allow_redirects=True)

            status    = response.status_code
            server    = response.headers.get("Server", "Not disclosed")
            final_url = response.url

            print(f"    [+] {scheme.upper():<6} Status: {status} | Server: {server} | Final URL: {final_url}")

            results[scheme] = {
                "status_code" : status,
                "server"      : server,
                "final_url"   : final_url,
            }

        except requests.exceptions.SSLError:
            print(f"    [!] {scheme.upper():<6} SSL certificate error (may be self-signed or expired)")

        except requests.exceptions.ConnectionError:
            print(f"    [-] {scheme.upper():<6} Connection refused or host unreachable")

        except requests.exceptions.Timeout:
            print(f"    [-] {scheme.upper():<6} Request timed out after 5 seconds")

        except Exception as e:
            print(f"    [-] {scheme.upper():<6} Unexpected error: {e}")

    return results


# ─── Report Export ────────────────────────────────────────────────────────────

def save_report(domain, ip, whois_data, dns_data, http_data, output_file):
    """
    Write all recon results to a plain text report file.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(output_file, "w") as f:
        f.write("=" * 55 + "\n")
        f.write("  OSINT Domain Recon Report\n")
        f.write("=" * 55 + "\n")
        f.write(f"  Target Domain : {domain}\n")
        f.write(f"  Scan Time     : {timestamp}\n")
        f.write(f"  Tool          : github.com/Jorgy762/osint-domain-recon\n")
        f.write("=" * 55 + "\n\n")

        f.write("IP RESOLUTION\n")
        f.write("-" * 30 + "\n")
        f.write(f"  IP Address: {ip if ip else 'Could not resolve'}\n\n")

        f.write("WHOIS DATA\n")
        f.write("-" * 30 + "\n")
        if whois_data:
            for key, value in whois_data.items():
                if value:
                    if isinstance(value, list):
                        value = ", ".join(str(v) for v in value[:3])
                    f.write(f"  {key}: {value}\n")
        else:
            f.write("  No WHOIS data retrieved.\n")
        f.write("\n")

        f.write("DNS RECORDS\n")
        f.write("-" * 30 + "\n")
        if dns_data:
            for rtype, records in dns_data.items():
                f.write(f"  {rtype}:\n")
                for r in records:
                    f.write(f"    - {r}\n")
        else:
            f.write("  No DNS records retrieved.\n")
        f.write("\n")

        f.write("HTTP/HTTPS STATUS\n")
        f.write("-" * 30 + "\n")
        if http_data:
            for scheme, data in http_data.items():
                f.write(f"  {scheme.upper()}:\n")
                for k, v in data.items():
                    f.write(f"    {k}: {v}\n")
        else:
            f.write("  HTTP probing was skipped or returned no results.\n")

    print(f"\n[+] Report saved to: {output_file}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print_banner()

    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(
        description="OSINT Domain Recon Tool -- automated domain reconnaissance"
    )
    parser.add_argument(
        "domain",
        help="Target domain to scan (e.g., example.com)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Optional: save report to a file (e.g., -o report.txt)",
        default=None
    )
    parser.add_argument(
        "--no-http",
        action="store_true",
        help="Optional: skip HTTP/HTTPS probing"
    )

    args = parser.parse_args()

    # Sanitize input -- strip protocol prefix and trailing slashes if user included them
    domain = (
        args.domain
        .strip()
        .lower()
        .replace("https://", "")
        .replace("http://", "")
        .rstrip("/")
    )

    print(f"[*] Target : {domain}")
    print(f"[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Run each recon module
    ip          = resolve_ip(domain)
    whois_data  = get_whois(domain)
    dns_data    = get_dns_records(domain)
    http_data   = {}

    if not args.no_http:
        http_data = check_http_status(domain)

    # Save report if output path was specified
    if args.output:
        save_report(domain, ip, whois_data, dns_data, http_data, args.output)

    print(f"\n[*] Scan complete: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("[*] Remember: only run this tool against domains you own or have permission to test.\n")


if __name__ == "__main__":
    main()
