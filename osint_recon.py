#!/usr/bin/env python3
"""
OSINT Domain Recon Tool
Author: Jorgy762
GitHub: https://github.com/Jorgy762/osint-domain-recon

Description:
    A command-line tool for automated domain reconnaissance.
    Given a target domain, it pulls registration data via RDAP
    (Registration Data Access Protocol), enumerates DNS records,
    resolves IP addresses, and probes HTTP/HTTPS availability,
    all in one run. Falls back to legacy WHOIS when a TLD has no
    RDAP service available.

Usage:
    python osint_recon.py example.com
    python osint_recon.py example.com -o report.txt
    python osint_recon.py example.com --no-http

Dependencies:
    pip install whoisit python-whois dnspython requests

Disclaimer:
    This tool is intended for educational purposes and authorized
    reconnaissance only. Only run it against domains you own or have
    explicit written permission to test. Unauthorized use may violate
    applicable laws including the Canadian Criminal Code (Section 342.1)
    and equivalent legislation in other jurisdictions.
"""

import argparse
import re
import socket
import sys
from datetime import datetime
from pathlib import Path

try:
    import whoisit
except ImportError:
    print("[!] Missing dependency: whoisit")
    print("    Run: pip install whoisit")
    sys.exit(1)

try:
    import whois  # legacy WHOIS, used only as a fallback
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


# Domain label rules: each label 1 to 63 chars, total length up to 253 chars,
# letters/digits/hyphens, no leading or trailing hyphen, TLD at least 2 chars.
DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+"
    r"[A-Za-z]{2,63}$"
)

# Cache the RDAP bootstrap data on disk. IANA refreshes the registry roughly
# weekly, so a 7-day cache window is safe and avoids a network round-trip
# on every invocation.
CACHE_DIR  = Path.home() / ".cache" / "osint-domain-recon"
CACHE_FILE = CACHE_DIR / "rdap_bootstrap.json"
CACHE_DAYS = 7


def print_banner():
    banner = """
+==============================================+
|          OSINT Domain Recon Tool             |
|          github.com/Jorgy762                 |
|          For authorized use only             |
+==============================================+
    """
    print(banner)


def validate_domain(raw):
    """
    Normalize and validate a domain. Strips schemes, paths, trailing dots,
    and converts to lowercase. Exits the program if the input is not a
    well-formed domain.
    """
    cleaned = (
        raw.strip().lower()
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
        .rstrip(".")
    )
    if not DOMAIN_REGEX.match(cleaned):
        print(f"[!] Invalid domain format: {cleaned!r}")
        sys.exit(1)
    return cleaned


def ensure_rdap_bootstrapped():
    """
    Load RDAP bootstrap data from disk cache when available and fresh,
    otherwise fetch from IANA and write a new cache file. The bootstrap
    tells whoisit which RDAP server is authoritative for a given TLD,
    IP block, or ASN.
    """
    if whoisit.is_bootstrapped():
        return

    if CACHE_FILE.exists():
        try:
            cached = CACHE_FILE.read_text(encoding="utf-8")
            whoisit.load_bootstrap_data(cached)
            if not whoisit.bootstrap_is_older_than(CACHE_DAYS):
                return
        except Exception:
            # Corrupt or unreadable cache. Fall through to a fresh bootstrap.
            whoisit.clear_bootstrapping()

    whoisit.bootstrap()
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(whoisit.save_bootstrap_data(), encoding="utf-8")
    except OSError as e:
        # Cache write failures are non-fatal. The tool still works, just
        # without the speedup.
        print(f"    [!] Could not write bootstrap cache ({e}). Continuing.")


def resolve_ip(domain):
    print("\n[*] Resolving IP Address...")
    try:
        ip = socket.gethostbyname(domain)
        print(f"    [+] IP Address : {ip}")
        return ip
    except socket.gaierror as e:
        print(f"    [-] Could not resolve IP: {e}")
        return None


def get_registration(domain):
    """
    Query RDAP for registration data, with a WHOIS fallback for any TLD
    that has no RDAP service or that returns an unexpected error.

    Returns a dict of normalized fields including a 'Source' key that
    indicates whether the data came from 'RDAP' or 'WHOIS'.
    """
    print("\n[*] Looking up registration data (RDAP)...")
    try:
        ensure_rdap_bootstrapped()
        r = whoisit.domain(domain)

        # The registrar's display name lives inside the registrar entity.
        registrar = ""
        registrars = r.get("entities", {}).get("registrar", [])
        if registrars:
            registrar = registrars[0].get("name", "")

        # RDAP does not return registrant country at the top level. It can
        # appear inside any role's vcard. Walk the common roles in order.
        country = ""
        for role in ("registrant", "administrative", "technical", "registrar"):
            for entity in r.get("entities", {}).get(role, []):
                country = entity.get("country", "")
                if country:
                    break
            if country:
                break

        fields = {
            "Source"             : "RDAP",
            "Registrar"          : registrar,
            "Creation Date"      : r.get("registration_date"),
            "Expiration Date"    : r.get("expiration_date"),
            "Last Updated"       : r.get("last_changed_date"),
            "Name Servers"       : r.get("nameservers") or [],
            "Status"             : r.get("status") or [],
            "Registrant Country" : country,
            "DNSSEC"             : "signedDelegation" if r.get("dnssec") else "unsigned",
        }
        _print_fields(fields)
        return fields

    except whoisit.errors.UnsupportedError:
        print("    [!] RDAP not supported for this TLD. Falling back to WHOIS...")
        return _whois_fallback(domain)
    except whoisit.errors.RateLimitedError as e:
        print(f"    [!] RDAP server rate-limited the request ({e}). Falling back to WHOIS...")
        return _whois_fallback(domain)
    except whoisit.errors.BootstrapError as e:
        print(f"    [!] RDAP bootstrap failed ({e}). Falling back to WHOIS...")
        return _whois_fallback(domain)
    except whoisit.errors.QueryError as e:
        print(f"    [!] RDAP query failed ({e}). Falling back to WHOIS...")
        return _whois_fallback(domain)
    except whoisit.errors.WhoisItError as e:
        print(f"    [!] RDAP error ({e}). Falling back to WHOIS...")
        return _whois_fallback(domain)


def _whois_fallback(domain):
    print("\n[*] Running WHOIS lookup...")
    try:
        w = whois.whois(domain)
        fields = {
            "Source"             : "WHOIS",
            "Registrar"          : w.registrar,
            "Creation Date"      : w.creation_date,
            "Expiration Date"    : w.expiration_date,
            "Last Updated"       : w.updated_date,
            "Name Servers"       : w.name_servers,
            "Status"             : w.status,
            "Registrant Country" : w.country,
            "DNSSEC"             : w.dnssec,
        }
        _print_fields(fields)
        return fields
    except Exception as e:
        print(f"    [-] WHOIS lookup failed: {e}")
        return {"Source": "FAILED"}


def _print_fields(fields):
    """
    Pretty-print a registration data dict. Skips empty values, deduplicates
    lists, and trims very long lists for readability.
    """
    for key, value in fields.items():
        if value in (None, "", [], {}):
            continue
        if isinstance(value, list):
            # Deduplicate while preserving order.
            seen = set()
            unique = []
            for v in value:
                s = str(v)
                if s not in seen:
                    seen.add(s)
                    unique.append(s)
            value = unique[0] if len(unique) == 1 else ", ".join(unique[:5])
        print(f"    [+] {key}: {value}")


def get_dns_records(domain):
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
            print(f"    [-] No {record_type} records found")
        except dns.resolver.NXDOMAIN:
            print(f"    [-] Domain does not exist (NXDOMAIN)")
            break
        except dns.resolver.Timeout:
            print(f"    [-] {record_type} lookup timed out")
        except Exception as e:
            print(f"    [-] {record_type} lookup error: {e}")
    return dns_results


def check_http_status(domain):
    print("\n[*] Checking HTTP/HTTPS Status...")
    results = {}
    for scheme in ["http", "https"]:
        url = f"{scheme}://{domain}"
        try:
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
            print(f"    [!] {scheme.upper():<6} SSL certificate error")
        except requests.exceptions.ConnectionError:
            print(f"    [-] {scheme.upper():<6} Connection refused or host unreachable")
        except requests.exceptions.Timeout:
            print(f"    [-] {scheme.upper():<6} Request timed out after 5 seconds")
        except Exception as e:
            print(f"    [-] {scheme.upper():<6} Unexpected error: {e}")
    return results


def save_report(domain, ip, reg_data, dns_data, http_data, output_file):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(output_file, "w", encoding="utf-8") as f:
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

        f.write("REGISTRATION DATA\n")
        f.write("-" * 30 + "\n")
        if reg_data and reg_data.get("Source") != "FAILED":
            for key, value in reg_data.items():
                if value in (None, "", [], {}):
                    continue
                if isinstance(value, list):
                    value = ", ".join(str(v) for v in value[:5])
                f.write(f"  {key}: {value}\n")
        else:
            f.write("  No registration data retrieved.\n")
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


def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="OSINT Domain Recon Tool. Automated domain reconnaissance via RDAP, DNS, and HTTP probing."
    )
    parser.add_argument("domain", help="Target domain to scan (e.g., example.com)")
    parser.add_argument("-o", "--output", help="Save report to a file", default=None)
    parser.add_argument("--no-http", action="store_true", help="Skip HTTP/HTTPS probing")
    args = parser.parse_args()

    domain = validate_domain(args.domain)

    print(f"[*] Target : {domain}")
    print(f"[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    ip       = resolve_ip(domain)
    reg_data = get_registration(domain)
    dns_data = get_dns_records(domain)
    http_data = {}

    if not args.no_http:
        http_data = check_http_status(domain)

    if args.output:
        save_report(domain, ip, reg_data, dns_data, http_data, args.output)

    print(f"\n[*] Scan complete: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("[*] Remember: only run this tool against domains you own or have permission to test.\n")


if __name__ == "__main__":
    main()
