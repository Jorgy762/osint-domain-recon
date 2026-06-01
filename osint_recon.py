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


def _format_value(value):
    """
    Normalize a value for display. Trims microseconds from datetime objects
    so output reads as second-precision ISO format. Returns the value
    unchanged for other types.
    """
    if isinstance(value, datetime):
        # Strip sub-second precision. RDAP servers and some WHOIS responses
        # include microseconds, which are noise for recon purposes.
        return value.replace(microsecond=0).isoformat(sep=" ")
    return value


def _print_fields(fields):
    """
    Pretty-print a registration data dict. Skips empty values, deduplicates
    lists, trims long lists, and normalizes datetimes to second precision.
    """
    for key, value in fields.items():
        if value in (None, "", [], {}):
            continue
        if isinstance(value, list):
            # Deduplicate while preserving order.
            seen = set()
            unique = []
            for v in value:
                s = str(_format_value(v))
                if s not in seen:
                    seen.add(s)
                    unique.append(s)
            value = unique[0] if len(unique) == 1 else ", ".join(unique[:5])
        else:
            value = _format_value(value)
        print(f"    [+] {key}: {value}")


# Common DKIM selectors observed across major mail providers. This list is not
# exhaustive. Custom or vendor-rotated selectors will be missed. A "DKIM not
# found" result here means "no DKIM at known common selectors", not "DKIM does
# not exist for this domain".
COMMON_DKIM_SELECTORS = [
    "selector1", "selector2",                          # Microsoft 365
    "google",                                          # Google Workspace
    "k1", "k2", "k3",                                  # Mailchimp, MailerLite
    "s1", "s2",                                        # SendGrid
    "mail", "smtp", "dkim", "default",                 # Generic / self-hosted
    "protonmail", "protonmail2", "protonmail3",        # ProtonMail
    "zoho", "zoho1", "zoho2",                          # Zoho
    "mandrill",                                        # Mandrill
    "mailgun",                                         # Mailgun
    "amazonses",                                       # AWS SES
    "postmark",                                        # Postmark
    "sparkpost",                                       # SparkPost
    "hs1", "hs2",                                      # HubSpot (base selectors)
    "fd", "fd1", "fd2",                                # Various
    "mxvault",                                         # MXVault
]

# Mechanisms in an SPF record that trigger a DNS lookup. Per RFC 7208, these
# count against the 10-lookup limit. The "ip4", "ip6", and "all" mechanisms
# do not trigger lookups and do not count.
SPF_LOOKUP_MECHANISMS = ("include", "a", "mx", "ptr", "exists", "redirect")


# Service verification token prefixes observed in TXT records across major
# SaaS providers. When a domain owner sets up a third-party service that
# requires DNS-based domain proof, the service issues a verification token
# that gets published as a TXT record. These tokens are persistent fingerprints
# of which services have touched a domain, useful OSINT signal for mapping
# a target's SaaS footprint without sending traffic to the services themselves.
#
# Each entry maps a substring (matched case-insensitively, anchored to the
# start of the record after stripping quotes) to the service it identifies.
SERVICE_TOKEN_MAP = {
    "ms=":                              "Microsoft 365 / Azure AD tenant",
    "google-site-verification=":        "Google (Workspace / Search Console)",
    "facebook-domain-verification=":    "Meta (Facebook / Instagram)",
    "atlassian-domain-verification=":   "Atlassian",
    "apple-domain-verification=":       "Apple Business Manager",
    "adobe-idp-site-verification=":     "Adobe",
    "adobe-sign-verification=":         "Adobe Sign",
    "docusign=":                        "DocuSign",
    "stripe-verification=":             "Stripe",
    "mongodb-site-verification=":       "MongoDB Atlas",
    "globalsign-domain-verification=":  "GlobalSign",
    "_globalsign-domain-verification=": "GlobalSign",
    "cisco-ci-domain-verification=":    "Cisco",
    "webex-domain-verification=":       "Cisco Webex",
    "_dnsauth=":                        "Cloudflare (or generic auth)",
    "notion-domain-verification=":      "Notion",
    "loom-site-verification=":          "Loom",
    "zoom-domain-verification=":        "Zoom",
    "zoom_verify_":                     "Zoom",
    "intercom-domain-verification=":    "Intercom",
    "_amazonses=":                      "AWS Simple Email Service",
    "amazonses:":                       "AWS Simple Email Service",
    "pinterest-site-verification=":     "Pinterest",
    "dropbox-domain-verification=":     "Dropbox",
    "miro-verification=":               "Miro",
    "asana-domain-verification=":       "Asana",
    "smartsheet-site-validation=":      "Smartsheet",
    "openai-domain-verification=":      "OpenAI",
    "anthropic-domain-verification=":   "Anthropic",
    "yandex-verification:":             "Yandex",
    "brave-ledger-verification=":       "Brave Rewards",
    "have-i-been-pwned-verification=":  "Have I Been Pwned",
    "onetrust-domain-verification=":    "OneTrust",
    "logmein-verification-code=":       "LogMeIn / GoTo",
}


def _classify_service_tokens(txt_records):
    """
    Scan a list of TXT record strings for known service-verification tokens
    and return a list of (token_prefix, service_name, full_record) tuples.
    Records that match no known prefix are skipped. SPF and DMARC records
    are explicitly excluded since they have dedicated handlers.
    """
    findings = []
    for record in txt_records:
        # Strip surrounding quotes that some resolvers add to display output.
        cleaned = record.strip().strip('"').strip()
        lower = cleaned.lower()
        # Skip records handled elsewhere.
        if lower.startswith(("v=spf1", "v=dmarc1", "v=dkim1", "v=bimi1")):
            continue
        for prefix, service in SERVICE_TOKEN_MAP.items():
            if lower.startswith(prefix):
                findings.append((prefix.rstrip("="), service, cleaned))
                break
    return findings


def _resolve_txt(name, timeout=2.0):
    """Resolve TXT records for a name with a tight timeout. Returns a list of
    joined strings (TXT records can have multiple chunks per RFC 1035) or an
    empty list on any failure."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(name, "TXT")
        records = []
        for r in answers:
            # Each TXT record is a list of byte strings. Decode and join them.
            chunks = [s.decode("utf-8", errors="replace") for s in r.strings]
            records.append("".join(chunks))
        return records
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.Timeout, dns.exception.DNSException):
        return []


def _count_spf_lookups(record_text, depth=0, max_depth=11, visited=None):
    """
    Recursively count the DNS lookups required to evaluate an SPF record.
    Returns a tuple of (lookup_count, void_lookup_count, errors).

    Per RFC 7208 Section 4.6.4, an SPF check may not exceed 10 DNS lookups.
    Void lookups (queries that return NXDOMAIN or empty answers) are capped
    at 2. Recursion is bounded by max_depth as a safety guard against
    malicious or pathological include chains.
    """
    if visited is None:
        visited = set()
    if depth >= max_depth:
        return (0, 0, [f"max recursion depth {max_depth} reached"])

    lookups = 0
    void_lookups = 0
    errors = []

    # SPF records are space-separated mechanism tokens. Strip the version
    # prefix and walk the rest.
    tokens = record_text.replace("v=spf1", "").strip().split()

    for token in tokens:
        # Strip qualifier prefix (+, -, ~, ?) if present. Qualifiers do not
        # change DNS-lookup behavior.
        bare = token.lstrip("+-~?")
        # Split mechanism name from value.
        if ":" in bare:
            name, value = bare.split(":", 1)
        elif "=" in bare:
            name, value = bare.split("=", 1)
        else:
            name, value = bare, ""
        name = name.lower()

        if name not in SPF_LOOKUP_MECHANISMS:
            continue

        lookups += 1

        # For "include" and "redirect", recursively resolve the target.
        if name in ("include", "redirect") and value:
            if value in visited:
                errors.append(f"include loop detected at {value}")
                continue
            visited.add(value)
            child_records = _resolve_txt(value)
            spf_children = [r for r in child_records if r.lower().startswith("v=spf1")]
            if not spf_children:
                void_lookups += 1
                continue
            sub_lookups, sub_void, sub_errs = _count_spf_lookups(
                spf_children[0], depth + 1, max_depth, visited
            )
            lookups += sub_lookups
            void_lookups += sub_void
            errors.extend(sub_errs)

    return (lookups, void_lookups, errors)


def _parse_spf(record_text):
    """Extract the qualifier on `all` and the list of authorized senders."""
    tokens = record_text.replace("v=spf1", "").strip().split()
    qualifier = "?"   # default per RFC 7208 if no `all` mechanism is present
    senders = []

    for token in tokens:
        bare = token.lstrip("+-~?")
        if bare.lower() == "all":
            q_char = token[0] if token[0] in "+-~?" else "+"
            qualifier = {
                "+": "+all (PASS, anyone authorized, MISCONFIGURATION)",
                "-": "-all (HARD FAIL, recommended)",
                "~": "~all (SOFT FAIL, quarantine)",
                "?": "?all (NEUTRAL, no policy)",
            }.get(q_char, q_char)
        elif bare.lower().startswith(("include:", "ip4:", "ip6:", "a:", "mx:", "exists:")):
            senders.append(bare)
        elif bare.lower() in ("a", "mx"):
            senders.append(bare)

    return qualifier, senders


def _parse_dmarc(record_text):
    """Parse a DMARC TXT record into its tag-value pairs."""
    tags = {}
    for part in record_text.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def get_email_security(domain):
    """
    Audit the domain's email-authentication posture: SPF (with recursive
    DNS lookup counting), DMARC, DKIM (probed at common selectors only),
    and BIMI. This is independent of the general DNS enumeration so the
    output can be reasoned about as a single security view.
    """
    print("\n[*] Auditing Email Security...")
    results = {}

    # SPF
    spf_records = [r for r in _resolve_txt(domain) if r.lower().startswith("v=spf1")]
    if spf_records:
        spf = spf_records[0]
        qualifier, senders = _parse_spf(spf)
        lookups, voids, errs = _count_spf_lookups(spf)
        print(f"    [+] SPF: {spf}")
        print(f"          Policy on `all`     : {qualifier}")
        print(f"          DNS lookups (chain) : {lookups} / 10 (RFC 7208 limit)")
        if lookups > 10:
            print(f"          [!] EXCEEDS LIMIT. SPF will return permerror.")
        print(f"          Void lookups        : {voids} / 2 (RFC 7208 limit)")
        if voids > 2:
            print(f"          [!] EXCEEDS LIMIT. SPF will return permerror.")
        for err in errs:
            print(f"          [!] {err}")
        if len(spf_records) > 1:
            print(f"    [!] Multiple SPF records found ({len(spf_records)}). RFC 7208 forbids this.")
        results["SPF"] = {
            "record": spf,
            "qualifier": qualifier,
            "senders": senders,
            "dns_lookups": lookups,
            "void_lookups": voids,
            "errors": errs,
            "duplicate_records": len(spf_records) > 1,
        }
    else:
        print("    [-] No SPF record found")
        results["SPF"] = None

    # DMARC
    dmarc_records = [r for r in _resolve_txt(f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]
    if dmarc_records:
        dmarc = dmarc_records[0]
        tags = _parse_dmarc(dmarc)
        policy = tags.get("p", "none")
        sub_policy = tags.get("sp", policy)
        pct = tags.get("pct", "100")
        rua = tags.get("rua", "")
        ruf = tags.get("ruf", "")
        print(f"    [+] DMARC: {dmarc}")
        print(f"          Policy              : p={policy}")
        if policy == "none":
            print(f"          [!] Policy is 'none'. Reporting only, no enforcement.")
        print(f"          Subdomain policy    : sp={sub_policy}")
        print(f"          Percentage applied  : pct={pct}")
        if rua:
            print(f"          Aggregate reports   : {rua}")
        if ruf:
            print(f"          Forensic reports    : {ruf}")
        results["DMARC"] = {"record": dmarc, "tags": tags}
    else:
        print("    [-] No DMARC record found at _dmarc.{}".format(domain))
        results["DMARC"] = None

    # DKIM
    print(f"    [*] Probing {len(COMMON_DKIM_SELECTORS)} common DKIM selectors...")
    found_selectors = []
    for selector in COMMON_DKIM_SELECTORS:
        records = _resolve_txt(f"{selector}._domainkey.{domain}")
        dkim = [r for r in records if "v=dkim1" in r.lower() or "k=" in r.lower() or "p=" in r.lower()]
        if dkim:
            found_selectors.append((selector, dkim[0]))
    if found_selectors:
        for selector, record in found_selectors:
            preview = record[:60] + "..." if len(record) > 60 else record
            print(f"    [+] DKIM selector '{selector}' found: {preview}")
        results["DKIM"] = found_selectors
    else:
        print("    [-] No DKIM records at common selectors. Custom selectors may exist.")
        results["DKIM"] = []

    # BIMI
    bimi = [r for r in _resolve_txt(f"default._bimi.{domain}") if r.lower().startswith("v=bimi1")]
    if bimi:
        print(f"    [+] BIMI: {bimi[0]}")
        results["BIMI"] = bimi[0]
    else:
        print("    [-] No BIMI record at default._bimi.{}".format(domain))
        results["BIMI"] = None

    return results


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

    # Classify TXT records against the known service-verification map.
    # This produces OSINT signal about which SaaS providers have touched
    # the domain, without sending traffic to those providers.
    txt_records = dns_results.get("TXT", [])
    if txt_records:
        service_findings = _classify_service_tokens(txt_records)
        if service_findings:
            print("\n[*] Service Verifications (TXT-token fingerprints):")
            for prefix, service, _record in service_findings:
                print(f"    [+] {service:<40} (token: {prefix})")
            dns_results["_service_tokens"] = service_findings

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


def save_report(domain, ip, reg_data, dns_data, email_data, http_data, output_file):
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
                    value = ", ".join(str(_format_value(v)) for v in value[:5])
                else:
                    value = _format_value(value)
                f.write(f"  {key}: {value}\n")
        else:
            f.write("  No registration data retrieved.\n")
        f.write("\n")

        f.write("DNS RECORDS\n")
        f.write("-" * 30 + "\n")
        if dns_data:
            for rtype, records in dns_data.items():
                # Skip internal keys (prefixed with underscore) from the
                # standard record listing. They have their own sections.
                if rtype.startswith("_"):
                    continue
                f.write(f"  {rtype}:\n")
                for r in records:
                    f.write(f"    - {r}\n")
        else:
            f.write("  No DNS records retrieved.\n")
        f.write("\n")

        service_tokens = (dns_data or {}).get("_service_tokens", [])
        if service_tokens:
            f.write("SERVICE VERIFICATIONS\n")
            f.write("-" * 30 + "\n")
            f.write("  TXT-token fingerprints indicating SaaS services tied to this domain.\n")
            for prefix, service, record in service_tokens:
                f.write(f"  - {service} (token: {prefix})\n")
                f.write(f"    {record}\n")
            f.write("\n")

        f.write("EMAIL SECURITY\n")
        f.write("-" * 30 + "\n")
        if email_data:
            spf = email_data.get("SPF")
            if spf:
                f.write(f"  SPF: {spf['record']}\n")
                f.write(f"    Qualifier on `all` : {spf['qualifier']}\n")
                f.write(f"    DNS lookups        : {spf['dns_lookups']} / 10\n")
                f.write(f"    Void lookups       : {spf['void_lookups']} / 2\n")
                if spf["dns_lookups"] > 10:
                    f.write(f"    [!] EXCEEDS RFC 7208 limit. SPF will return permerror.\n")
                if spf["void_lookups"] > 2:
                    f.write(f"    [!] EXCEEDS RFC 7208 void-lookup limit.\n")
                if spf["duplicate_records"]:
                    f.write(f"    [!] Multiple SPF records published. RFC 7208 forbids this.\n")
                for err in spf.get("errors", []):
                    f.write(f"    [!] {err}\n")
            else:
                f.write("  SPF: not found\n")

            dmarc = email_data.get("DMARC")
            if dmarc:
                tags = dmarc["tags"]
                f.write(f"  DMARC: {dmarc['record']}\n")
                f.write(f"    Policy           : p={tags.get('p', 'none')}\n")
                f.write(f"    Subdomain policy : sp={tags.get('sp', tags.get('p', 'none'))}\n")
                f.write(f"    Percentage       : pct={tags.get('pct', '100')}\n")
                if tags.get("rua"):
                    f.write(f"    Aggregate reports: {tags['rua']}\n")
                if tags.get("ruf"):
                    f.write(f"    Forensic reports : {tags['ruf']}\n")
            else:
                f.write("  DMARC: not found\n")

            dkim = email_data.get("DKIM", [])
            if dkim:
                f.write(f"  DKIM selectors found ({len(dkim)}):\n")
                for selector, record in dkim:
                    f.write(f"    {selector}: {record[:80]}...\n" if len(record) > 80
                            else f"    {selector}: {record}\n")
            else:
                f.write("  DKIM: no records at common selectors (custom selectors may exist)\n")

            f.write(f"  BIMI: {email_data.get('BIMI') or 'not found'}\n")
        else:
            f.write("  Email security audit was skipped.\n")
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
        description="OSINT Domain Recon Tool. Automated domain reconnaissance via RDAP, DNS, email-auth, and HTTP probing."
    )
    parser.add_argument("domain", help="Target domain to scan (e.g., example.com)")
    parser.add_argument("-o", "--output", help="Save report to a file", default=None)
    parser.add_argument("--no-http", action="store_true", help="Skip HTTP/HTTPS probing")
    parser.add_argument("--no-email-security", action="store_true",
                        help="Skip email-authentication audit (SPF/DMARC/DKIM/BIMI)")
    args = parser.parse_args()

    domain = validate_domain(args.domain)

    print(f"[*] Target : {domain}")
    print(f"[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    ip       = resolve_ip(domain)
    reg_data = get_registration(domain)
    dns_data = get_dns_records(domain)

    email_data = {}
    if not args.no_email_security:
        email_data = get_email_security(domain)

    http_data = {}
    if not args.no_http:
        http_data = check_http_status(domain)

    if args.output:
        save_report(domain, ip, reg_data, dns_data, email_data, http_data, args.output)

    print(f"\n[*] Scan complete: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("[*] Remember: only run this tool against domains you own or have permission to test.\n")


if __name__ == "__main__":
    main()
