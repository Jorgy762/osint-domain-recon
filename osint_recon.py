#!/usr/bin/env python3
"""
OSINT Domain Recon Tool
Author: Jorgy762
GitHub: https://github.com/Jorgy762/osint-domain-recon

Description:
    A command-line tool for automated domain reconnaissance.
    Given a target domain, it pulls registration data via RDAP
    (Registration Data Access Protocol), enumerates DNS records,
    classifies SaaS service-verification tokens, audits email
    authentication (SPF, DMARC, DKIM, BIMI), and probes HTTP/HTTPS
    availability. All in one run, with optional plaintext report
    export. Falls back to legacy WHOIS when a TLD has no RDAP
    service available.

Usage:
    python osint_recon.py example.com
    python osint_recon.py example.com -o report.txt
    python osint_recon.py example.com --no-http
    python osint_recon.py example.com --no-email-security

Dependencies:
    pip install whoisit python-whois dnspython requests

File structure (top to bottom):
    1. Imports and dependency checks
    2. Constants (regex, caching, lookup tables)
    3. Generic utility helpers
    4. CLI banner and input validation
    5. Scan stage: IP resolution
    6. Scan stage: registration data (RDAP with WHOIS fallback)
    7. Scan stage: DNS enumeration and service-token classification
    8. Scan stage: email security audit (SPF, DMARC, DKIM, BIMI)
    9. Scan stage: HTTP/HTTPS probing
   10. Report writer (one section per scan stage)
   11. Main entry point

Disclaimer:
    This tool is intended for educational purposes and authorized
    reconnaissance only. Only run it against domains you own or have
    explicit written permission to test. Unauthorized use may violate
    applicable laws including the Canadian Criminal Code (Section 342.1)
    and equivalent legislation in other jurisdictions.
"""

# ============================================================================
# IMPORTS AND DEPENDENCY CHECKS
# ============================================================================

import argparse
import re
import socket
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# Third-party dependencies. Each is wrapped in try/except so a missing package
# produces a friendly install instruction instead of a Python traceback.
try:
    import whoisit
except ImportError:
    print("[!] Missing dependency: whoisit")
    print("    Run: pip install whoisit")
    sys.exit(1)

try:
    import whois  # legacy WHOIS library, used only as a fallback
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


# ============================================================================
# CONSTANTS
# ============================================================================

# Domain validation regex.
#
# The rules encoded here (per RFC 1035 and RFC 1123):
#   - Total length: 1 to 253 characters (enforced by the positive lookahead).
#   - Each label: 1 to 63 characters of letters, digits, or hyphens.
#   - No leading hyphen on a label: (?!-) negative lookahead at label start.
#   - No trailing hyphen on a label: (?<!-) negative lookbehind at label end.
#   - At least one dot separator (one or more labels followed by a TLD).
#   - TLD: 2 to 63 letter characters (no digits in TLDs per common practice).
DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)"                          # total length 1 to 253
    r"(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+"    # one or more labels with dot
    r"[A-Za-z]{2,63}$"                         # final TLD label
)

# Cache the RDAP bootstrap data on disk. IANA refreshes the registry roughly
# weekly, so a 7-day cache window avoids a network round-trip on every run
# without serving stale data.
CACHE_DIR: Path = Path.home() / ".cache" / "osint-domain-recon"
CACHE_FILE: Path = CACHE_DIR / "rdap_bootstrap.json"
CACHE_DAYS: int = 7

# DNS resolver timeout for the email-security audit. Tight enough to keep the
# 29-selector DKIM probe from dominating scan time, loose enough to tolerate
# slow authoritative servers.
DNS_TIMEOUT_SECONDS: float = 2.0

# HTTP request timeout for the availability probe.
HTTP_TIMEOUT_SECONDS: int = 5

# Mechanisms in an SPF record that trigger a DNS lookup. Per RFC 7208, these
# count against the 10-lookup limit. The "ip4", "ip6", and "all" mechanisms
# do not trigger lookups and do not count against the limit.
SPF_LOOKUP_MECHANISMS: tuple[str, ...] = (
    "include", "a", "mx", "ptr", "exists", "redirect"
)

# RFC 7208 limits for SPF evaluation.
SPF_MAX_DNS_LOOKUPS: int = 10
SPF_MAX_VOID_LOOKUPS: int = 2
SPF_MAX_RECURSION_DEPTH: int = 11   # one above the lookup limit as safety guard

# Common DKIM selectors observed across major mail providers. This list is not
# exhaustive. Custom or vendor-rotated selectors will be missed. A "DKIM not
# found" result here means "no DKIM at known common selectors", not "DKIM does
# not exist for this domain". The tool surfaces this limitation in its output.
COMMON_DKIM_SELECTORS: list[str] = [
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

# Service verification token prefixes observed in TXT records across major
# SaaS providers. When a domain owner sets up a third-party service that
# requires DNS-based domain proof, the service issues a verification token
# that gets published as a TXT record. These tokens are persistent fingerprints
# of which services have touched a domain: useful OSINT signal for mapping
# a target's SaaS footprint without sending traffic to the services themselves.
#
# Each entry maps a prefix (matched case-insensitively against the start of
# the record after stripping quotes) to the service it identifies.
SERVICE_TOKEN_MAP: dict[str, str] = {
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


# ============================================================================
# GENERIC UTILITY HELPERS
# ============================================================================

def _format_value(value: Any) -> Any:
    """
    Normalize a single value for display. Datetimes are stripped to second
    precision (RDAP servers sometimes return microsecond timestamps that are
    noise for recon work). All other types pass through unchanged.
    """
    if isinstance(value, datetime):
        return value.replace(microsecond=0).isoformat(sep=" ")
    return value


def _print_fields(fields: dict[str, Any]) -> None:
    """
    Pretty-print a key/value dict to the terminal. Skips empty values,
    deduplicates list entries (some registrars return duplicates with
    different casing), trims long lists to five entries, and normalizes
    datetimes via _format_value.
    """
    for key, value in fields.items():
        # Skip empty values across all the common empty types.
        if value in (None, "", [], {}):
            continue

        if isinstance(value, list):
            # Deduplicate while preserving original order.
            seen: set[str] = set()
            unique: list[str] = []
            for v in value:
                s = str(_format_value(v))
                if s not in seen:
                    seen.add(s)
                    unique.append(s)
            value = unique[0] if len(unique) == 1 else ", ".join(unique[:5])
        else:
            value = _format_value(value)

        print(f"    [+] {key}: {value}")


# ============================================================================
# CLI BANNER AND INPUT VALIDATION
# ============================================================================

def print_banner() -> None:
    """Display the startup banner and authorized-use reminder."""
    banner = """
+==============================================+
|          OSINT Domain Recon Tool             |
|          github.com/Jorgy762                 |
|          For authorized use only             |
+==============================================+
    """
    print(banner)


def validate_domain(raw: str) -> str:
    """
    Normalize and validate a domain name. Strips URL schemes, paths,
    trailing dots, and uppercase characters, then validates against
    DOMAIN_REGEX. Exits the program with a friendly error message if
    the input is not a well-formed domain.
    """
    cleaned = (
        raw.strip().lower()
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]          # drop path component if URL was passed
        .rstrip(".")            # drop trailing dot (FQDN form)
    )
    if not DOMAIN_REGEX.match(cleaned):
        print(f"[!] Invalid domain format: {cleaned!r}")
        sys.exit(1)
    return cleaned


# ============================================================================
# STAGE 1: IP RESOLUTION
# ============================================================================

def resolve_ip(domain: str) -> str | None:
    """
    Resolve the A record for the domain via the system DNS resolver.
    Returns the IPv4 address as a string, or None on resolution failure.
    """
    print("\n[*] Resolving IP Address...")
    try:
        ip = socket.gethostbyname(domain)
        print(f"    [+] IP Address : {ip}")
        return ip
    except socket.gaierror as e:
        print(f"    [-] Could not resolve IP: {e}")
        return None


# ============================================================================
# STAGE 2: REGISTRATION DATA (RDAP WITH WHOIS FALLBACK)
# ============================================================================

def ensure_rdap_bootstrapped() -> None:
    """
    Make sure the whoisit library has its RDAP bootstrap data loaded.

    The bootstrap tells whoisit which RDAP server is authoritative for a
    given TLD, IP block, or ASN. Without it, no query can be routed.

    Strategy:
      1. If already loaded in-process, do nothing.
      2. If a fresh disk cache exists (<= CACHE_DAYS old), load that.
      3. Otherwise fetch from IANA and write a new cache.

    Cache write failures are non-fatal. The tool still works, just slower.
    """
    if whoisit.is_bootstrapped():
        return

    # Try the disk cache first.
    if CACHE_FILE.exists():
        try:
            cached = CACHE_FILE.read_text(encoding="utf-8")
            whoisit.load_bootstrap_data(cached)
            if not whoisit.bootstrap_is_older_than(CACHE_DAYS):
                return
        except Exception:
            # Corrupt or unreadable cache. Discard and fall through.
            whoisit.clear_bootstrapping()

    # No cache or stale cache: fetch fresh and write the new copy.
    whoisit.bootstrap()
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(whoisit.save_bootstrap_data(), encoding="utf-8")
    except OSError as e:
        print(f"    [!] Could not write bootstrap cache ({e}). Continuing.")


def _whois_fallback(domain: str) -> dict[str, Any]:
    """
    Fallback to legacy WHOIS via python-whois when RDAP is unavailable.
    Returns a dict in the same shape as the RDAP path so callers do not
    need to know which protocol succeeded.
    """
    print("\n[*] Running WHOIS lookup...")
    try:
        w = whois.whois(domain)
        fields: dict[str, Any] = {
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


def get_registration(domain: str) -> dict[str, Any]:
    """
    Look up domain registration data, RDAP first with WHOIS as fallback.
    Returns a dict with normalized field names and a "Source" key that
    indicates which protocol returned the data ("RDAP", "WHOIS", or
    "FAILED").
    """
    print("\n[*] Looking up registration data (RDAP)...")
    try:
        ensure_rdap_bootstrapped()
        r = whoisit.domain(domain)

        # Extract the registrar's display name from the registrar entity.
        registrar = ""
        registrars = r.get("entities", {}).get("registrar", [])
        if registrars:
            registrar = registrars[0].get("name", "")

        # RDAP does not return registrant country at the top level. It can
        # appear inside any role's vCard. Walk the common roles in priority
        # order and take the first hit.
        country = ""
        for role in ("registrant", "administrative", "technical", "registrar"):
            for entity in r.get("entities", {}).get(role, []):
                country = entity.get("country", "")
                if country:
                    break
            if country:
                break

        fields: dict[str, Any] = {
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

    # Whoisit raises specific exception types for distinct failure modes.
    # All of them trigger the WHOIS fallback path.
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


# ============================================================================
# STAGE 3: DNS ENUMERATION AND SERVICE-TOKEN CLASSIFICATION
# ============================================================================

def _classify_service_tokens(txt_records: list[str]) -> list[tuple[str, str, str]]:
    """
    Scan TXT records for known service-verification token prefixes.
    Returns a list of (token_prefix, service_name, full_record) tuples
    for matched records. SPF, DMARC, DKIM, and BIMI records are excluded
    since those have dedicated handlers in the email-security stage.
    """
    findings: list[tuple[str, str, str]] = []
    for record in txt_records:
        # Strip surrounding quotes that some resolvers include in their output.
        cleaned = record.strip().strip('"').strip()
        lower = cleaned.lower()

        # Skip records owned by other scan stages.
        if lower.startswith(("v=spf1", "v=dmarc1", "v=dkim1", "v=bimi1")):
            continue

        for prefix, service in SERVICE_TOKEN_MAP.items():
            if lower.startswith(prefix):
                findings.append((prefix.rstrip("="), service, cleaned))
                break

    return findings


def get_dns_records(domain: str) -> dict[str, Any]:
    """
    Enumerate the standard DNS record types for the domain, then run
    service-token classification on the TXT records. Returns a dict
    keyed by record type (e.g. "A", "MX") with list-of-string values.
    Service-token findings are stored under the internal key
    "_service_tokens" (underscore-prefixed so the report writer can
    skip it when iterating standard record types).
    """
    print("\n[*] Enumerating DNS Records...")
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    dns_results: dict[str, Any] = {}

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
            break   # no point continuing if the domain itself does not resolve
        except dns.resolver.Timeout:
            print(f"    [-] {record_type} lookup timed out")
        except Exception as e:
            print(f"    [-] {record_type} lookup error: {e}")

    # Classify any TXT records found against the known service-token map.
    # Produces OSINT signal about SaaS providers tied to the domain.
    txt_records = dns_results.get("TXT", [])
    if txt_records:
        service_findings = _classify_service_tokens(txt_records)
        if service_findings:
            print("\n[*] Service Verifications (TXT-token fingerprints):")
            for prefix, service, _record in service_findings:
                print(f"    [+] {service:<40} (token: {prefix})")
            dns_results["_service_tokens"] = service_findings

    return dns_results


# ============================================================================
# STAGE 4: EMAIL SECURITY AUDIT
# ============================================================================

def _resolve_txt(name: str, timeout: float = DNS_TIMEOUT_SECONDS) -> list[str]:
    """
    Resolve TXT records for a name with a tight timeout. Returns a list
    of joined strings (TXT records can have multiple chunks per RFC 1035,
    which dnspython exposes as a list of byte strings).

    Returns an empty list on any failure: NXDOMAIN, NoAnswer, timeout,
    or any other DNS exception. Email-security checks are best-effort
    and a single failed lookup should not crash the scan.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(name, "TXT")
        records: list[str] = []
        for r in answers:
            # Each TXT record is a list of byte strings. Decode each chunk
            # and join them into a single string.
            chunks = [s.decode("utf-8", errors="replace") for s in r.strings]
            records.append("".join(chunks))
        return records
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.Timeout, dns.exception.DNSException):
        return []


def _count_spf_lookups(
    record_text: str,
    depth: int = 0,
    max_depth: int = SPF_MAX_RECURSION_DEPTH,
    visited: set[str] | None = None,
) -> tuple[int, int, list[str]]:
    """
    Recursively count the DNS lookups required to evaluate an SPF record.
    Returns (lookup_count, void_lookup_count, errors).

    Per RFC 7208 Section 4.6.4, an SPF check may not exceed 10 DNS lookups
    total. Void lookups (queries that return NXDOMAIN or empty answers)
    are capped separately at 2.

    The recursion handles "include" and "redirect" mechanisms by fetching
    the referenced SPF record and counting its lookups too. Recursion is
    bounded by max_depth as a safety guard against malicious or pathological
    include chains, and the visited set prevents infinite loops if a
    record incorrectly includes itself transitively.
    """
    if visited is None:
        visited = set()
    if depth >= max_depth:
        return (0, 0, [f"max recursion depth {max_depth} reached"])

    lookups = 0
    void_lookups = 0
    errors: list[str] = []

    # SPF records are space-separated mechanism tokens after the "v=spf1"
    # version prefix. Strip the prefix and walk the rest.
    tokens = record_text.replace("v=spf1", "").strip().split()

    for token in tokens:
        # Strip qualifier prefix (+ - ~ ?) if present. Qualifiers affect
        # pass/fail semantics but do not change DNS lookup behavior.
        bare = token.lstrip("+-~?")

        # Mechanisms come in three forms:
        #   "include:value"  (colon-separated, e.g. include:_spf.google.com)
        #   "redirect=value" (equals-separated, e.g. redirect=spf.example.com)
        #   "a" or "mx" alone (no value, refers to the current domain)
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

        # For "include" and "redirect", recursively resolve the target
        # record and add its lookups to the running total.
        if name in ("include", "redirect") and value:
            if value in visited:
                errors.append(f"include loop detected at {value}")
                continue
            visited.add(value)

            child_records = _resolve_txt(value)
            spf_children = [r for r in child_records if r.lower().startswith("v=spf1")]

            if not spf_children:
                # No SPF record returned. This counts as a void lookup
                # per RFC 7208.
                void_lookups += 1
                continue

            sub_lookups, sub_void, sub_errs = _count_spf_lookups(
                spf_children[0], depth + 1, max_depth, visited
            )
            lookups += sub_lookups
            void_lookups += sub_void
            errors.extend(sub_errs)

    return (lookups, void_lookups, errors)


def _parse_spf(record_text: str) -> tuple[str, list[str]]:
    """
    Extract the qualifier on the `all` mechanism (which sets the default
    policy for non-matching senders) and the list of authorized-sender
    mechanisms from an SPF record.

    Returns (qualifier_description, sender_list).
    """
    tokens = record_text.replace("v=spf1", "").strip().split()
    qualifier = "?"   # RFC 7208 default if no `all` mechanism is present
    senders: list[str] = []

    for token in tokens:
        bare = token.lstrip("+-~?")

        if bare.lower() == "all":
            # The qualifier is the leading character if present, else "+".
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


def _parse_dmarc(record_text: str) -> dict[str, str]:
    """
    Parse a DMARC TXT record into its tag-value pairs.
    DMARC records look like: v=DMARC1; p=reject; pct=100; rua=mailto:...
    """
    tags: dict[str, str] = {}
    for part in record_text.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def _audit_spf(domain: str) -> dict[str, Any] | None:
    """
    Audit the domain's SPF record: parse the policy, count the recursive
    DNS lookups against RFC 7208 limits, and surface void lookups and
    duplicate-record errors.
    Returns a result dict, or None if no SPF record exists.
    """
    spf_records = [r for r in _resolve_txt(domain) if r.lower().startswith("v=spf1")]
    if not spf_records:
        print("    [-] No SPF record found")
        return None

    spf = spf_records[0]
    qualifier, senders = _parse_spf(spf)
    lookups, voids, errs = _count_spf_lookups(spf)

    print(f"    [+] SPF: {spf}")
    print(f"          Policy on `all`     : {qualifier}")
    print(f"          DNS lookups (chain) : {lookups} / {SPF_MAX_DNS_LOOKUPS} (RFC 7208 limit)")
    if lookups > SPF_MAX_DNS_LOOKUPS:
        print(f"          [!] EXCEEDS LIMIT. SPF will return permerror.")
    print(f"          Void lookups        : {voids} / {SPF_MAX_VOID_LOOKUPS} (RFC 7208 limit)")
    if voids > SPF_MAX_VOID_LOOKUPS:
        print(f"          [!] EXCEEDS LIMIT. SPF will return permerror.")
    for err in errs:
        print(f"          [!] {err}")
    if len(spf_records) > 1:
        print(f"    [!] Multiple SPF records found ({len(spf_records)}). RFC 7208 forbids this.")

    return {
        "record": spf,
        "qualifier": qualifier,
        "senders": senders,
        "dns_lookups": lookups,
        "void_lookups": voids,
        "errors": errs,
        "duplicate_records": len(spf_records) > 1,
    }


def _audit_dmarc(domain: str) -> dict[str, Any] | None:
    """
    Audit the domain's DMARC record at _dmarc.{domain}. Surfaces the
    enforcement policy and flags p=none (reporting-only, no enforcement).
    Returns a result dict, or None if no DMARC record exists.
    """
    dmarc_records = [
        r for r in _resolve_txt(f"_dmarc.{domain}")
        if r.lower().startswith("v=dmarc1")
    ]
    if not dmarc_records:
        print(f"    [-] No DMARC record found at _dmarc.{domain}")
        return None

    dmarc = dmarc_records[0]
    tags = _parse_dmarc(dmarc)
    policy = tags.get("p", "none")
    sub_policy = tags.get("sp", policy)   # subdomain policy defaults to main
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

    return {"record": dmarc, "tags": tags}


def _audit_dkim(domain: str) -> list[tuple[str, str]]:
    """
    Probe COMMON_DKIM_SELECTORS for DKIM public keys. Returns a list of
    (selector_name, record_text) tuples for each selector that returned
    a DKIM-looking record. Empty list means "no DKIM at common selectors"
    (which is NOT the same as "no DKIM exists": custom selectors may be
    in use).
    """
    print(f"    [*] Probing {len(COMMON_DKIM_SELECTORS)} common DKIM selectors...")
    found: list[tuple[str, str]] = []

    for selector in COMMON_DKIM_SELECTORS:
        records = _resolve_txt(f"{selector}._domainkey.{domain}")
        # DKIM detection is loose: accept records containing v=DKIM1 OR
        # k= (key type) OR p= (public key). RFC 6376 allows the version
        # tag to be omitted, so a strict version check would miss some
        # legitimate records.
        dkim = [
            r for r in records
            if "v=dkim1" in r.lower() or "k=" in r.lower() or "p=" in r.lower()
        ]
        if dkim:
            found.append((selector, dkim[0]))

    if found:
        for selector, record in found:
            preview = record[:60] + "..." if len(record) > 60 else record
            print(f"    [+] DKIM selector '{selector}' found: {preview}")
    else:
        print("    [-] No DKIM records at common selectors. Custom selectors may exist.")

    return found


def _audit_bimi(domain: str) -> str | None:
    """
    Look up the BIMI record at default._bimi.{domain}. BIMI requires a
    DMARC policy of quarantine or reject as a prerequisite, so its
    presence implies a mature mail security posture.
    """
    bimi = [
        r for r in _resolve_txt(f"default._bimi.{domain}")
        if r.lower().startswith("v=bimi1")
    ]
    if bimi:
        print(f"    [+] BIMI: {bimi[0]}")
        return bimi[0]

    print(f"    [-] No BIMI record at default._bimi.{domain}")
    return None


def get_email_security(domain: str) -> dict[str, Any]:
    """
    Coordinate the email-authentication audit. Each protocol is handled
    by its own helper function. Returns a single results dict keyed by
    protocol name ("SPF", "DMARC", "DKIM", "BIMI").
    """
    print("\n[*] Auditing Email Security...")
    return {
        "SPF":   _audit_spf(domain),
        "DMARC": _audit_dmarc(domain),
        "DKIM":  _audit_dkim(domain),
        "BIMI":  _audit_bimi(domain),
    }


# ============================================================================
# STAGE 5: HTTP/HTTPS PROBING
# ============================================================================

def check_http_status(domain: str) -> dict[str, dict[str, Any]]:
    """
    Probe both HTTP and HTTPS endpoints on the domain. Captures the
    final status code (after redirects), the Server header, and the
    final URL the request resolved to.
    Returns a dict keyed by scheme ("http", "https").
    """
    print("\n[*] Checking HTTP/HTTPS Status...")
    results: dict[str, dict[str, Any]] = {}

    for scheme in ["http", "https"]:
        url = f"{scheme}://{domain}"
        try:
            response = requests.get(url, timeout=HTTP_TIMEOUT_SECONDS, allow_redirects=True)
            status = response.status_code
            server = response.headers.get("Server", "Not disclosed")
            final_url = response.url
            print(f"    [+] {scheme.upper():<6} Status: {status} | Server: {server} | Final URL: {final_url}")
            results[scheme] = {
                "status_code": status,
                "server": server,
                "final_url": final_url,
            }
        except requests.exceptions.SSLError:
            print(f"    [!] {scheme.upper():<6} SSL certificate error")
        except requests.exceptions.ConnectionError:
            print(f"    [-] {scheme.upper():<6} Connection refused or host unreachable")
        except requests.exceptions.Timeout:
            print(f"    [-] {scheme.upper():<6} Request timed out after {HTTP_TIMEOUT_SECONDS} seconds")
        except Exception as e:
            print(f"    [-] {scheme.upper():<6} Unexpected error: {e}")

    return results


# ============================================================================
# REPORT WRITER (one section per scan stage)
# ============================================================================

def _write_header(f: Any, domain: str, timestamp: str) -> None:
    """Write the report's top-of-file banner block."""
    f.write("=" * 55 + "\n")
    f.write("  OSINT Domain Recon Report\n")
    f.write("=" * 55 + "\n")
    f.write(f"  Target Domain : {domain}\n")
    f.write(f"  Scan Time     : {timestamp}\n")
    f.write(f"  Tool          : github.com/Jorgy762/osint-domain-recon\n")
    f.write("=" * 55 + "\n\n")


def _write_ip_section(f: Any, ip: str | None) -> None:
    """Write the IP resolution section."""
    f.write("IP RESOLUTION\n")
    f.write("-" * 30 + "\n")
    f.write(f"  IP Address: {ip if ip else 'Could not resolve'}\n\n")


def _write_registration_section(f: Any, reg_data: dict[str, Any]) -> None:
    """Write the registration data section (RDAP or WHOIS results)."""
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


def _write_dns_section(f: Any, dns_data: dict[str, Any]) -> None:
    """
    Write the standard DNS records section. Internal keys (those
    prefixed with underscore, like "_service_tokens") are filtered out
    here because they have their own dedicated section.
    """
    f.write("DNS RECORDS\n")
    f.write("-" * 30 + "\n")
    if dns_data:
        for rtype, records in dns_data.items():
            if rtype.startswith("_"):
                continue   # internal key, handled by another section
            f.write(f"  {rtype}:\n")
            for r in records:
                f.write(f"    - {r}\n")
    else:
        f.write("  No DNS records retrieved.\n")
    f.write("\n")


def _write_service_tokens_section(f: Any, dns_data: dict[str, Any]) -> None:
    """Write the SaaS service-token classification section, if any were found."""
    service_tokens = (dns_data or {}).get("_service_tokens", [])
    if not service_tokens:
        return

    f.write("SERVICE VERIFICATIONS\n")
    f.write("-" * 30 + "\n")
    f.write("  TXT-token fingerprints indicating SaaS services tied to this domain.\n")
    for prefix, service, record in service_tokens:
        f.write(f"  - {service} (token: {prefix})\n")
        f.write(f"    {record}\n")
    f.write("\n")


def _write_email_security_section(f: Any, email_data: dict[str, Any]) -> None:
    """Write the email security audit section: SPF, DMARC, DKIM, BIMI."""
    f.write("EMAIL SECURITY\n")
    f.write("-" * 30 + "\n")
    if not email_data:
        f.write("  Email security audit was skipped.\n\n")
        return

    # SPF
    spf = email_data.get("SPF")
    if spf:
        f.write(f"  SPF: {spf['record']}\n")
        f.write(f"    Qualifier on `all` : {spf['qualifier']}\n")
        f.write(f"    DNS lookups        : {spf['dns_lookups']} / {SPF_MAX_DNS_LOOKUPS}\n")
        f.write(f"    Void lookups       : {spf['void_lookups']} / {SPF_MAX_VOID_LOOKUPS}\n")
        if spf["dns_lookups"] > SPF_MAX_DNS_LOOKUPS:
            f.write(f"    [!] EXCEEDS RFC 7208 limit. SPF will return permerror.\n")
        if spf["void_lookups"] > SPF_MAX_VOID_LOOKUPS:
            f.write(f"    [!] EXCEEDS RFC 7208 void-lookup limit.\n")
        if spf["duplicate_records"]:
            f.write(f"    [!] Multiple SPF records published. RFC 7208 forbids this.\n")
        for err in spf.get("errors", []):
            f.write(f"    [!] {err}\n")
    else:
        f.write("  SPF: not found\n")

    # DMARC
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

    # DKIM
    dkim = email_data.get("DKIM", [])
    if dkim:
        f.write(f"  DKIM selectors found ({len(dkim)}):\n")
        for selector, record in dkim:
            if len(record) > 80:
                f.write(f"    {selector}: {record[:80]}...\n")
            else:
                f.write(f"    {selector}: {record}\n")
    else:
        f.write("  DKIM: no records at common selectors (custom selectors may exist)\n")

    # BIMI
    f.write(f"  BIMI: {email_data.get('BIMI') or 'not found'}\n\n")


def _write_http_section(f: Any, http_data: dict[str, Any]) -> None:
    """Write the HTTP/HTTPS probe section."""
    f.write("HTTP/HTTPS STATUS\n")
    f.write("-" * 30 + "\n")
    if http_data:
        for scheme, data in http_data.items():
            f.write(f"  {scheme.upper()}:\n")
            for k, v in data.items():
                f.write(f"    {k}: {v}\n")
    else:
        f.write("  HTTP probing was skipped or returned no results.\n")


def save_report(
    domain: str,
    ip: str | None,
    reg_data: dict[str, Any],
    dns_data: dict[str, Any],
    email_data: dict[str, Any],
    http_data: dict[str, Any],
    output_file: str,
) -> None:
    """
    Coordinator that opens the output file and dispatches to each
    section-writer helper in display order.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(output_file, "w", encoding="utf-8") as f:
        _write_header(f, domain, timestamp)
        _write_ip_section(f, ip)
        _write_registration_section(f, reg_data)
        _write_dns_section(f, dns_data)
        _write_service_tokens_section(f, dns_data)
        _write_email_security_section(f, email_data)
        _write_http_section(f, http_data)
    print(f"\n[+] Report saved to: {output_file}")


# ============================================================================
# ENTRY POINT
# ============================================================================

def main() -> None:
    """Parse CLI arguments, run each scan stage in order, optionally write report."""
    print_banner()

    parser = argparse.ArgumentParser(
        description=(
            "OSINT Domain Recon Tool. Automated domain reconnaissance via "
            "RDAP, DNS, email-auth, and HTTP probing."
        )
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


if __name__ == "__main__":
    main()
