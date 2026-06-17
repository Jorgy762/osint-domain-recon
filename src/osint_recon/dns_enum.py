"""
DNS operations: IP resolution, full record-type enumeration, and
classification of SaaS verification tokens found in TXT records.

This module covers both the "stage 1: IP" and "stage 3: DNS"
scan stages from a UX perspective, since both are fundamentally
DNS lookups against the target domain.
"""

import socket
from typing import Any

import dns.resolver

from .constants import SERVICE_TOKEN_MAP


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
    service-token classification on the TXT records.

    Returns a dict keyed by record type (e.g. "A", "MX") with
    list-of-string values. Service-token findings are stored under the
    internal key "_service_tokens" (underscore-prefixed so the report
    writer can skip it when iterating standard record types).
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
            print("    [-] Domain does not exist (NXDOMAIN)")
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
