"""
Report writer: serializes scan results to a plaintext file.

The save_report function is a thin coordinator that dispatches to
per-section writers (_write_ip_section, _write_registration_section,
etc.) in display order. Adding a new report section means writing
one helper and adding one line to the coordinator.
"""

from datetime import datetime
from typing import Any

from .constants import SPF_MAX_DNS_LOOKUPS, SPF_MAX_VOID_LOOKUPS
from .utils import _format_value


def _write_header(f: Any, domain: str, timestamp: str) -> None:
    """Write the report's top-of-file banner block."""
    f.write("=" * 55 + "\n")
    f.write("  OSINT Domain Recon Report\n")
    f.write("=" * 55 + "\n")
    f.write(f"  Target Domain : {domain}\n")
    f.write(f"  Scan Time     : {timestamp}\n")
    f.write("  Tool          : github.com/Jorgy762/osint-domain-recon\n")
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
    Write the standard DNS records section.

    Internal keys (those prefixed with underscore, like "_service_tokens")
    are filtered out here because they have their own dedicated section.
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
            f.write("    [!] EXCEEDS RFC 7208 limit. SPF will return permerror.\n")
        if spf["void_lookups"] > SPF_MAX_VOID_LOOKUPS:
            f.write("    [!] EXCEEDS RFC 7208 void-lookup limit.\n")
        if spf["duplicate_records"]:
            f.write("    [!] Multiple SPF records published. RFC 7208 forbids this.\n")
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
