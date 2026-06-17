"""
Tests for osint_recon.reporting.

Covers the section-writer helpers (_write_*). Tests use io.StringIO as a
file-like object stand-in, which lets us verify the formatted output
without writing real files to disk.
"""

import io

from osint_recon.reporting import (
    _write_dns_section,
    _write_email_security_section,
    _write_header,
    _write_http_section,
    _write_ip_section,
    _write_registration_section,
    _write_service_tokens_section,
)

# ============================================================================
# HEADER SECTION
# ============================================================================

def test_header_includes_domain_and_timestamp():
    """Header should include the target domain and scan time"""
    buf = io.StringIO()
    _write_header(buf, "example.com", "2026-05-31 22:53:29")
    output = buf.getvalue()
    assert "example.com" in output
    assert "2026-05-31 22:53:29" in output
    assert "OSINT Domain Recon Report" in output


# ============================================================================
# IP RESOLUTION SECTION
# ============================================================================

def test_ip_section_with_resolved_address():
    """IP section should include the resolved address when present"""
    buf = io.StringIO()
    _write_ip_section(buf, "93.184.216.34")
    assert "93.184.216.34" in buf.getvalue()


def test_ip_section_with_failed_resolution():
    """IP section should show fallback text when resolution returned None"""
    buf = io.StringIO()
    _write_ip_section(buf, None)
    assert "Could not resolve" in buf.getvalue()


# ============================================================================
# REGISTRATION SECTION
# ============================================================================

def test_registration_section_outputs_all_fields():
    """Registration section should output every non-empty field"""
    buf = io.StringIO()
    data = {
        "Source": "RDAP",
        "Registrar": "NAMECHEAP INC",
        "Name Servers": ["ns1.example.com", "ns2.example.com"],
    }
    _write_registration_section(buf, data)
    output = buf.getvalue()
    assert "RDAP" in output
    assert "NAMECHEAP INC" in output
    assert "ns1.example.com" in output


def test_registration_section_failed_lookup():
    """Registration section should show fallback text when Source=FAILED"""
    buf = io.StringIO()
    _write_registration_section(buf, {"Source": "FAILED"})
    assert "No registration data retrieved" in buf.getvalue()


def test_registration_section_skips_empty_values():
    """Empty values (None, '', [], {}) should be skipped"""
    buf = io.StringIO()
    data = {
        "Source": "RDAP",
        "Registrar": "",            # should be skipped
        "Status": [],               # should be skipped
        "DNSSEC": "signedDelegation",
    }
    _write_registration_section(buf, data)
    output = buf.getvalue()
    assert "Registrar" not in output    # because value was empty string
    assert "Status" not in output       # because value was empty list
    assert "DNSSEC" in output


# ============================================================================
# DNS RECORDS SECTION
# ============================================================================

def test_dns_section_writes_all_record_types():
    """All DNS record types should be written under their type heading"""
    buf = io.StringIO()
    dns_data = {
        "A": ["192.0.2.1"],
        "MX": ["10 mail.example.com"],
    }
    _write_dns_section(buf, dns_data)
    output = buf.getvalue()
    assert "192.0.2.1" in output
    assert "mail.example.com" in output


def test_dns_section_skips_underscore_keys():
    """Internal keys (underscore-prefixed) should not appear in the DNS section"""
    buf = io.StringIO()
    dns_data = {
        "A": ["192.0.2.1"],
        "_service_tokens": [("ms", "Microsoft 365", "MS=ms123")],
    }
    _write_dns_section(buf, dns_data)
    output = buf.getvalue()
    assert "192.0.2.1" in output
    assert "_service_tokens" not in output


# ============================================================================
# SERVICE VERIFICATIONS SECTION
# ============================================================================

def test_service_tokens_section_omitted_when_empty():
    """No section should be written when no service tokens were found"""
    buf = io.StringIO()
    _write_service_tokens_section(buf, {})
    assert buf.getvalue() == ""


def test_service_tokens_section_renders_findings():
    """Findings should be rendered with service name and token"""
    buf = io.StringIO()
    dns_data = {
        "_service_tokens": [("ms", "Microsoft 365 / Azure AD tenant", "MS=ms12345")],
    }
    _write_service_tokens_section(buf, dns_data)
    output = buf.getvalue()
    assert "Microsoft 365" in output
    assert "MS=ms12345" in output


# ============================================================================
# EMAIL SECURITY SECTION
# ============================================================================

def test_email_security_section_skipped_message():
    """Empty email_data should produce the skipped-audit message"""
    buf = io.StringIO()
    _write_email_security_section(buf, {})
    assert "skipped" in buf.getvalue().lower()


def test_email_security_section_renders_spf():
    """SPF data should appear in the email security section"""
    buf = io.StringIO()
    email_data = {
        "SPF": {
            "record": "v=spf1 -all",
            "qualifier": "-all (HARD FAIL, recommended)",
            "dns_lookups": 0,
            "void_lookups": 0,
            "duplicate_records": False,
            "errors": [],
        },
        "DMARC": None,
        "DKIM": [],
        "BIMI": None,
    }
    _write_email_security_section(buf, email_data)
    output = buf.getvalue()
    assert "v=spf1 -all" in output
    assert "HARD FAIL" in output


def test_email_security_warns_on_spf_lookup_exceeded():
    """SPF section should flag when lookups exceed RFC 7208 limit"""
    buf = io.StringIO()
    email_data = {
        "SPF": {
            "record": "v=spf1 ...",
            "qualifier": "-all",
            "dns_lookups": 15,          # exceeds limit of 10
            "void_lookups": 0,
            "duplicate_records": False,
            "errors": [],
        },
        "DMARC": None,
        "DKIM": [],
        "BIMI": None,
    }
    _write_email_security_section(buf, email_data)
    assert "EXCEEDS" in buf.getvalue()


# ============================================================================
# HTTP/HTTPS SECTION
# ============================================================================

def test_http_section_renders_both_schemes():
    """Both HTTP and HTTPS results should be written to the report"""
    buf = io.StringIO()
    http_data = {
        "http": {"status_code": 301, "server": "nginx", "final_url": "https://example.com/"},
        "https": {"status_code": 200, "server": "nginx", "final_url": "https://example.com/"},
    }
    _write_http_section(buf, http_data)
    output = buf.getvalue()
    assert "HTTP" in output
    assert "HTTPS" in output
    assert "nginx" in output


def test_http_section_skipped_when_empty():
    """Empty http_data should produce the skipped message"""
    buf = io.StringIO()
    _write_http_section(buf, {})
    assert "skipped" in buf.getvalue().lower() or "no results" in buf.getvalue().lower()
