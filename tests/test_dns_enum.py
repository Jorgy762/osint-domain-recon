"""
Tests for osint_recon.dns_enum.

Covers _classify_service_tokens (the SaaS verification token classifier).
The network-dependent functions (resolve_ip and get_dns_records) would
need DNS mocking to test properly and belong in an integration test
suite, not a unit test suite.
"""

from osint_recon.dns_enum import _classify_service_tokens

# ============================================================================
# POSITIVE CASES: known service tokens should be classified
# ============================================================================

def test_classifies_microsoft_365_token():
    """MS= prefix should map to Microsoft 365 / Azure AD"""
    findings = _classify_service_tokens(['"MS=ms123456789"'])
    assert len(findings) == 1
    prefix, service, _ = findings[0]
    assert "Microsoft" in service
    assert prefix == "ms"


def test_classifies_google_workspace_token():
    """google-site-verification= should map to Google"""
    findings = _classify_service_tokens(['"google-site-verification=abc123"'])
    assert len(findings) == 1
    _, service, _ = findings[0]
    assert "Google" in service


def test_classifies_meta_token():
    """facebook-domain-verification= should map to Meta"""
    findings = _classify_service_tokens(['"facebook-domain-verification=qwerty"'])
    _, service, _ = findings[0]
    assert "Meta" in service


def test_classifies_docusign_token():
    """docusign= should map to DocuSign"""
    findings = _classify_service_tokens(['"docusign=12345-abcde"'])
    _, service, _ = findings[0]
    assert service == "DocuSign"


def test_classifies_multiple_services_in_one_pass():
    """Multiple distinct tokens should all be detected"""
    records = [
        '"MS=ms123"',
        '"google-site-verification=abc"',
        '"docusign=token1"',
        '"stripe-verification=tok2"',
    ]
    findings = _classify_service_tokens(records)
    assert len(findings) == 4


# ============================================================================
# EXCLUSION CASES: email-auth records belong to other scan stages
# ============================================================================

def test_excludes_spf_records():
    """SPF records should be skipped (handled by email-security stage)"""
    findings = _classify_service_tokens(['"v=spf1 include:_spf.example.com -all"'])
    assert findings == []


def test_excludes_dmarc_records():
    """DMARC records should be skipped"""
    findings = _classify_service_tokens(['"v=DMARC1; p=reject"'])
    assert findings == []


def test_excludes_dkim_records():
    """DKIM records should be skipped"""
    findings = _classify_service_tokens(['"v=DKIM1; k=rsa; p=base64..."'])
    assert findings == []


def test_excludes_bimi_records():
    """BIMI records should be skipped"""
    findings = _classify_service_tokens(['"v=BIMI1; l=https://example.com/logo.svg"'])
    assert findings == []


# ============================================================================
# NEGATIVE CASES: unknown tokens, edge cases, empty inputs
# ============================================================================

def test_skips_unknown_tokens():
    """Tokens not in SERVICE_TOKEN_MAP should be silently skipped"""
    findings = _classify_service_tokens(['"random-unknown-token=value"'])
    assert findings == []


def test_strips_surrounding_quotes():
    """Records wrapped in quotes should still match"""
    findings = _classify_service_tokens(['"MS=ms123"'])
    assert len(findings) == 1


def test_case_insensitive_prefix_matching():
    """Token prefix matching should be case-insensitive"""
    findings = _classify_service_tokens(['"MS=ms123"'])
    assert len(findings) == 1


def test_empty_input_returns_empty_list():
    """Empty record list should produce empty findings"""
    assert _classify_service_tokens([]) == []


def test_mixed_known_and_unknown():
    """Mix of known and unknown tokens: only known should be returned"""
    records = [
        '"MS=ms123"',
        '"unknown=value"',
        '"docusign=t"',
        '"alsounknown=zzz"',
    ]
    findings = _classify_service_tokens(records)
    assert len(findings) == 2
