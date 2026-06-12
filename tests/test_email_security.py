"""
Tests for osint_recon.email_security.

Covers SPF parsing (_parse_spf), DMARC parsing (_parse_dmarc), and the
network-free paths of SPF lookup counting (_count_spf_lookups). Tests
that would require live DNS resolution are excluded; they would belong
in an integration test suite, not a unit test suite.
"""

from osint_recon.email_security import (
    _parse_spf,
    _parse_dmarc,
    _count_spf_lookups,
)


# ============================================================================
# _parse_spf TESTS
# ============================================================================

def test_spf_hard_fail_flagged_recommended():
    """Hard-fail SPF (-all) should be flagged as the recommended policy"""
    qualifier, _ = _parse_spf("v=spf1 include:_spf.google.com -all")
    assert "-all" in qualifier
    assert "HARD FAIL" in qualifier
    assert "recommended" in qualifier


def test_spf_soft_fail_flagged_quarantine():
    """Soft-fail SPF (~all) should be flagged as quarantine"""
    qualifier, _ = _parse_spf("v=spf1 ip4:192.0.2.1 ~all")
    assert "~all" in qualifier
    assert "SOFT FAIL" in qualifier


def test_spf_neutral_flagged_no_policy():
    """Neutral SPF (?all) should be flagged as having no enforcement"""
    qualifier, _ = _parse_spf("v=spf1 ?all")
    assert "?all" in qualifier
    assert "NEUTRAL" in qualifier


def test_spf_plus_all_flagged_misconfiguration():
    """+all is a misconfiguration that allows anyone to send"""
    qualifier, _ = _parse_spf("v=spf1 +all")
    assert "+all" in qualifier
    assert "MISCONFIGURATION" in qualifier


def test_spf_no_all_mechanism_defaults_neutral():
    """SPF without an explicit all should default to neutral (?)"""
    qualifier, _ = _parse_spf("v=spf1 ip4:192.0.2.1")
    assert qualifier == "?"


def test_spf_extracts_include_senders():
    """Include mechanisms should be collected into the sender list"""
    _, senders = _parse_spf("v=spf1 include:_spf.google.com -all")
    assert "include:_spf.google.com" in senders


def test_spf_extracts_ip_senders():
    """IP-based mechanisms should be collected into the sender list"""
    _, senders = _parse_spf("v=spf1 ip4:10.0.0.0/8 ip6:2001:db8::/32 -all")
    assert "ip4:10.0.0.0/8" in senders
    assert "ip6:2001:db8::/32" in senders


def test_spf_extracts_bare_a_mx():
    """Bare a and mx mechanisms (no colon) should be in the sender list"""
    _, senders = _parse_spf("v=spf1 a mx -all")
    assert "a" in senders
    assert "mx" in senders


# ============================================================================
# _parse_dmarc TESTS
# ============================================================================

def test_dmarc_full_record_extracts_all_tags():
    """DMARC parser should extract every standard tag from a complete record"""
    record = "v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:a@example.com"
    tags = _parse_dmarc(record)
    assert tags == {
        "v": "DMARC1",
        "p": "reject",
        "sp": "quarantine",
        "pct": "100",
        "rua": "mailto:a@example.com",
    }


def test_dmarc_minimal_record():
    """A minimal DMARC record with just policy should parse correctly"""
    tags = _parse_dmarc("v=DMARC1; p=none")
    assert tags["p"] == "none"


def test_dmarc_lowercases_keys():
    """Tag keys should be normalized to lowercase"""
    tags = _parse_dmarc("v=DMARC1; P=reject; PCT=50")
    assert "p" in tags
    assert "pct" in tags
    assert tags["p"] == "reject"


def test_dmarc_whitespace_tolerant():
    """Whitespace around tags and values should not affect parsing"""
    tags = _parse_dmarc("v=DMARC1 ;  p=reject  ;  pct=100")
    assert tags["p"] == "reject"
    assert tags["pct"] == "100"


def test_dmarc_no_semicolon_terminator():
    """Records without a trailing semicolon should still parse"""
    tags = _parse_dmarc("v=DMARC1; p=quarantine")
    assert tags["p"] == "quarantine"


# ============================================================================
# _count_spf_lookups TESTS (network-free paths only)
# ============================================================================

def test_spf_count_zero_for_ip_only_record():
    """ip4, ip6, and all mechanisms do not trigger DNS lookups"""
    lookups, voids, errs = _count_spf_lookups("v=spf1 ip4:10.0.0.0/8 ip6:2001::/32 -all")
    assert lookups == 0
    assert voids == 0
    assert errs == []


def test_spf_count_zero_for_empty_record():
    """An SPF record with only the version prefix produces zero lookups"""
    lookups, voids, _ = _count_spf_lookups("v=spf1")
    assert lookups == 0
    assert voids == 0


def test_spf_count_recursion_depth_guard():
    """Hitting max recursion returns an error instead of looping forever"""
    # Call with depth already at the max to immediately trigger the guard.
    lookups, voids, errs = _count_spf_lookups("v=spf1 -all", depth=100, max_depth=10)
    assert errs == ["max recursion depth 10 reached"]
    assert lookups == 0
    assert voids == 0
