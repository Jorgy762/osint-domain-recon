"""
Tests for osint_recon.validation.

Covers validate_domain across normalization (scheme stripping, lowercasing,
path stripping, dot stripping) and rejection of malformed inputs.
"""

import pytest
from osint_recon.validation import validate_domain


# ============================================================================
# NORMALIZATION TESTS
# These verify that valid-but-decorated inputs are cleaned up correctly.
# ============================================================================

def test_strips_https_scheme():
    """validate_domain should remove the https:// prefix"""
    assert validate_domain("https://example.com") == "example.com"


def test_strips_http_scheme():
    """validate_domain should remove the http:// prefix"""
    assert validate_domain("http://example.com") == "example.com"


def test_lowercases_input():
    """validate_domain should normalize to lowercase"""
    assert validate_domain("EXAMPLE.COM") == "example.com"


def test_strips_path_component():
    """validate_domain should remove URL path components"""
    assert validate_domain("https://example.com/some/path") == "example.com"


def test_strips_trailing_dot():
    """validate_domain should strip the FQDN trailing dot"""
    assert validate_domain("example.com.") == "example.com"


def test_combined_normalization():
    """All normalizations should apply together in a single pass"""
    assert validate_domain("HTTPS://Example.COM/path") == "example.com"


# ============================================================================
# ACCEPTANCE TESTS
# These verify that legitimate domains pass validation.
# ============================================================================

def test_accepts_multiple_subdomains():
    """Deep subdomain chains should pass validation"""
    assert validate_domain("a.b.c.d.example.co.uk") == "a.b.c.d.example.co.uk"


def test_accepts_hyphens_inside_labels():
    """Hyphens within (not at boundaries of) labels are valid"""
    assert validate_domain("my-domain.example.com") == "my-domain.example.com"


def test_accepts_numeric_labels():
    """Labels containing digits are valid"""
    assert validate_domain("test123.example.com") == "test123.example.com"


# ============================================================================
# REJECTION TESTS
# These verify that malformed input causes a clean exit with status 1
# rather than a Python traceback or silent acceptance.
# ============================================================================

@pytest.mark.parametrize("bad_input", [
    "-bad.com",         # leading hyphen on label
    "bad-.com",         # trailing hyphen on label
    "bad_domain.com",   # underscore not allowed in DNS labels
    "justaword",        # no TLD
    "example.c",        # TLD too short (needs 2+ chars)
    "",                 # empty string
])
def test_rejects_malformed_input(bad_input):
    """Malformed domains should exit the program with status 1"""
    with pytest.raises(SystemExit):
        validate_domain(bad_input)
