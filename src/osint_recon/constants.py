"""
Module-level constants for the OSINT Domain Recon tool.

This file is the single source of truth for:
  - The domain validation regex
  - Cache file locations and refresh windows
  - DNS and HTTP timeout values
  - RFC 7208 SPF evaluation limits
  - The DKIM selector probe list
  - The SaaS service-verification token classification map

Constants live here so that updates (a new DKIM selector to add, a
new SaaS token to recognize, a different timeout) require touching
exactly one file.
"""

import re
from pathlib import Path

# ----------------------------------------------------------------------------
# DOMAIN VALIDATION
# ----------------------------------------------------------------------------

# Domain validation regex.
#
# Rules encoded here (per RFC 1035 and RFC 1123):
#   - Total length: 1 to 253 characters (positive lookahead at start).
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

# ----------------------------------------------------------------------------
# RDAP BOOTSTRAP CACHE
# ----------------------------------------------------------------------------

# Cache the RDAP bootstrap data on disk. IANA refreshes the registry roughly
# weekly, so a 7-day cache window avoids a network round-trip on every run
# without serving stale data.
CACHE_DIR: Path = Path.home() / ".cache" / "osint-domain-recon"
CACHE_FILE: Path = CACHE_DIR / "rdap_bootstrap.json"
CACHE_DAYS: int = 7

# ----------------------------------------------------------------------------
# NETWORK TIMEOUTS
# ----------------------------------------------------------------------------

# DNS resolver timeout for the email-security audit. Tight enough to keep the
# 29-selector DKIM probe from dominating scan time, loose enough to tolerate
# slow authoritative servers.
DNS_TIMEOUT_SECONDS: float = 2.0

# HTTP request timeout for the availability probe.
HTTP_TIMEOUT_SECONDS: int = 5

# ----------------------------------------------------------------------------
# SPF EVALUATION LIMITS (RFC 7208)
# ----------------------------------------------------------------------------

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

# ----------------------------------------------------------------------------
# DKIM SELECTOR PROBE LIST
# ----------------------------------------------------------------------------

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

# ----------------------------------------------------------------------------
# SERVICE VERIFICATION TOKEN MAP
# ----------------------------------------------------------------------------

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
