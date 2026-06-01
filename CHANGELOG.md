# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- Subdomain enumeration (wordlist plus certificate transparency log lookups)
- SSL/TLS certificate inspection (expiry, issuer, SANs, cipher info)
- JSON report export option
- Refactor single-file script into proper module structure

## [0.2.0] - 2026-05-31

### Added

- RDAP (Registration Data Access Protocol) as the primary source for domain registration data, replacing legacy WHOIS text parsing as the default path. Provides structured JSON responses defined in RFC 7480 through 7484.
- WHOIS retained as automatic fallback for TLDs without RDAP service support.
- Email authentication audit stage covering SPF, DMARC, DKIM, and BIMI.
- SPF parser with recursive DNS-lookup counting against the RFC 7208 limit of 10 lookups per evaluation.
- SPF void-lookup tracking against the RFC 7208 limit of 2 void lookups.
- SPF qualifier classification flagging `+all` misconfigurations.
- DMARC tag parser with explicit flagging of `p=none` (reporting-only) policies.
- DKIM probing across 29 common selectors covering Microsoft 365, Google Workspace, Mailchimp, SendGrid, ProtonMail, Zoho, Mandrill, Mailgun, AWS SES, Postmark, SparkPost, HubSpot, and generic self-hosted setups.
- BIMI lookup at `default._bimi.{domain}`.
- Service-verification token classification across 30+ SaaS providers (Microsoft 365, Google Workspace, Meta, Atlassian, Adobe, DocuSign, Stripe, MongoDB Atlas, GlobalSign, Cisco, Webex, Cloudflare, Notion, Loom, Zoom, Intercom, AWS SES, Pinterest, Dropbox, and more).
- Domain input validation with regex-based normalization (strips schemes, paths, trailing dots; rejects malformed input cleanly).
- RDAP bootstrap data cached to disk at `~/.cache/osint-domain-recon/` with 7-day refresh window.
- `--no-email-security` CLI flag to skip the email authentication audit.

### Changed

- Registration data output now includes a `Source` field indicating whether the lookup returned RDAP or WHOIS data.
- Datetime values trimmed to second precision in all output (microseconds removed).
- Pretty-printer deduplicates list values and trims long lists to five entries.

### Removed

- MTA-STS lookup. Added and then removed within development before public release after considering deployment complexity versus value. May return in a future release if paired with proper policy-file validation.

## [0.1.0] - 2026-05-18

Initial public release.

### Added

- IP address resolution via DNS lookup.
- WHOIS data retrieval via `python-whois` (registrar, creation/expiry dates, name servers, country, DNSSEC).
- DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA).
- HTTP/HTTPS status probing with redirect chain tracking.
- Optional plaintext report export with `-o` flag.
- `--no-http` flag to skip HTTP/HTTPS probing.

[Unreleased]: https://github.com/Jorgy762/osint-domain-recon/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Jorgy762/osint-domain-recon/releases/tag/v0.2.0
[0.1.0]: https://github.com/Jorgy762/osint-domain-recon/commits/main
