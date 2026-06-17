# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- Subdomain enumeration (wordlist plus certificate transparency log lookups)
- SSL/TLS certificate inspection (expiry, issuer, SANs, cipher info)
- JSON report export option

## [0.3.1] - 2026-06-12

### Added

- Ruff linter configuration in `pyproject.toml` with sensible default rule set (pycodestyle, pyflakes, isort, pyupgrade, bugbear, simplify). Install with `pip install -e .[dev]` and run with `ruff check .`.
- GitHub Actions CI workflow at `.github/workflows/test.yml` running ruff and pytest on push and pull request, across Python 3.10, 3.11, 3.12, and 3.13.
- CI status badge in README.

### Changed

- Consolidated five separate `whoisit.errors` exception handlers in `registration.py` into a single base-class catch on `WhoisItError`. The specific error class surfaces in the printed message via `type(e).__name__`. Net effect: 15 lines reduced to 3, behavior identical.
- Replaced the manual deduplication loop in `utils._print_fields` with the `dict.fromkeys()` idiom. Net effect: 7 lines reduced to 2, behavior identical.
- Compacted argparse argument definitions in `cli.py` from multi-line blocks to one-liners where they fit. Net effect: 20 lines reduced to 5.
- Routed dependency check errors and domain validation errors to `stderr` instead of `stdout`. Users piping normal output to a file now still see error messages on screen.
- Auto-fixed import ordering across all modules per ruff's isort ruleset.
- Removed `f` prefix from f-strings that contained no placeholders (8 instances flagged by ruff).
- Combined two adjacent `elif` branches in `_parse_spf` using `or` per ruff's simplify ruleset.

### Notes

- No functional changes to scan output, CLI flags, return-value dict shapes, or cache file locations. All 67 unit tests pass.

## [0.3.0] - 2026-06-11

### Added

- `pyproject.toml` using PEP 621 for project metadata, runtime dependencies, dev extras, and build configuration. The project is now pip-installable.
- Console script entry point `osint-recon` registered at install time. After `pip install -e .` the tool runs as `osint-recon example.com` from anywhere on PATH inside the venv.
- Pytest test suite under `tests/` covering the pure-logic helpers: domain validation, SPF parsing, DMARC parsing, service-token classification, datetime formatting, and report section writing. 67 tests total, all pass in under a second, no network access required.
- Development dependencies (`pytest`) declared as an optional extra. Install with `pip install -e .[dev]`.
- Package version metadata sourced from `importlib.metadata.version()` rather than hardcoded in code, giving a single source of truth in `pyproject.toml`.

### Changed

- Refactored from a single 1083-line script into a proper Python package under `src/osint_recon/`. New module layout: `validation.py`, `registration.py`, `dns_enum.py`, `email_security.py`, `http_probe.py`, `reporting.py`, plus shared `constants.py`, `utils.py`, and `cli.py`.
- Source layout follows the Python Packaging User Guide recommendation (`src/` directory) which prevents accidental imports of the development copy.
- README updated with new installation, usage, and testing instructions reflecting the package structure.

### Removed

- Old monolithic `osint_recon.py` at the repository root. All functionality is preserved in the new module structure.

### Notes

- No functional changes to scan output, CLI flags, return-value dict shapes, or cache file locations. Parity with v0.2.1 verified via dedicated unit tests during development.

## [0.2.1] - 2026-05-31

### Changed

- Reorganized file structure for readability. All constants moved into a single block near the top of the file. Functions reordered to match runtime execution order.
- Added section-divider banner comments (e.g. `# === STAGE 3: DNS ENUMERATION ===`) marking the 11 major regions of the file.
- Decomposed `get_email_security` into a thin coordinator plus four focused helpers (`_audit_spf`, `_audit_dmarc`, `_audit_dkim`, `_audit_bimi`).
- Decomposed `save_report` into a thin coordinator plus seven section-writer helpers.
- Added type hints to every function signature for both public and helper functions.
- Extracted magic numbers (DNS timeout, HTTP timeout, RFC 7208 SPF lookup limits) into named module-level constants.
- Improved inline comments in the dense logic sections: the domain validation regex now has line-by-line explanations, the recursive SPF resolver explains its decision points, and the DKIM detection logic documents why its version check is intentionally loose per RFC 6376.

### Fixed

- No functional fixes. This release is a structural refactor with no behavior changes. All outputs, CLI flags, dict shapes, and cache file locations are identical to v0.2.0.

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

[Unreleased]: https://github.com/Jorgy762/osint-domain-recon/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/Jorgy762/osint-domain-recon/releases/tag/v0.3.1
[0.3.0]: https://github.com/Jorgy762/osint-domain-recon/releases/tag/v0.3.0
[0.2.1]: https://github.com/Jorgy762/osint-domain-recon/releases/tag/v0.2.1
[0.2.0]: https://github.com/Jorgy762/osint-domain-recon/releases/tag/v0.2.0
[0.1.0]: https://github.com/Jorgy762/osint-domain-recon/commits/main
