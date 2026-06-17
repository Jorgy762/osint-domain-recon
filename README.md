# OSINT Domain Recon Tool

[![Tests](https://github.com/Jorgy762/osint-domain-recon/actions/workflows/test.yml/badge.svg)](https://github.com/Jorgy762/osint-domain-recon/actions/workflows/test.yml)

A Python-based command-line tool for automated domain reconnaissance. Given a target domain, it pulls registration data via RDAP, enumerates DNS records, classifies SaaS service-verification tokens, audits email authentication (SPF, DMARC, DKIM, BIMI), and probes HTTP/HTTPS availability. All in one run, with an optional plaintext report export.

Built as a learning project to bridge IT/sysadmin knowledge with practical cybersecurity tooling.

---

## Features

- IP address resolution via DNS lookup
- Registration data via RDAP (with legacy WHOIS fallback for TLDs that do not yet run RDAP servers)
- DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA)
- Service-verification token classification across 30+ SaaS providers (Microsoft 365, Google Workspace, Meta, Atlassian, Adobe, DocuSign, Stripe, AWS SES, and more)
- Email authentication audit:
  - SPF parsing with recursive DNS-lookup counting against the RFC 7208 limit of 10
  - SPF void-lookup tracking against the RFC 7208 limit of 2
  - DMARC tag parsing with policy enforcement flagging
  - DKIM probing at 29 common selectors with explicit limitations disclosure
  - BIMI lookup
- HTTP/HTTPS status probing (status code, server header, redirect tracking)
- Domain input validation (rejects malformed input cleanly)
- RDAP bootstrap data cached on disk for 7 days to avoid repeated IANA round-trips
- Optional plaintext report export with `-o`

---

## Requirements

- Python 3.10 or higher
- Runtime dependencies (installed automatically via `pip install -e .`):
  - `whoisit` (RDAP)
  - `python-whois` (legacy WHOIS fallback)
  - `dnspython` (DNS resolution)
  - `requests` (HTTP probing)

---

## Installation

Clone the repository and install in editable mode:

```bash
git clone https://github.com/Jorgy762/osint-domain-recon.git
cd osint-domain-recon
python -m venv .venv
source .venv/Scripts/activate          # Linux/macOS: source .venv/bin/activate
pip install -e .
```

The `-e` flag (editable install) means changes to the source files take effect immediately without reinstalling. After installation, the `osint-recon` command is available on your PATH inside the activated venv.

To also install development dependencies (pytest, used to run the test suite):

```bash
pip install -e .[dev]
```

---

## Testing

The test suite covers the pure-logic helpers: domain validation, SPF parsing, DMARC parsing, service-token classification, datetime formatting, and report section writing. Tests do not require network access and complete in under a second.

To run the tests, install development dependencies and invoke pytest:

```bash
pip install -e .[dev]
pytest
```

Expected output (timing varies by machine, typically well under one second):

```
============================== 67 passed ==============================
```

---

## Development

The project uses [ruff](https://docs.astral.sh/ruff/) for linting and import sorting. Configuration lives in `pyproject.toml` under `[tool.ruff]`.

Run the linter:

```bash
ruff check .
```

Auto-fix issues where possible:

```bash
ruff check --fix .
```

GitHub Actions runs both ruff and pytest on every push to `main` and every pull request, against Python 3.10, 3.11, 3.12, and 3.13. Workflow definition lives at `.github/workflows/test.yml`. The status badge at the top of this README reflects the most recent CI run.

---

## Usage

The tool can be invoked two ways. Both produce identical output.

### As a console command (recommended)

```bash
osint-recon example.com
osint-recon example.com -o report.txt
osint-recon example.com --no-http
osint-recon example.com --no-email-security
```

### As a Python module

```bash
python -m osint_recon example.com
python -m osint_recon example.com -o report.txt
```

### Flags

| Flag | Purpose |
|------|---------|
| `-o FILE`, `--output FILE` | Save report to a plaintext file |
| `--no-http` | Skip HTTP/HTTPS probing |
| `--no-email-security` | Skip email-authentication audit (SPF/DMARC/DKIM/BIMI) |

---

## Example Output

```
+==============================================+
|          OSINT Domain Recon Tool             |
|          github.com/Jorgy762                 |
|          For authorized use only             |
+==============================================+

[*] Target : example.com
[*] Started: 2026-05-31 22:53:29

[*] Resolving IP Address...
    [+] IP Address : 93.184.216.34

[*] Looking up registration data (RDAP)...
    [+] Source: RDAP
    [+] Registrar: ICANN
    [+] Creation Date: 1995-08-14 04:00:00
    [+] Expiration Date: 2025-08-13 04:00:00
    [+] Name Servers: a.iana-servers.net, b.iana-servers.net
    [+] DNSSEC: signedDelegation

[*] Enumerating DNS Records...
    [+] A Records:
          - 93.184.216.34
    [+] MX Records:
          - 0 .
    [+] NS Records:
          - a.iana-servers.net.
          - b.iana-servers.net.
    [+] TXT Records:
          - "v=spf1 -all"

[*] Service Verifications (TXT-token fingerprints):
    [+] Microsoft 365 / Azure AD tenant         (token: ms)

[*] Auditing Email Security...
    [+] SPF: v=spf1 -all
          Policy on `all`     : -all (HARD FAIL, recommended)
          DNS lookups (chain) : 0 / 10 (RFC 7208 limit)
          Void lookups        : 0 / 2 (RFC 7208 limit)
    [+] DMARC: v=DMARC1; p=reject; pct=100; rua=mailto:reports@example.com
          Policy              : p=reject
    [*] Probing 29 common DKIM selectors...
    [+] DKIM selector 'selector1' found: v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0...
    [-] No BIMI record at default._bimi.example.com

[*] Checking HTTP/HTTPS Status...
    [+] HTTP   Status: 200 | Server: ECS | Final URL: https://www.example.com/

[*] Scan complete: 2026-05-31 22:53:33
[*] Remember: only run this tool against domains you own or have permission to test.
```

---

## Project Structure

```
osint-domain-recon/
├── .github/
│   └── workflows/
│       └── test.yml              # GitHub Actions CI (ruff + pytest)
├── src/
│   └── osint_recon/
│       ├── __init__.py           # Package metadata, version lookup
│       ├── __main__.py           # Entry point for python -m osint_recon
│       ├── cli.py                # Argparse, dependency check, main coordinator
│       ├── constants.py          # Regex, lookup tables, RFC 7208 limits
│       ├── utils.py              # Display helpers (_format_value, _print_fields)
│       ├── validation.py         # Domain input validation, startup banner
│       ├── registration.py       # RDAP lookup with WHOIS fallback
│       ├── dns_enum.py           # IP resolution, DNS records, service token classifier
│       ├── email_security.py     # SPF, DMARC, DKIM, BIMI auditors
│       ├── http_probe.py         # HTTP/HTTPS availability checks
│       └── reporting.py          # Plaintext report writer
├── tests/                        # Pytest test suite (67 tests, no network required)
├── pyproject.toml                # Package definition (PEP 621) + ruff config
├── CHANGELOG.md                  # Version history (Keep a Changelog format)
├── README.md                     # This file
├── .gitattributes                # Line ending policy
└── .gitignore
```

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

---

## Design Principles

- **Authorized use only.** The tool and all documentation make this explicit.
- **Graceful error handling.** Every network call is wrapped in try/except with meaningful output.
- **Honest about limitations.** The DKIM probe makes clear that "not found" means "not found at common selectors," not "DKIM does not exist." Any tool that pretends to ground truth it cannot deliver is worse than one that admits its limits.
- **CLI-first.** No GUI, no web interface. Stays a clean command-line tool.
- **Heavily commented.** Code should be readable by someone learning Python, not just by experienced developers.
- **Modular structure.** Each scan stage lives in its own module so the tool is testable and maintainable as it grows.

---

## Roadmap

Potential future additions:

- [ ] Subdomain enumeration (wordlist plus certificate transparency log lookups)
- [ ] SSL/TLS certificate inspection (expiry, issuer, SANs, cipher info)
- [ ] Shodan API integration for open port data
- [ ] JSON report export option
- [ ] Banner grabbing

---

## Disclaimer

This tool is intended for educational purposes and authorized reconnaissance only. Only run it against domains you own or have explicit written permission to test. Unauthorized use may violate applicable laws including the Canadian Criminal Code (Section 342.1) and equivalent legislation in other jurisdictions.

---

## Author

**Jorgy762** | [GitHub](https://github.com/Jorgy762)

Certifications: ISC2 Certified in Cybersecurity | Certified Zero Trust Practitioner | Certified Threat & Malware Analysis | Fortinet Certified Associate in Cybersecurity | OSINT Certificate (WithYouWithMe) | CSA Trusted AI Safety Expert | Microsoft AZ-900 Azure Fundamentals | Unit Information Systems Security Officer (CAF)
