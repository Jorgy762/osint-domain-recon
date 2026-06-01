# OSINT Domain Recon Tool

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
- The following third-party libraries:

```
pip install whoisit python-whois dnspython requests
```

The `whoisit` library handles RDAP queries. `python-whois` remains in the dependency list as a fallback for legacy WHOIS lookups on TLDs without RDAP support.

---

## Usage

### Basic scan (output to terminal only)

```
python osint_recon.py example.com
```

### Save report to a file

```
python osint_recon.py example.com -o report.txt
```

### Skip HTTP/HTTPS probing

```
python osint_recon.py example.com --no-http
```

### Skip email authentication audit

```
python osint_recon.py example.com --no-email-security
```

### Combine flags

```
python osint_recon.py example.com --no-http --no-email-security -o report.txt
```

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
├── osint_recon.py     # Main script
├── CHANGELOG.md       # Version history
├── .gitignore
└── README.md          # This file
```

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

---

## Design Principles

- **Authorized use only.** The tool and all documentation make this explicit.
- **Graceful error handling.** Every network call is wrapped in try/except with meaningful output.
- **Honest about limitations.** The DKIM probe makes clear that "not found" means "not found at common selectors," not "DKIM does not exist." Any tool that pretends to ground truth it cannot deliver is worse than one that admits its limits.
- **CLI-first.** No GUI, no web interface. Stays a clean command-line tool.
- **Heavily commented.** Code should be readable by someone learning Python, not just by experienced developers.

---

## Roadmap

Potential future additions:

- [ ] Subdomain enumeration (wordlist plus certificate transparency log lookups)
- [ ] SSL/TLS certificate inspection (expiry, issuer, SANs, cipher info)
- [ ] Shodan API integration for open port data
- [ ] JSON report export option
- [ ] Banner grabbing
- [ ] Refactor single-file script into proper module structure

---

## Disclaimer

This tool is intended for educational purposes and authorized reconnaissance only. Only run it against domains you own or have explicit written permission to test. Unauthorized use may violate applicable laws including the Canadian Criminal Code (Section 342.1) and equivalent legislation in other jurisdictions.

---

## Author

**Jorgy762** | [GitHub](https://github.com/Jorgy762)

Certifications: ISC2 Certified in Cybersecurity | Certified Zero Trust Practitioner | Certified Threat & Malware Analysis | Fortinet Certified Associate in Cybersecurity | OSINT Certificate (WithYouWithMe) | CSA Trusted AI Safety Expert | Microsoft AZ-900 Azure Fundamentals
