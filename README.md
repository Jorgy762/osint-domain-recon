# OSINT Domain Recon Tool

A Python-based command-line tool for automated domain reconnaissance. Given a target domain, it pulls WHOIS registration data, enumerates DNS records, resolves IP addresses, and probes HTTP/HTTPS availability -- all in one run, with an optional report export.

Built as a learning project to bridge IT/sysadmin knowledge with practical cybersecurity tooling.

---

## Features

- IP address resolution via DNS lookup
- WHOIS data (registrar, creation/expiry dates, name servers, registrant country, DNSSEC)
- DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA)
- HTTP/HTTPS status probing (status code, server header, redirect tracking)
- Optional plaintext report export with `-o`

---

## Requirements

- Python 3.8 or higher
- The following third-party libraries:

```bash
pip install python-whois dnspython requests
```

---

## Usage

### Basic scan (output to terminal only)

```bash
python osint_recon.py example.com
```

### Save report to a file

```bash
python osint_recon.py example.com -o report.txt
```

### Skip HTTP/HTTPS probing

```bash
python osint_recon.py example.com --no-http
```

### Combine flags

```bash
python osint_recon.py example.com --no-http -o report.txt
```

---

## Example Output

```
╔══════════════════════════════════════════════╗
║          OSINT Domain Recon Tool             ║
║          github.com/Jorgy762                 ║
║          For authorized use only             ║
╚══════════════════════════════════════════════╝

[*] Target : example.com
[*] Started: 2026-05-17 10:30:00

[*] Resolving IP Address...
    [+] IP Address : 93.184.216.34

[*] Running WHOIS Lookup...
    [+] Registrar: ICANN
    [+] Creation Date: 1995-08-14 04:00:00
    [+] Expiration Date: 2025-08-13 04:00:00
    [+] Name Servers: A.IANA-SERVERS.NET, B.IANA-SERVERS.NET

[*] Enumerating DNS Records...
    [+] A Records:
          - 93.184.216.34
    [+] MX Records:
          - 0 .
    [+] NS Records:
          - a.iana-servers.net.
          - b.iana-servers.net.

[*] Checking HTTP/HTTPS Status...
    [+] HTTP   Status: 200 | Server: ECS | Final URL: https://www.example.com/
    [+] HTTPS  Status: 200 | Server: ECS | Final URL: https://www.example.com/

[*] Scan complete: 2026-05-17 10:30:05
[*] Remember: only run this tool against domains you own or have permission to test.
```

---

## Project Structure

```
osint-domain-recon/
├── osint_recon.py     # Main script
└── README.md          # This file
```

---

## Roadmap

Potential future additions:

- [ ] Subdomain enumeration
- [ ] Shodan API integration for open port data
- [ ] SSL/TLS certificate inspection
- [ ] JSON report export option
- [ ] Banner grabbing

---

## Disclaimer

This tool is intended for educational purposes and authorized reconnaissance only. Only run it against domains you own or have explicit written permission to test. Unauthorized use may violate applicable laws including the Canadian Criminal Code (Section 342.1) and equivalent legislation in other jurisdictions.

---

## Author

**Jorgy762** | [GitHub](https://github.com/Jorgy762)

Certifications: ISC2 Certified in Cybersecurity | Certified Zero Trust Practitioner | Certified Threat & Malware Analysis | Fortinet Certified Associate in Cybersecurity | OSINT Certificate (WithYouWithMe)
