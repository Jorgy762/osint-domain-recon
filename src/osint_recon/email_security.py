"""
Email authentication audit: SPF, DMARC, DKIM, and BIMI.

The audit is independent of the general DNS enumeration so that mail
security can be reasoned about as a single view. Each protocol has
its own auditor function (_audit_spf, _audit_dmarc, _audit_dkim,
_audit_bimi) called by the get_email_security coordinator.

The SPF auditor includes recursive DNS-lookup counting against the
RFC 7208 limit of 10, which catches the most common SPF
misconfiguration: nested includes that blow past the limit and cause
permerrors.
"""

from typing import Any

import dns.exception
import dns.resolver

from .constants import (
    COMMON_DKIM_SELECTORS,
    DNS_TIMEOUT_SECONDS,
    SPF_LOOKUP_MECHANISMS,
    SPF_MAX_DNS_LOOKUPS,
    SPF_MAX_RECURSION_DEPTH,
    SPF_MAX_VOID_LOOKUPS,
)


def _resolve_txt(name: str, timeout: float = DNS_TIMEOUT_SECONDS) -> list[str]:
    """
    Resolve TXT records for a name with a tight timeout.

    Returns a list of joined strings (TXT records can have multiple
    chunks per RFC 1035, which dnspython exposes as a list of byte
    strings). Returns an empty list on any failure: NXDOMAIN, NoAnswer,
    timeout, or any other DNS exception. Email-security checks are
    best-effort and a single failed lookup should not crash the scan.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(name, "TXT")
        records: list[str] = []
        for r in answers:
            # Each TXT record is a list of byte strings. Decode each chunk
            # and join them into a single string.
            chunks = [s.decode("utf-8", errors="replace") for s in r.strings]
            records.append("".join(chunks))
        return records
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.Timeout, dns.exception.DNSException):
        return []


def _count_spf_lookups(
    record_text: str,
    depth: int = 0,
    max_depth: int = SPF_MAX_RECURSION_DEPTH,
    visited: set[str] | None = None,
) -> tuple[int, int, list[str]]:
    """
    Recursively count the DNS lookups required to evaluate an SPF record.

    Returns (lookup_count, void_lookup_count, errors).

    Per RFC 7208 Section 4.6.4, an SPF check may not exceed 10 DNS lookups
    total. Void lookups (queries that return NXDOMAIN or empty answers)
    are capped separately at 2.

    The recursion handles "include" and "redirect" mechanisms by fetching
    the referenced SPF record and counting its lookups too. Recursion is
    bounded by max_depth as a safety guard against malicious or
    pathological include chains, and the visited set prevents infinite
    loops if a record incorrectly includes itself transitively.
    """
    if visited is None:
        visited = set()
    if depth >= max_depth:
        return (0, 0, [f"max recursion depth {max_depth} reached"])

    lookups = 0
    void_lookups = 0
    errors: list[str] = []

    # SPF records are space-separated mechanism tokens after the "v=spf1"
    # version prefix. Strip the prefix and walk the rest.
    tokens = record_text.replace("v=spf1", "").strip().split()

    for token in tokens:
        # Strip qualifier prefix (+ - ~ ?) if present. Qualifiers affect
        # pass/fail semantics but do not change DNS lookup behavior.
        bare = token.lstrip("+-~?")

        # Mechanisms come in three forms:
        #   "include:value"  (colon-separated, e.g. include:_spf.google.com)
        #   "redirect=value" (equals-separated, e.g. redirect=spf.example.com)
        #   "a" or "mx" alone (no value, refers to the current domain)
        if ":" in bare:
            name, value = bare.split(":", 1)
        elif "=" in bare:
            name, value = bare.split("=", 1)
        else:
            name, value = bare, ""
        name = name.lower()

        if name not in SPF_LOOKUP_MECHANISMS:
            continue

        lookups += 1

        # For "include" and "redirect", recursively resolve the target
        # record and add its lookups to the running total.
        if name in ("include", "redirect") and value:
            if value in visited:
                errors.append(f"include loop detected at {value}")
                continue
            visited.add(value)

            child_records = _resolve_txt(value)
            spf_children = [r for r in child_records if r.lower().startswith("v=spf1")]

            if not spf_children:
                # No SPF record returned. This counts as a void lookup
                # per RFC 7208.
                void_lookups += 1
                continue

            sub_lookups, sub_void, sub_errs = _count_spf_lookups(
                spf_children[0], depth + 1, max_depth, visited
            )
            lookups += sub_lookups
            void_lookups += sub_void
            errors.extend(sub_errs)

    return (lookups, void_lookups, errors)


def _parse_spf(record_text: str) -> tuple[str, list[str]]:
    """
    Extract the qualifier on the `all` mechanism (which sets the default
    policy for non-matching senders) and the list of authorized-sender
    mechanisms from an SPF record.

    Returns (qualifier_description, sender_list).
    """
    tokens = record_text.replace("v=spf1", "").strip().split()
    qualifier = "?"   # RFC 7208 default if no `all` mechanism is present
    senders: list[str] = []

    for token in tokens:
        bare = token.lstrip("+-~?")

        if bare.lower() == "all":
            # The qualifier is the leading character if present, else "+".
            q_char = token[0] if token[0] in "+-~?" else "+"
            qualifier = {
                "+": "+all (PASS, anyone authorized, MISCONFIGURATION)",
                "-": "-all (HARD FAIL, recommended)",
                "~": "~all (SOFT FAIL, quarantine)",
                "?": "?all (NEUTRAL, no policy)",
            }.get(q_char, q_char)
        elif bare.lower().startswith(("include:", "ip4:", "ip6:", "a:", "mx:", "exists:")) or bare.lower() in ("a", "mx"):
            senders.append(bare)

    return qualifier, senders


def _parse_dmarc(record_text: str) -> dict[str, str]:
    """
    Parse a DMARC TXT record into its tag-value pairs.

    DMARC records look like: v=DMARC1; p=reject; pct=100; rua=mailto:...
    """
    tags: dict[str, str] = {}
    for part in record_text.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def _audit_spf(domain: str) -> dict[str, Any] | None:
    """
    Audit the domain's SPF record: parse the policy, count the recursive
    DNS lookups against RFC 7208 limits, and surface void lookups and
    duplicate-record errors.

    Returns a result dict, or None if no SPF record exists.
    """
    spf_records = [r for r in _resolve_txt(domain) if r.lower().startswith("v=spf1")]
    if not spf_records:
        print("    [-] No SPF record found")
        return None

    spf = spf_records[0]
    qualifier, senders = _parse_spf(spf)
    lookups, voids, errs = _count_spf_lookups(spf)

    print(f"    [+] SPF: {spf}")
    print(f"          Policy on `all`     : {qualifier}")
    print(f"          DNS lookups (chain) : {lookups} / {SPF_MAX_DNS_LOOKUPS} (RFC 7208 limit)")
    if lookups > SPF_MAX_DNS_LOOKUPS:
        print("          [!] EXCEEDS LIMIT. SPF will return permerror.")
    print(f"          Void lookups        : {voids} / {SPF_MAX_VOID_LOOKUPS} (RFC 7208 limit)")
    if voids > SPF_MAX_VOID_LOOKUPS:
        print("          [!] EXCEEDS LIMIT. SPF will return permerror.")
    for err in errs:
        print(f"          [!] {err}")
    if len(spf_records) > 1:
        print(f"    [!] Multiple SPF records found ({len(spf_records)}). RFC 7208 forbids this.")

    return {
        "record": spf,
        "qualifier": qualifier,
        "senders": senders,
        "dns_lookups": lookups,
        "void_lookups": voids,
        "errors": errs,
        "duplicate_records": len(spf_records) > 1,
    }


def _audit_dmarc(domain: str) -> dict[str, Any] | None:
    """
    Audit the domain's DMARC record at _dmarc.{domain}. Surfaces the
    enforcement policy and flags p=none (reporting-only, no enforcement).

    Returns a result dict, or None if no DMARC record exists.
    """
    dmarc_records = [
        r for r in _resolve_txt(f"_dmarc.{domain}")
        if r.lower().startswith("v=dmarc1")
    ]
    if not dmarc_records:
        print(f"    [-] No DMARC record found at _dmarc.{domain}")
        return None

    dmarc = dmarc_records[0]
    tags = _parse_dmarc(dmarc)
    policy = tags.get("p", "none")
    sub_policy = tags.get("sp", policy)   # subdomain policy defaults to main
    pct = tags.get("pct", "100")
    rua = tags.get("rua", "")
    ruf = tags.get("ruf", "")

    print(f"    [+] DMARC: {dmarc}")
    print(f"          Policy              : p={policy}")
    if policy == "none":
        print("          [!] Policy is 'none'. Reporting only, no enforcement.")
    print(f"          Subdomain policy    : sp={sub_policy}")
    print(f"          Percentage applied  : pct={pct}")
    if rua:
        print(f"          Aggregate reports   : {rua}")
    if ruf:
        print(f"          Forensic reports    : {ruf}")

    return {"record": dmarc, "tags": tags}


def _audit_dkim(domain: str) -> list[tuple[str, str]]:
    """
    Probe COMMON_DKIM_SELECTORS for DKIM public keys.

    Returns a list of (selector_name, record_text) tuples for each
    selector that returned a DKIM-looking record. Empty list means
    "no DKIM at common selectors" (which is NOT the same as "no DKIM
    exists": custom selectors may be in use).
    """
    print(f"    [*] Probing {len(COMMON_DKIM_SELECTORS)} common DKIM selectors...")
    found: list[tuple[str, str]] = []

    for selector in COMMON_DKIM_SELECTORS:
        records = _resolve_txt(f"{selector}._domainkey.{domain}")
        # DKIM detection is loose: accept records containing v=DKIM1 OR
        # k= (key type) OR p= (public key). RFC 6376 allows the version
        # tag to be omitted, so a strict version check would miss some
        # legitimate records.
        dkim = [
            r for r in records
            if "v=dkim1" in r.lower() or "k=" in r.lower() or "p=" in r.lower()
        ]
        if dkim:
            found.append((selector, dkim[0]))

    if found:
        for selector, record in found:
            preview = record[:60] + "..." if len(record) > 60 else record
            print(f"    [+] DKIM selector '{selector}' found: {preview}")
    else:
        print("    [-] No DKIM records at common selectors. Custom selectors may exist.")

    return found


def _audit_bimi(domain: str) -> str | None:
    """
    Look up the BIMI record at default._bimi.{domain}.

    BIMI requires a DMARC policy of quarantine or reject as a
    prerequisite, so its presence implies a mature mail security posture.
    """
    bimi = [
        r for r in _resolve_txt(f"default._bimi.{domain}")
        if r.lower().startswith("v=bimi1")
    ]
    if bimi:
        print(f"    [+] BIMI: {bimi[0]}")
        return bimi[0]

    print(f"    [-] No BIMI record at default._bimi.{domain}")
    return None


def get_email_security(domain: str) -> dict[str, Any]:
    """
    Coordinate the email-authentication audit.

    Each protocol is handled by its own helper function. Returns a
    single results dict keyed by protocol name ("SPF", "DMARC",
    "DKIM", "BIMI").
    """
    print("\n[*] Auditing Email Security...")
    return {
        "SPF":   _audit_spf(domain),
        "DMARC": _audit_dmarc(domain),
        "DKIM":  _audit_dkim(domain),
        "BIMI":  _audit_bimi(domain),
    }
