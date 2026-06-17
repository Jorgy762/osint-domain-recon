"""
Domain registration data lookup via RDAP, with legacy WHOIS as a
fallback for TLDs that have no RDAP service available.

RDAP (Registration Data Access Protocol, RFC 7480-7484) returns
structured JSON instead of the free-form text that traditional WHOIS
provides, which makes parsing reliable across registrars. ICANN has
mandated RDAP for gTLD registrars since 2019.

The whoisit library handles the RDAP protocol mechanics including
bootstrap (determining which RDAP server is authoritative for a given
TLD) and response parsing. We cache the bootstrap data on disk so we
do not hit IANA on every scan run.
"""

from typing import Any

import whois  # legacy WHOIS library, used only as a fallback
import whoisit

from .constants import CACHE_DAYS, CACHE_DIR, CACHE_FILE
from .utils import _print_fields


def ensure_rdap_bootstrapped() -> None:
    """
    Make sure the whoisit library has its RDAP bootstrap data loaded.

    The bootstrap tells whoisit which RDAP server is authoritative for a
    given TLD, IP block, or ASN. Without it, no query can be routed.

    Strategy:
      1. If already loaded in-process, do nothing.
      2. If a fresh disk cache exists (<= CACHE_DAYS old), load that.
      3. Otherwise fetch from IANA and write a new cache.

    Cache write failures are non-fatal. The tool still works, just slower
    on subsequent runs.
    """
    if whoisit.is_bootstrapped():
        return

    # Try the disk cache first.
    if CACHE_FILE.exists():
        try:
            cached = CACHE_FILE.read_text(encoding="utf-8")
            whoisit.load_bootstrap_data(cached)
            if not whoisit.bootstrap_is_older_than(CACHE_DAYS):
                return
        except Exception:
            # Corrupt or unreadable cache. Discard and fall through.
            whoisit.clear_bootstrapping()

    # No cache or stale cache: fetch fresh and write the new copy.
    whoisit.bootstrap()
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(whoisit.save_bootstrap_data(), encoding="utf-8")
    except OSError as e:
        print(f"    [!] Could not write bootstrap cache ({e}). Continuing.")


def _whois_fallback(domain: str) -> dict[str, Any]:
    """
    Fallback to legacy WHOIS via python-whois when RDAP is unavailable.

    Returns a dict in the same shape as the RDAP path so callers do not
    need to know which protocol succeeded.
    """
    print("\n[*] Running WHOIS lookup...")
    try:
        w = whois.whois(domain)
        fields: dict[str, Any] = {
            "Source"             : "WHOIS",
            "Registrar"          : w.registrar,
            "Creation Date"      : w.creation_date,
            "Expiration Date"    : w.expiration_date,
            "Last Updated"       : w.updated_date,
            "Name Servers"       : w.name_servers,
            "Status"             : w.status,
            "Registrant Country" : w.country,
            "DNSSEC"             : w.dnssec,
        }
        _print_fields(fields)
        return fields
    except Exception as e:
        print(f"    [-] WHOIS lookup failed: {e}")
        return {"Source": "FAILED"}


def get_registration(domain: str) -> dict[str, Any]:
    """
    Look up domain registration data, RDAP first with WHOIS as fallback.

    Returns a dict with normalized field names and a "Source" key that
    indicates which protocol returned the data ("RDAP", "WHOIS", or
    "FAILED").
    """
    print("\n[*] Looking up registration data (RDAP)...")
    try:
        ensure_rdap_bootstrapped()
        r = whoisit.domain(domain)

        # Extract the registrar's display name from the registrar entity.
        registrar = ""
        registrars = r.get("entities", {}).get("registrar", [])
        if registrars:
            registrar = registrars[0].get("name", "")

        # RDAP does not return registrant country at the top level. It can
        # appear inside any role's vCard. Walk the common roles in priority
        # order and take the first hit.
        country = ""
        for role in ("registrant", "administrative", "technical", "registrar"):
            for entity in r.get("entities", {}).get(role, []):
                country = entity.get("country", "")
                if country:
                    break
            if country:
                break

        fields: dict[str, Any] = {
            "Source"             : "RDAP",
            "Registrar"          : registrar,
            "Creation Date"      : r.get("registration_date"),
            "Expiration Date"    : r.get("expiration_date"),
            "Last Updated"       : r.get("last_changed_date"),
            "Name Servers"       : r.get("nameservers") or [],
            "Status"             : r.get("status") or [],
            "Registrant Country" : country,
            "DNSSEC"             : "signedDelegation" if r.get("dnssec") else "unsigned",
        }
        _print_fields(fields)
        return fields

    # Whoisit's WhoisItError is the base class for all whoisit exceptions
    # (UnsupportedError, RateLimitedError, BootstrapError, QueryError, etc.).
    # A single catch on the base class handles all RDAP failure modes with
    # the specific exception class name surfaced in the printed message.
    except whoisit.errors.WhoisItError as e:
        print(f"    [!] RDAP failed ({type(e).__name__}: {e}). Falling back to WHOIS...")
        return _whois_fallback(domain)
