"""
Input validation and startup display.

Validates that user-supplied domain input is well-formed before any
network calls are made. Also defines the startup banner shown at the
top of each scan run.
"""

import sys

from .constants import DOMAIN_REGEX


def print_banner() -> None:
    """Display the startup banner and authorized-use reminder."""
    banner = """
+==============================================+
|          OSINT Domain Recon Tool             |
|          github.com/Jorgy762                 |
|          For authorized use only             |
+==============================================+
    """
    print(banner)


def validate_domain(raw: str) -> str:
    """
    Normalize and validate a domain name.

    Strips URL schemes, paths, trailing dots, and uppercase characters,
    then validates against DOMAIN_REGEX. Exits the program with a
    friendly error message if the input is not a well-formed domain.

    This function is the single trust boundary for user input. Every
    other module assumes the domain has already passed validation.
    """
    cleaned = (
        raw.strip().lower()
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]          # drop path component if URL was passed
        .rstrip(".")            # drop trailing dot (FQDN form)
    )
    if not DOMAIN_REGEX.match(cleaned):
        print(f"[!] Invalid domain format: {cleaned!r}")
        sys.exit(1)
    return cleaned
