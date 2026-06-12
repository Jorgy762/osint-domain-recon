"""
OSINT Domain Recon Tool.

A command-line tool for automated domain reconnaissance. See the
project README at https://github.com/Jorgy762/osint-domain-recon
for installation, usage, and feature documentation.

The package version is read from the installed package metadata
(populated by pyproject.toml at install time), so there is exactly
one source of truth for the version number.
"""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("osint-domain-recon")
except PackageNotFoundError:
    # Package is not installed. This happens when running directly from
    # source without "pip install -e ." having been run first. The tool
    # will still work, but the reported version will be the placeholder.
    __version__ = "0.0.0+unknown"

__author__ = "Jorgy762"
