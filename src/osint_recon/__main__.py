"""
Entry point for "python -m osint_recon".

This module exists so the package can be invoked as a module. It is
deliberately a one-liner that defers all real work to cli.main(),
keeping the entry surface area trivially auditable.
"""

from .cli import main

if __name__ == "__main__":
    main()
