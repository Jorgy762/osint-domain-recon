"""
Generic display utilities used by multiple modules.

These functions normalize values for output (datetime stripping,
empty-value filtering, list deduplication) and print key/value dicts
in the standard "[+] Key: Value" terminal format used throughout
the tool.
"""

from datetime import datetime
from typing import Any


def _format_value(value: Any) -> Any:
    """
    Normalize a single value for display.

    Datetimes are stripped to second precision: RDAP servers sometimes
    return microsecond timestamps that are noise for recon work. All
    other types pass through unchanged.
    """
    if isinstance(value, datetime):
        return value.replace(microsecond=0).isoformat(sep=" ")
    return value


def _print_fields(fields: dict[str, Any]) -> None:
    """
    Pretty-print a key/value dict to the terminal in the "[+] Key: Value"
    format used by every scan stage. Skips empty values, deduplicates
    list entries (some registrars return duplicates with different
    casing), trims long lists to five entries, and normalizes datetimes
    via _format_value.
    """
    for key, value in fields.items():
        # Skip empty values across all the common empty types.
        if value in (None, "", [], {}):
            continue

        if isinstance(value, list):
            # Deduplicate while preserving original order.
            seen: set[str] = set()
            unique: list[str] = []
            for v in value:
                s = str(_format_value(v))
                if s not in seen:
                    seen.add(s)
                    unique.append(s)
            value = unique[0] if len(unique) == 1 else ", ".join(unique[:5])
        else:
            value = _format_value(value)

        print(f"    [+] {key}: {value}")
