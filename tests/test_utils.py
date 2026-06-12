"""
Tests for osint_recon.utils.

Covers _format_value: datetime microsecond stripping and type passthrough
for all non-datetime values.
"""

from datetime import datetime
from osint_recon.utils import _format_value


def test_strips_datetime_microseconds():
    """Datetime objects should be stripped to second precision"""
    dt = datetime(2027, 5, 18, 5, 37, 42, 150000)
    result = _format_value(dt)
    assert result == "2027-05-18 05:37:42"


def test_datetime_no_microseconds_still_formats():
    """Datetime with microsecond=0 should still produce ISO output"""
    dt = datetime(2027, 5, 18, 5, 37, 42, 0)
    result = _format_value(dt)
    assert result == "2027-05-18 05:37:42"


def test_string_passthrough():
    """Strings should pass through unchanged"""
    assert _format_value("NAMECHEAP INC") == "NAMECHEAP INC"


def test_none_passthrough():
    """None should pass through unchanged"""
    assert _format_value(None) is None


def test_integer_passthrough():
    """Integers should pass through unchanged"""
    assert _format_value(42) == 42


def test_list_passthrough():
    """Lists pass through unchanged (list handling lives in _print_fields)"""
    assert _format_value([1, 2, 3]) == [1, 2, 3]


def test_empty_string_passthrough():
    """Empty strings should pass through unchanged"""
    assert _format_value("") == ""
