"""Test basic package functionality."""

import vaulytica


def test_version() -> None:
    """Test that version is defined."""
    assert vaulytica.__version__ == "0.1.0"


def test_package_metadata() -> None:
    """Test that package metadata is defined."""
    assert vaulytica.__author__ is not None
    assert vaulytica.__license__ == "MIT"

