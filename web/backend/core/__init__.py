"""Core utilities for Vaulytica web backend."""

from .cache import (
    get_cache,
    cached,
    invalidate_cache,
    make_cache_key,
    CACHE_PREFIX_SCAN_STATS,
    CACHE_PREFIX_FINDINGS_SUMMARY,
    CACHE_PREFIX_DASHBOARD,
    CACHE_TTL_SCAN_STATS,
    CACHE_TTL_FINDINGS_SUMMARY,
    CACHE_TTL_DASHBOARD,
)

__all__ = [
    "get_cache",
    "cached",
    "invalidate_cache",
    "make_cache_key",
    "CACHE_PREFIX_SCAN_STATS",
    "CACHE_PREFIX_FINDINGS_SUMMARY",
    "CACHE_PREFIX_DASHBOARD",
    "CACHE_TTL_SCAN_STATS",
    "CACHE_TTL_FINDINGS_SUMMARY",
    "CACHE_TTL_DASHBOARD",
]
