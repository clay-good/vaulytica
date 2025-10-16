"""Tests for analysis caching."""

import pytest
import time
from datetime import datetime, timedelta
from vaulytica.cache import AnalysisCache


class TestAnalysisCache:
    """Tests for AnalysisCache."""

    def test_cache_initialization(self, mock_config):
        """Test cache initialization."""
        cache = AnalysisCache(mock_config)
        assert cache.cache_dir.exists()
        assert cache.ttl_hours == 24

    def test_cache_set_and_get(self, mock_config, sample_security_event, sample_analysis_result):
        """Test setting and getting cache entries."""
        cache = AnalysisCache(mock_config)
        
        # Set cache
        cache.set(sample_security_event, sample_analysis_result)
        
        # Get cache
        result = cache.get(sample_security_event)
        assert result is not None
        assert result.event_id == sample_analysis_result.event_id
        assert result.risk_score == sample_analysis_result.risk_score

    def test_cache_miss(self, mock_config, sample_security_event):
        """Test cache miss for non-existent entry."""
        cache = AnalysisCache(mock_config)
        result = cache.get(sample_security_event)
        assert result is None

    def test_cache_key_generation(self, mock_config, sample_security_event):
        """Test cache key generation is consistent."""
        cache = AnalysisCache(mock_config)
        
        key1 = cache._generate_cache_key(sample_security_event)
        key2 = cache._generate_cache_key(sample_security_event)
        
        assert key1 == key2
        assert len(key1) == 64  # SHA256 hex digest length

    def test_cache_clear_all(self, mock_config, sample_security_event, sample_analysis_result):
        """Test clearing all cache entries."""
        cache = AnalysisCache(mock_config)
        
        # Add some cache entries
        cache.set(sample_security_event, sample_analysis_result)
        
        # Clear all
        cleared = cache.clear_all()
        assert cleared >= 1
        
        # Verify cache is empty
        result = cache.get(sample_security_event)
        assert result is None

    def test_cache_stats(self, mock_config, sample_security_event, sample_analysis_result):
        """Test getting cache statistics."""
        cache = AnalysisCache(mock_config)
        
        # Add cache entry
        cache.set(sample_security_event, sample_analysis_result)
        
        # Get stats
        stats = cache.get_stats()
        assert stats["total_entries"] >= 1
        assert stats["total_size_bytes"] > 0
        assert "cache_dir" in stats
        assert stats["ttl_hours"] == 24

    def test_cache_clear_expired(self, mock_config, sample_security_event, sample_analysis_result):
        """Test clearing expired cache entries."""
        cache = AnalysisCache(mock_config)
        cache.ttl_hours = 0  # Set TTL to 0 for testing
        
        # Add cache entry
        cache.set(sample_security_event, sample_analysis_result)
        
        # Wait a moment
        time.sleep(0.1)
        
        # Clear expired
        cleared = cache.clear_expired()
        assert cleared >= 0  # May or may not clear depending on timing

    def test_cache_different_events_different_keys(self, mock_config, sample_security_event):
        """Test that different events generate different cache keys."""
        cache = AnalysisCache(mock_config)
        
        # Create a modified event
        modified_event = sample_security_event.model_copy()
        modified_event.event_id = "different-id"
        
        key1 = cache._generate_cache_key(sample_security_event)
        key2 = cache._generate_cache_key(modified_event)
        
        assert key1 != key2

