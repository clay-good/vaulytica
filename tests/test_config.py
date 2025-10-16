"""Tests for configuration management."""

import pytest
from pathlib import Path
from vaulytica.config import VaulyticaConfig, load_config


class TestVaulyticaConfig:
    """Tests for VaulyticaConfig."""

    def test_create_config_with_defaults(self, tmp_path):
        """Test creating config with default values."""
        config = VaulyticaConfig(
            anthropic_api_key="test-key",
            chroma_db_path=tmp_path / "chroma",
            output_dir=tmp_path / "outputs"
        )
        assert config.anthropic_api_key == "test-key"
        assert config.model_name == "claude-3-haiku-20240307"
        assert config.max_tokens == 4000
        assert config.temperature == 0.0
        assert config.enable_rag is True
        assert config.enable_cache is True

    def test_config_creates_directories(self, tmp_path):
        """Test that config creates required directories."""
        chroma_path = tmp_path / "chroma"
        output_path = tmp_path / "outputs"
        
        config = VaulyticaConfig(
            anthropic_api_key="test-key",
            chroma_db_path=chroma_path,
            output_dir=output_path
        )
        
        assert chroma_path.exists()
        assert output_path.exists()

    def test_config_validates_api_key(self, tmp_path):
        """Test that config validates API key."""
        with pytest.raises(ValueError, match="Valid Anthropic API key required"):
            VaulyticaConfig(
                anthropic_api_key="",
                chroma_db_path=tmp_path / "chroma",
                output_dir=tmp_path / "outputs"
            )

    def test_config_custom_values(self, tmp_path):
        """Test creating config with custom values."""
        config = VaulyticaConfig(
            anthropic_api_key="test-key",
            model_name="claude-3-sonnet-20240229",
            max_tokens=8000,
            temperature=0.5,
            enable_rag=False,
            enable_cache=False,
            max_historical_incidents=10,
            batch_max_workers=5,
            chroma_db_path=tmp_path / "chroma",
            output_dir=tmp_path / "outputs"
        )
        
        assert config.model_name == "claude-3-sonnet-20240229"
        assert config.max_tokens == 8000
        assert config.temperature == 0.5
        assert config.enable_rag is False
        assert config.enable_cache is False
        assert config.max_historical_incidents == 10
        assert config.batch_max_workers == 5

    def test_load_config_with_api_key(self):
        """Test load_config function with API key."""
        config = load_config(api_key="test-key-123")
        assert config.anthropic_api_key == "test-key-123"

    def test_config_log_level(self, tmp_path):
        """Test config log level setting."""
        config = VaulyticaConfig(
            anthropic_api_key="test-key",
            log_level="DEBUG",
            chroma_db_path=tmp_path / "chroma",
            output_dir=tmp_path / "outputs"
        )
        assert config.log_level == "DEBUG"

