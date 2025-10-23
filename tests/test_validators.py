"""Tests for input validation."""

import pytest
import json
from pathlib import Path
from vaulytica.validators import (
    validate_json_file,
    validate_output_path,
    validate_source_type,
    validate_directory,
    validate_pattern,
    sanitize_string,
    ValidationError
)


class TestValidateJsonFile:
    """Tests for JSON file validation."""

    def test_validate_valid_json_file(self, tmp_path):
        """Test validating a valid JSON file."""
        test_file = tmp_path / "test.json"
        test_data = {"key": "value", "number": 42}
        with open(test_file, 'w') as f:
            json.dump(test_data, f)
        
        result = validate_json_file(test_file)
        assert result == test_data

    def test_validate_nonexistent_file(self, tmp_path):
        """Test validating a nonexistent file."""
        test_file = tmp_path / "nonexistent.json"
        with pytest.raises(ValidationError, match="File not found"):
            validate_json_file(test_file)

    def test_validate_empty_file(self, tmp_path):
        """Test validating an empty file."""
        test_file = tmp_path / "empty.json"
        test_file.touch()
        with pytest.raises(ValidationError, match="File is empty"):
            validate_json_file(test_file)

    def test_validate_invalid_json(self, tmp_path):
        """Test validating invalid JSON."""
        test_file = tmp_path / "invalid.json"
        with open(test_file, 'w') as f:
            f.write("not valid json {")
        
        with pytest.raises(ValidationError, match="Invalid JSON"):
            validate_json_file(test_file)

    def test_validate_json_array(self, tmp_path):
        """Test validating JSON array."""
        test_file = tmp_path / "array.json"
        test_data = [{"id": 1}, {"id": 2}]
        with open(test_file, 'w') as f:
            json.dump(test_data, f)
        
        result = validate_json_file(test_file)
        assert result == test_data


class TestValidateOutputPath:
    """Tests for output path validation."""

    def test_validate_valid_output_path(self, tmp_path):
        """Test validating a valid output path."""
        output_file = tmp_path / "output.json"
        validate_output_path(output_file)  # Should not raise

    def test_validate_output_path_creates_parent(self, tmp_path):
        """Test that validation creates parent directory."""
        output_file = tmp_path / "subdir" / "output.json"
        validate_output_path(output_file)
        assert output_file.parent.exists()

    def test_validate_output_path_directory(self, tmp_path):
        """Test validating a directory as output path."""
        output_dir = tmp_path / "dir"
        output_dir.mkdir()
        with pytest.raises(ValidationError, match="Path is a directory"):
            validate_output_path(output_dir)


class TestValidateSourceType:
    """Tests for source type validation."""

    def test_validate_valid_source(self):
        """Test validating a valid source type."""
        sources = ['guardduty', 'gcp-scc', 'datadog']
        result = validate_source_type('guardduty', sources)
        assert result == 'guardduty'

    def test_validate_invalid_source(self):
        """Test validating an invalid source type."""
        sources = ['guardduty', 'gcp-scc']
        with pytest.raises(ValidationError, match="Invalid source type"):
            validate_source_type('invalid', sources)


class TestValidateDirectory:
    """Tests for directory validation."""

    def test_validate_valid_directory(self, tmp_path):
        """Test validating a valid directory."""
        test_dir = tmp_path / "testdir"
        test_dir.mkdir()
        validate_directory(test_dir)  # Should not raise

    def test_validate_nonexistent_directory(self, tmp_path):
        """Test validating a nonexistent directory."""
        test_dir = tmp_path / "nonexistent"
        with pytest.raises(ValidationError, match="Directory not found"):
            validate_directory(test_dir)

    def test_validate_file_as_directory(self, tmp_path):
        """Test validating a file as directory."""
        test_file = tmp_path / "file.txt"
        test_file.touch()
        with pytest.raises(ValidationError, match="Path is not a directory"):
            validate_directory(test_file)


class TestValidatePattern:
    """Tests for pattern validation."""

    def test_validate_valid_pattern(self):
        """Test validating a valid glob pattern."""
        validate_pattern("*.json")  # Should not raise
        validate_pattern("test_*.json")  # Should not raise

    def test_validate_empty_pattern(self):
        """Test validating an empty pattern."""
        with pytest.raises(ValidationError, match="Pattern cannot be empty"):
            validate_pattern("")


class TestSanitizeString:
    """Tests for string sanitization."""

    def test_sanitize_normal_string(self):
        """Test sanitizing a normal string."""
        result = sanitize_string("Hello World")
        assert result == "Hello World"

    def test_sanitize_string_with_control_chars(self):
        """Test sanitizing string with control characters."""
        result = sanitize_string("Hello\x00World\x1f")
        assert result == "HelloWorld"

    def test_sanitize_long_string(self):
        """Test sanitizing a very long string."""
        long_string = "A" * 15000
        result = sanitize_string(long_string, max_length=10000)
        assert len(result) <= 10003  # 10000 + "..."
        assert result.endswith("...")

    def test_sanitize_non_string(self):
        """Test sanitizing non-string input."""
        result = sanitize_string(12345)
        assert result == "12345"

