"""Input validation and sanitization."""

import json
from pathlib import Path
from typing import Any, Dict, List
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class ValidationError(Exception):
    """Custom exception for validation errors."""
    pass


def validate_json_file(file_path: Path) -> Dict[str, Any]:
    """Validate and load JSON file with comprehensive error handling."""

    if not file_path.exists():
        raise ValidationError(f"File not found: {file_path}")

    if not file_path.is_file():
        raise ValidationError(f"Path is not a file: {file_path}")

    if file_path.stat().st_size == 0:
        raise ValidationError(f"File is empty: {file_path}")

    if file_path.stat().st_size > 100 * 1024 * 1024:
        raise ValidationError(f"File too large (>100MB): {file_path}")

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValidationError(f"Invalid JSON in {file_path}: {e}")
    except UnicodeDecodeError as e:
        raise ValidationError(f"Invalid encoding in {file_path}: {e}")
    except Exception as e:
        raise ValidationError(f"Error reading {file_path}: {e}")

    if not isinstance(data, (dict, list)):
        raise ValidationError(f"JSON must be object or array, got {type(data).__name__}")

    logger.debug(f"Successfully validated JSON file: {file_path}")
    return data


def validate_output_path(output_path: Path, create_dirs: bool = True) -> Path:
    """Validate output path and create directories if needed."""

    if output_path.exists() and output_path.is_dir():
        raise ValidationError(f"Output path is a directory: {output_path}")

    if create_dirs:
        output_path.parent.mkdir(parents=True, exist_ok=True)
    elif not output_path.parent.exists():
        raise ValidationError(f"Output directory does not exist: {output_path.parent}")

    logger.debug(f"Validated output path: {output_path}")
    return output_path


def validate_source_type(source: str, supported_sources: List[str]) -> str:
    """Validate source type against supported sources."""

    if not source:
        raise ValidationError("Source type cannot be empty")

    source_lower = source.lower()
    if source_lower not in supported_sources:
        raise ValidationError(
            f"Unsupported source: {source}. "
            f"Supported sources: {', '.join(supported_sources)}"
        )

    return source_lower


def validate_api_key(api_key: str) -> str:
    """Validate Anthropic API key format."""

    if not api_key:
        raise ValidationError("API key cannot be empty")

    if not api_key.startswith("sk-ant-"):
        raise ValidationError("Invalid API key format (must start with 'sk-ant-')")

    if len(api_key) < 20:
        raise ValidationError("API key too short")

    logger.debug("API key format validated")
    return api_key


def sanitize_string(value: str, max_length: int = 10000) -> str:
    """Sanitize string input by removing control characters and limiting length."""

    if not isinstance(value, str):
        return str(value)

    import re
    sanitized = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f-\x9f]', '', value)

    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "..."
        logger.warning(f"String truncated to {max_length} characters")

    return sanitized


def validate_risk_score(score: float) -> float:
    """Validate risk score is within valid range."""

    if not isinstance(score, (int, float)):
        raise ValidationError(f"Risk score must be numeric, got {type(score).__name__}")

    if not 0.0 <= score <= 10.0:
        raise ValidationError(f"Risk score must be between 0.0 and 10.0, got {score}")

    return float(score)


def validate_confidence(confidence: float) -> float:
    """Validate confidence is within valid range."""

    if not isinstance(confidence, (int, float)):
        raise ValidationError(f"Confidence must be numeric, got {type(confidence).__name__}")

    if not 0.0 <= confidence <= 1.0:
        raise ValidationError(f"Confidence must be between 0.0 and 1.0, got {confidence}")

    return float(confidence)


def validate_directory(directory: Path, must_exist: bool = True) -> Path:
    """Validate directory path."""

    if must_exist and not directory.exists():
        raise ValidationError(f"Directory not found: {directory}")

    if directory.exists() and not directory.is_dir():
        raise ValidationError(f"Path is not a directory: {directory}")

    return directory


def validate_pattern(pattern: str) -> str:
    """Validate file pattern."""

    if not pattern:
        raise ValidationError("File pattern cannot be empty")

    if not pattern.endswith('.json'):
        logger.warning(f"Pattern '{pattern}' does not end with .json")

    return pattern


def validate_event(event: Dict[str, Any]) -> bool:
    """Validate security event structure.

    Args:
        event: Event dictionary to validate

    Returns:
        True if event is valid

    Raises:
        ValidationError: If event structure is invalid
    """
    if not isinstance(event, dict):
        raise ValidationError(f"Event must be a dictionary, got {type(event).__name__}")

    required_fields = ['event_id', 'source_system', 'title']
    missing_fields = [field for field in required_fields if field not in event]

    if missing_fields:
        raise ValidationError(f"Event missing required fields: {', '.join(missing_fields)}")

    if not event.get('event_id'):
        raise ValidationError("Event ID cannot be empty")

    if not event.get('source_system'):
        raise ValidationError("Source system cannot be empty")

    if not event.get('title'):
        raise ValidationError("Title cannot be empty")

    logger.debug(f"Successfully validated event: {event.get('event_id')}")
    return True
