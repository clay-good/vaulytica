"""Custom PII pattern management for industry-specific detection."""

import re
import yaml
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class CustomPIIPattern:
    """Custom PII pattern definition."""

    name: str
    pattern: str
    description: str
    severity: str = "medium"  # low, medium, high, critical
    enabled: bool = True
    category: str = "custom"
    compiled_pattern: Optional[re.Pattern] = field(default=None, init=False, repr=False)

    def __post_init__(self):
        """Compile the regex pattern after initialization."""
        try:
            self.compiled_pattern = re.compile(self.pattern, re.IGNORECASE)
        except re.error as e:
            logger.error(
                "invalid_custom_pattern",
                pattern_name=self.name,
                pattern=self.pattern,
                error=str(e),
            )
            raise ValueError(f"Invalid regex pattern for {self.name}: {e}")

    def matches(self, text: str) -> List[str]:
        """Find all matches in the given text."""
        if not self.enabled or not self.compiled_pattern:
            return []

        try:
            matches = self.compiled_pattern.findall(text)
            return matches if matches else []
        except Exception as e:
            logger.error(
                "pattern_match_error",
                pattern_name=self.name,
                error=str(e),
            )
            return []


class CustomPIIPatternManager:
    """Manage custom PII patterns from configuration files."""

    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize the custom pattern manager.

        Args:
            config_path: Path to custom patterns YAML file
        """
        self.config_path = config_path
        self.patterns: Dict[str, CustomPIIPattern] = {}
        self._load_patterns()

    def _load_patterns(self):
        """Load custom patterns from configuration file."""
        if not self.config_path or not self.config_path.exists():
            logger.info("no_custom_patterns_file", config_path=str(self.config_path))
            return

        try:
            with open(self.config_path, "r") as f:
                config = yaml.safe_load(f)

            if not config or "custom_pii_patterns" not in config:
                logger.warning("no_custom_patterns_in_config")
                return

            patterns_config = config["custom_pii_patterns"]
            for pattern_data in patterns_config:
                try:
                    pattern = CustomPIIPattern(
                        name=pattern_data["name"],
                        pattern=pattern_data["pattern"],
                        description=pattern_data.get("description", ""),
                        severity=pattern_data.get("severity", "medium"),
                        enabled=pattern_data.get("enabled", True),
                        category=pattern_data.get("category", "custom"),
                    )
                    self.patterns[pattern.name] = pattern
                    logger.info(
                        "custom_pattern_loaded",
                        pattern_name=pattern.name,
                        category=pattern.category,
                    )
                except Exception as e:
                    logger.error(
                        "failed_to_load_pattern",
                        pattern_data=pattern_data,
                        error=str(e),
                    )

            logger.info("custom_patterns_loaded", count=len(self.patterns))

        except Exception as e:
            logger.error(
                "failed_to_load_custom_patterns",
                config_path=str(self.config_path),
                error=str(e),
            )

    def add_pattern(
        self,
        name: str,
        pattern: str,
        description: str,
        severity: str = "medium",
        category: str = "custom",
    ) -> bool:
        """
        Add a new custom pattern.

        Args:
            name: Pattern name
            pattern: Regex pattern
            description: Pattern description
            severity: Severity level (low, medium, high, critical)
            category: Pattern category

        Returns:
            True if pattern was added successfully
        """
        try:
            custom_pattern = CustomPIIPattern(
                name=name,
                pattern=pattern,
                description=description,
                severity=severity,
                category=category,
            )
            self.patterns[name] = custom_pattern
            logger.info("custom_pattern_added", pattern_name=name)
            return True
        except Exception as e:
            logger.error("failed_to_add_pattern", pattern_name=name, error=str(e))
            return False

    def remove_pattern(self, name: str) -> bool:
        """
        Remove a custom pattern.

        Args:
            name: Pattern name to remove

        Returns:
            True if pattern was removed
        """
        if name in self.patterns:
            del self.patterns[name]
            logger.info("custom_pattern_removed", pattern_name=name)
            return True
        return False

    def enable_pattern(self, name: str) -> bool:
        """Enable a custom pattern."""
        if name in self.patterns:
            self.patterns[name].enabled = True
            logger.info("custom_pattern_enabled", pattern_name=name)
            return True
        return False

    def disable_pattern(self, name: str) -> bool:
        """Disable a custom pattern."""
        if name in self.patterns:
            self.patterns[name].enabled = False
            logger.info("custom_pattern_disabled", pattern_name=name)
            return True
        return False

    def get_pattern(self, name: str) -> Optional[CustomPIIPattern]:
        """Get a custom pattern by name."""
        return self.patterns.get(name)

    def get_all_patterns(self) -> List[CustomPIIPattern]:
        """Get all custom patterns."""
        return list(self.patterns.values())

    def get_enabled_patterns(self) -> List[CustomPIIPattern]:
        """Get all enabled custom patterns."""
        return [p for p in self.patterns.values() if p.enabled]

    def scan_text(self, text: str) -> Dict[str, List[str]]:
        """
        Scan text for all enabled custom patterns.

        Args:
            text: Text to scan

        Returns:
            Dictionary mapping pattern names to list of matches
        """
        results = {}
        for pattern in self.get_enabled_patterns():
            matches = pattern.matches(text)
            if matches:
                results[pattern.name] = matches

        return results

    def save_patterns(self, output_path: Optional[Path] = None):
        """
        Save custom patterns to YAML file.

        Args:
            output_path: Path to save patterns (defaults to config_path)
        """
        save_path = output_path or self.config_path
        if not save_path:
            logger.error("no_save_path_specified")
            return

        patterns_data = []
        for pattern in self.patterns.values():
            patterns_data.append(
                {
                    "name": pattern.name,
                    "pattern": pattern.pattern,
                    "description": pattern.description,
                    "severity": pattern.severity,
                    "enabled": pattern.enabled,
                    "category": pattern.category,
                }
            )

        config = {"custom_pii_patterns": patterns_data}

        try:
            with open(save_path, "w") as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)
            logger.info("custom_patterns_saved", path=str(save_path), count=len(patterns_data))
        except Exception as e:
            logger.error("failed_to_save_patterns", path=str(save_path), error=str(e))

    def validate_pattern(self, pattern: str) -> tuple[bool, Optional[str]]:
        """
        Validate a regex pattern.

        Args:
            pattern: Regex pattern to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            re.compile(pattern)
            return True, None
        except re.error as e:
            return False, str(e)

    def get_statistics(self) -> Dict:
        """Get statistics about custom patterns."""
        enabled = len(self.get_enabled_patterns())
        disabled = len(self.patterns) - enabled

        categories = {}
        severities = {}

        for pattern in self.patterns.values():
            categories[pattern.category] = categories.get(pattern.category, 0) + 1
            severities[pattern.severity] = severities.get(pattern.severity, 0) + 1

        return {
            "total_patterns": len(self.patterns),
            "enabled_patterns": enabled,
            "disabled_patterns": disabled,
            "categories": categories,
            "severities": severities,
        }

