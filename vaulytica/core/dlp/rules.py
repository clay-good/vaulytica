"""Custom DLP rules engine."""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Pattern
from enum import Enum

import structlog
import yaml

logger = structlog.get_logger(__name__)


class RuleAction(Enum):
    """Actions to take when a rule matches."""

    ALERT = "alert"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    LOG = "log"


class RuleSeverity(Enum):
    """Rule severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DLPPattern:
    """A pattern to match in content."""

    name: str
    pattern: str
    regex: Optional[Pattern] = None
    case_sensitive: bool = False
    whole_word: bool = False

    def __post_init__(self):
        """Compile regex pattern."""
        flags = 0 if self.case_sensitive else re.IGNORECASE

        if self.whole_word:
            pattern = rf"\b{self.pattern}\b"
        else:
            pattern = self.pattern

        try:
            self.regex = re.compile(pattern, flags)
        except re.error as e:
            logger.error("invalid_regex_pattern", pattern=self.pattern, error=str(e))
            raise ValueError(f"Invalid regex pattern: {self.pattern}")


@dataclass
class DLPRule:
    """A DLP rule definition."""

    id: str
    name: str
    description: str
    severity: RuleSeverity
    action: RuleAction
    patterns: List[DLPPattern] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    file_types: List[str] = field(default_factory=list)  # MIME types
    file_extensions: List[str] = field(default_factory=list)
    min_matches: int = 1
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DLPMatch:
    """A match found by a DLP rule."""

    rule_id: str
    rule_name: str
    severity: RuleSeverity
    action: RuleAction
    pattern_name: str
    matched_text: str
    context: str
    position: int


@dataclass
class DLPResult:
    """Result of DLP scanning."""

    file_id: str
    file_name: str
    matches: List[DLPMatch] = field(default_factory=list)
    rules_triggered: List[str] = field(default_factory=list)
    highest_severity: Optional[RuleSeverity] = None
    recommended_action: Optional[RuleAction] = None

    def calculate_risk_score(self) -> int:
        """Calculate risk score based on matches."""
        score = 0

        severity_scores = {
            RuleSeverity.CRITICAL: 25,
            RuleSeverity.HIGH: 15,
            RuleSeverity.MEDIUM: 10,
            RuleSeverity.LOW: 5,
            RuleSeverity.INFO: 1,
        }

        for match in self.matches:
            score += severity_scores.get(match.severity, 0)

        return min(100, score)


class DLPEngine:
    """Custom DLP rules engine."""

    def __init__(self, rules: Optional[List[DLPRule]] = None):
        """Initialize DLP engine.

        Args:
            rules: List of DLP rules
        """
        self.rules = rules or []
        logger.info("dlp_engine_initialized", rule_count=len(self.rules))

    @classmethod
    def from_yaml(cls, yaml_path: str) -> "DLPEngine":
        """Load DLP rules from YAML file.

        Args:
            yaml_path: Path to YAML file

        Returns:
            DLPEngine instance
        """
        logger.info("loading_dlp_rules", path=yaml_path)

        with open(yaml_path, "r") as f:
            data = yaml.safe_load(f)

        rules = []
        for rule_data in data.get("rules", []):
            rule = cls._parse_rule(rule_data)
            rules.append(rule)

        logger.info("dlp_rules_loaded", count=len(rules))
        return cls(rules)

    @staticmethod
    def _parse_rule(rule_data: Dict[str, Any]) -> DLPRule:
        """Parse rule from dictionary.

        Args:
            rule_data: Rule data dictionary

        Returns:
            DLPRule instance
        """
        # Parse patterns
        patterns = []
        for pattern_data in rule_data.get("patterns", []):
            pattern = DLPPattern(
                name=pattern_data.get("name", ""),
                pattern=pattern_data.get("pattern", ""),
                case_sensitive=pattern_data.get("case_sensitive", False),
                whole_word=pattern_data.get("whole_word", False),
            )
            patterns.append(pattern)

        # Create rule
        rule = DLPRule(
            id=rule_data.get("id", ""),
            name=rule_data.get("name", ""),
            description=rule_data.get("description", ""),
            severity=RuleSeverity(rule_data.get("severity", "medium")),
            action=RuleAction(rule_data.get("action", "alert")),
            patterns=patterns,
            keywords=rule_data.get("keywords", []),
            file_types=rule_data.get("file_types", []),
            file_extensions=rule_data.get("file_extensions", []),
            min_matches=rule_data.get("min_matches", 1),
            enabled=rule_data.get("enabled", True),
            metadata=rule_data.get("metadata", {}),
        )

        return rule

    def scan_content(
        self,
        content: str,
        file_id: str,
        file_name: str,
        file_type: Optional[str] = None,
    ) -> DLPResult:
        """Scan content with DLP rules.

        Args:
            content: Content to scan
            file_id: File ID
            file_name: File name
            file_type: MIME type

        Returns:
            DLPResult
        """
        result = DLPResult(file_id=file_id, file_name=file_name)

        # Get file extension
        file_ext = file_name.split(".")[-1].lower() if "." in file_name else ""

        for rule in self.rules:
            if not rule.enabled:
                continue

            # Check file type filters
            if rule.file_types and file_type not in rule.file_types:
                continue

            if rule.file_extensions and file_ext not in rule.file_extensions:
                continue

            # Scan with this rule
            matches = self._scan_with_rule(rule, content)

            if len(matches) >= rule.min_matches:
                result.matches.extend(matches)
                result.rules_triggered.append(rule.id)

        # Determine highest severity and recommended action
        if result.matches:
            severities = [m.severity for m in result.matches]
            severity_order = [
                RuleSeverity.CRITICAL,
                RuleSeverity.HIGH,
                RuleSeverity.MEDIUM,
                RuleSeverity.LOW,
                RuleSeverity.INFO,
            ]

            for severity in severity_order:
                if severity in severities:
                    result.highest_severity = severity
                    break

            # Get most severe action
            actions = [m.action for m in result.matches]
            if RuleAction.BLOCK in actions:
                result.recommended_action = RuleAction.BLOCK
            elif RuleAction.QUARANTINE in actions:
                result.recommended_action = RuleAction.QUARANTINE
            elif RuleAction.ALERT in actions:
                result.recommended_action = RuleAction.ALERT
            else:
                result.recommended_action = RuleAction.LOG

        return result

    def _scan_with_rule(self, rule: DLPRule, content: str) -> List[DLPMatch]:
        """Scan content with a single rule.

        Args:
            rule: DLP rule
            content: Content to scan

        Returns:
            List of DLPMatch objects
        """
        matches = []

        # Scan with patterns
        for pattern in rule.patterns:
            if not pattern.regex:
                continue

            for match in pattern.regex.finditer(content):
                matched_text = match.group(0)
                position = match.start()

                # Get context (50 chars before and after)
                context_start = max(0, position - 50)
                context_end = min(len(content), position + len(matched_text) + 50)
                context = content[context_start:context_end]

                dlp_match = DLPMatch(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    action=rule.action,
                    pattern_name=pattern.name,
                    matched_text=matched_text,
                    context=context,
                    position=position,
                )

                matches.append(dlp_match)

        # Scan with keywords
        for keyword in rule.keywords:
            keyword_lower = keyword.lower()
            content_lower = content.lower()

            pos = 0
            while True:
                pos = content_lower.find(keyword_lower, pos)
                if pos == -1:
                    break

                matched_text = content[pos : pos + len(keyword)]

                # Get context
                context_start = max(0, pos - 50)
                context_end = min(len(content), pos + len(keyword) + 50)
                context = content[context_start:context_end]

                dlp_match = DLPMatch(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    action=rule.action,
                    pattern_name=f"keyword:{keyword}",
                    matched_text=matched_text,
                    context=context,
                    position=pos,
                )

                matches.append(dlp_match)
                pos += len(keyword)

        return matches

    def add_rule(self, rule: DLPRule) -> None:
        """Add a rule to the engine.

        Args:
            rule: DLP rule to add
        """
        self.rules.append(rule)
        logger.info("dlp_rule_added", rule_id=rule.id, rule_name=rule.name)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule from the engine.

        Args:
            rule_id: Rule ID to remove

        Returns:
            True if removed, False if not found
        """
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                self.rules.pop(i)
                logger.info("dlp_rule_removed", rule_id=rule_id)
                return True

        return False

    def get_rule(self, rule_id: str) -> Optional[DLPRule]:
        """Get a rule by ID.

        Args:
            rule_id: Rule ID

        Returns:
            DLPRule or None
        """
        for rule in self.rules:
            if rule.id == rule_id:
                return rule

        return None

