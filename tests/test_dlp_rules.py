"""Tests for DLP rules engine."""

from pathlib import Path

import pytest
import yaml

from vaulytica.core.dlp.rules import (
    RuleAction,
    RuleSeverity,
    DLPPattern,
    DLPRule,
    DLPEngine,
)


class TestDLPPattern:
    """Test DLP pattern matching."""

    def test_create_pattern(self):
        """Test creating a DLP pattern."""
        pattern = DLPPattern(
            name="SSN",
            pattern=r"\d{3}-\d{2}-\d{4}",
            case_sensitive=False,
            whole_word=False,
        )

        assert pattern.name == "SSN"
        assert pattern.pattern == r"\d{3}-\d{2}-\d{4}"
        assert pattern.case_sensitive is False

    def test_pattern_matching_basic(self):
        """Test basic pattern matching."""
        pattern = DLPPattern(
            name="Email",
            pattern=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        )

        text = "Contact me at user@company.com for more information."

        matches = list(pattern.regex.finditer(text))

        assert len(matches) == 1
        assert "user@company.com" in matches[0].group(0)

    def test_pattern_case_sensitivity(self):
        """Test case sensitive pattern matching."""
        pattern_sensitive = DLPPattern(
            name="Test",
            pattern="SENSITIVE",
            case_sensitive=True,
        )

        pattern_insensitive = DLPPattern(
            name="Test",
            pattern="SENSITIVE",
            case_sensitive=False,
        )

        text = "This is sensitive data"

        # Case sensitive should not match
        matches_sensitive = list(pattern_sensitive.regex.finditer(text))
        assert len(matches_sensitive) == 0

        # Case insensitive should match
        matches_insensitive = list(pattern_insensitive.regex.finditer(text))
        assert len(matches_insensitive) == 1

    def test_pattern_whole_word_matching(self):
        """Test whole word pattern matching."""
        pattern_whole_word = DLPPattern(
            name="Test",
            pattern="secret",
            whole_word=True,
        )

        pattern_partial = DLPPattern(
            name="Test",
            pattern="secret",
            whole_word=False,
        )

        text = "This is a secret and also secretive information."

        # Whole word should match once
        matches_whole = list(pattern_whole_word.regex.finditer(text))
        assert len(matches_whole) == 1

        # Partial should match twice (secret and secretive)
        matches_partial = list(pattern_partial.regex.finditer(text))
        assert len(matches_partial) == 2

    def test_ssn_pattern(self):
        """Test SSN pattern matching."""
        pattern = DLPPattern(
            name="SSN",
            pattern=r"\d{3}-\d{2}-\d{4}",
        )

        text = "Employee SSN: 123-45-6789"

        matches = list(pattern.regex.finditer(text))

        assert len(matches) == 1
        assert "123-45-6789" in matches[0].group(0)

    def test_credit_card_pattern(self):
        """Test credit card pattern matching."""
        pattern = DLPPattern(
            name="Credit Card",
            pattern=r"\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}",
        )

        text = "Card number: 1234-5678-9012-3456"

        matches = list(pattern.regex.finditer(text))

        assert len(matches) == 1


class TestDLPRule:
    """Test DLP rules."""

    def test_create_rule(self):
        """Test creating a DLP rule."""
        pattern = DLPPattern(name="SSN", pattern=r"\d{3}-\d{2}-\d{4}")

        rule = DLPRule(
            id="rule001",
            name="Detect SSN",
            description="Detect Social Security Numbers",
            patterns=[pattern],
            action=RuleAction.ALERT,
            severity=RuleSeverity.HIGH,
            enabled=True,
        )

        assert rule.id == "rule001"
        assert rule.name == "Detect SSN"
        assert rule.action == RuleAction.ALERT
        assert rule.severity == RuleSeverity.HIGH
        assert rule.enabled is True

    def test_rule_matching(self):
        """Test rule matching against content."""
        pattern = DLPPattern(name="SSN", pattern=r"\d{3}-\d{2}-\d{4}")

        rule = DLPRule(
            id="rule001",
            name="Detect SSN",
            description="Detect Social Security Numbers",
            patterns=[pattern],
            action=RuleAction.ALERT,
            severity=RuleSeverity.HIGH,
            enabled=True,
        )

        text = "Employee records: SSN 123-45-6789, DOB 01/01/1990"

        # Use DLPEngine to test rule matching
        engine = DLPEngine(rules=[rule])
        result = engine.scan_content(text, "test_file", "test.txt")

        assert result is not None
        assert len(result.matches) > 0

    def test_disabled_rule(self):
        """Test that disabled rules don't match."""
        pattern = DLPPattern(name="SSN", pattern=r"\d{3}-\d{2}-\d{4}")

        rule = DLPRule(
            id="rule001",
            name="Detect SSN",
            description="Detect Social Security Numbers",
            patterns=[pattern],
            action=RuleAction.ALERT,
            severity=RuleSeverity.HIGH,
            enabled=False,  # Disabled
        )

        text = "SSN: 123-45-6789"

        # Use DLPEngine to test disabled rule
        engine = DLPEngine(rules=[rule])
        result = engine.scan_content(text, "test_file", "test.txt")

        # Disabled rule should not generate matches
        assert len(result.matches) == 0


class TestDLPEngine:
    """Test DLP rules engine."""

    def test_create_engine(self):
        """Test creating a DLP rules engine."""
        engine = DLPEngine()

        assert engine is not None
        assert len(engine.rules) == 0

    def test_add_rule(self):
        """Test adding a rule to the engine."""
        engine = DLPEngine()

        pattern = DLPPattern(name="SSN", pattern=r"\d{3}-\d{2}-\d{4}")

        rule = DLPRule(
            id="rule001",
            name="Detect SSN",
            description="Detect Social Security Numbers",
            patterns=[pattern],
            action=RuleAction.ALERT,
            severity=RuleSeverity.HIGH,
            enabled=True,
        )

        engine.add_rule(rule)

        assert len(engine.rules) == 1
        assert engine.rules[0].id == "rule001"

    def test_scan_content(self):
        """Test scanning content with rules."""
        engine = DLPEngine()

        # Add SSN rule
        ssn_pattern = DLPPattern(name="SSN", pattern=r"\d{3}-\d{2}-\d{4}")
        ssn_rule = DLPRule(
            id="rule001",
            name="Detect SSN",
            description="Detect Social Security Numbers",
            patterns=[ssn_pattern],
            action=RuleAction.ALERT,
            severity=RuleSeverity.HIGH,
            enabled=True,
        )
        engine.add_rule(ssn_rule)

        # Add email rule
        email_pattern = DLPPattern(
            name="Email",
            pattern=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        )
        email_rule = DLPRule(
            id="rule002",
            name="Detect Email",
            description="Detect email addresses",
            patterns=[email_pattern],
            action=RuleAction.LOG,
            severity=RuleSeverity.MEDIUM,
            enabled=True,
        )
        engine.add_rule(email_rule)

        text = "Employee: John Doe, SSN: 123-45-6789, Email: john@company.com"

        result = engine.scan_content(text, "test_file", "test.txt")

        assert len(result.matches) == 2  # Should detect both SSN and email
        assert any(v.rule_id == "rule001" for v in result.matches)
        assert any(v.rule_id == "rule002" for v in result.matches)

    def test_load_rules_from_yaml(self, tmp_path):
        """Test loading rules from YAML file."""
        rules_yaml = """
rules:
  - id: rule001
    name: Detect SSN
    description: Detect Social Security Numbers
    patterns:
      - name: SSN
        pattern: "\\\\d{3}-\\\\d{2}-\\\\d{4}"
        case_sensitive: false
    action: alert
    severity: high
    enabled: true

  - id: rule002
    name: Detect Email
    description: Detect email addresses
    patterns:
      - name: Email
        pattern: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\\\.[a-zA-Z]{2,}"
        case_sensitive: false
    action: log
    severity: medium
    enabled: true
"""

        rules_file = tmp_path / "dlp_rules.yaml"
        rules_file.write_text(rules_yaml)

        engine = DLPEngine.from_yaml(str(rules_file))

        assert len(engine.rules) == 2
        assert engine.rules[0].id == "rule001"
        assert engine.rules[1].id == "rule002"

    def test_rule_action_execution(self):
        """Test rule action execution."""
        engine = DLPEngine()

        pattern = DLPPattern(name="SSN", pattern=r"\d{3}-\d{2}-\d{4}")

        # Alert action
        alert_rule = DLPRule(
            id="rule001",
            name="Alert on SSN",
            description="Alert when SSN detected",
            patterns=[pattern],
            action=RuleAction.ALERT,
            severity=RuleSeverity.CRITICAL,
            enabled=True,
        )

        # Block action
        block_rule = DLPRule(
            id="rule002",
            name="Block SSN",
            description="Block when SSN detected",
            patterns=[pattern],
            action=RuleAction.BLOCK,
            severity=RuleSeverity.CRITICAL,
            enabled=True,
        )

        engine.add_rule(alert_rule)
        engine.add_rule(block_rule)

        text = "SSN: 123-45-6789"

        result = engine.scan_content(text, "test_file", "test.txt")

        # Should have matches for both rules
        assert len(result.matches) == 2
        assert any(v.action == RuleAction.ALERT for v in result.matches)
        assert any(v.action == RuleAction.BLOCK for v in result.matches)


class TestRuleActions:
    """Test different rule actions."""

    def test_alert_action(self):
        """Test ALERT action."""
        action = RuleAction.ALERT
        assert action.value == "alert"

    def test_block_action(self):
        """Test BLOCK action."""
        action = RuleAction.BLOCK
        assert action.value == "block"

    def test_quarantine_action(self):
        """Test QUARANTINE action."""
        action = RuleAction.QUARANTINE
        assert action.value == "quarantine"

    def test_log_action(self):
        """Test LOG action."""
        action = RuleAction.LOG
        assert action.value == "log"


class TestRuleSeverity:
    """Test rule severity levels."""

    def test_critical_severity(self):
        """Test CRITICAL severity."""
        severity = RuleSeverity.CRITICAL
        assert severity.value == "critical"

    def test_high_severity(self):
        """Test HIGH severity."""
        severity = RuleSeverity.HIGH
        assert severity.value == "high"

    def test_medium_severity(self):
        """Test MEDIUM severity."""
        severity = RuleSeverity.MEDIUM
        assert severity.value == "medium"

    def test_low_severity(self):
        """Test LOW severity."""
        severity = RuleSeverity.LOW
        assert severity.value == "low"


class TestCustomPatterns:
    """Test custom industry-specific patterns."""

    def test_employee_id_pattern(self):
        """Test employee ID pattern."""
        pattern = DLPPattern(
            name="Employee ID",
            pattern=r"EMP-\d{6}",
        )

        text = "Employee ID: EMP-123456"

        matches = list(pattern.regex.finditer(text))

        assert len(matches) == 1
        assert "EMP-123456" in matches[0].group(0)

    def test_medical_record_number(self):
        """Test medical record number pattern."""
        pattern = DLPPattern(
            name="MRN",
            pattern=r"MRN-\d{8}",
        )

        text = "Medical Record: MRN-12345678"

        matches = list(pattern.regex.finditer(text))

        assert len(matches) == 1

    def test_patient_id_pattern(self):
        """Test patient ID pattern."""
        pattern = DLPPattern(
            name="Patient ID",
            pattern=r"PT\d{7}",
        )

        text = "Patient: PT1234567"

        matches = list(pattern.regex.finditer(text))

        assert len(matches) == 1


class TestRulePerformance:
    """Test DLP rules engine performance."""

    def test_scan_large_document(self):
        """Test scanning large documents."""
        engine = DLPEngine()

        pattern = DLPPattern(name="SSN", pattern=r"\d{3}-\d{2}-\d{4}")
        rule = DLPRule(
            id="rule001",
            name="Detect SSN",
            description="Detect Social Security Numbers",
            patterns=[pattern],
            action=RuleAction.ALERT,
            severity=RuleSeverity.HIGH,
            enabled=True,
        )
        engine.add_rule(rule)

        # Create large document (10,000 lines)
        large_text = "Line with no PII.\n" * 9990 + "SSN: 123-45-6789\n" * 10

        import time
        start = time.time()
        result = engine.scan_content(large_text, "large_file", "large.txt")
        duration = time.time() - start

        # Should complete quickly (< 1 second)
        assert duration < 1.0
        assert len(result.matches) > 0

    def test_multiple_rules_performance(self):
        """Test performance with many rules."""
        engine = DLPEngine()

        # Add 10 different rules
        patterns_and_rules = [
            ("SSN", r"\d{3}-\d{2}-\d{4}"),
            ("Email", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
            ("Phone", r"\d{3}-\d{3}-\d{4}"),
            ("ZIP", r"\d{5}"),
            ("CC", r"\d{4}-\d{4}-\d{4}-\d{4}"),
        ]

        for i, (name, regex) in enumerate(patterns_and_rules):
            pattern = DLPPattern(name=name, pattern=regex)
            rule = DLPRule(
                id=f"rule{i:03d}",
                name=f"Detect {name}",
                description=f"Detect {name} patterns",
                patterns=[pattern],
                action=RuleAction.LOG,
                severity=RuleSeverity.MEDIUM,
                enabled=True,
            )
            engine.add_rule(rule)

        text = "SSN: 123-45-6789, Email: user@company.com, Phone: 555-123-4567"

        import time
        start = time.time()
        result = engine.scan_content(text, "test_file", "test.txt")
        duration = time.time() - start

        # Should complete quickly even with multiple rules
        assert duration < 0.5
        assert len(result.matches) >= 3  # Should detect SSN, email, and phone
