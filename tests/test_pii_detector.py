"""Tests for PII detector."""

import pytest

from vaulytica.core.detectors.pii_detector import (
    PIIDetector,
    PIIType,
    PIIMatch,
    PIIDetectionResult,
)


class TestPIIDetector:
    """Tests for PIIDetector."""

    def test_init_default(self):
        """Test PIIDetector initialization with defaults."""
        detector = PIIDetector()
        assert len(detector.enabled_patterns) > 0

    def test_init_with_specific_patterns(self):
        """Test PIIDetector with specific patterns."""
        detector = PIIDetector(enabled_patterns=["ssn", "email"])
        assert PIIType.SSN in detector.enabled_patterns
        assert PIIType.EMAIL in detector.enabled_patterns
        assert PIIType.CREDIT_CARD not in detector.enabled_patterns

    def test_detect_ssn(self):
        """Test detecting SSN."""
        detector = PIIDetector(enabled_patterns=["ssn"])
        content = "My SSN is 234-56-7890 for verification."

        result = detector.detect(content)

        assert result.total_matches >= 1
        assert PIIType.SSN in result.pii_types_found
        assert any("234-56-7890" in match.value for match in result.matches)

    def test_detect_ssn_formats(self):
        """Test detecting SSN in different formats."""
        detector = PIIDetector(enabled_patterns=["ssn"])

        test_cases = [
            "234-56-7890",  # Dashed
            "234 56 7890",  # Spaced
            "234567890",  # No separator
        ]

        for ssn in test_cases:
            content = f"SSN: {ssn}"
            result = detector.detect(content)
            assert result.total_matches >= 1, f"Failed to detect: {ssn}"

    def test_detect_credit_card(self):
        """Test detecting credit card numbers."""
        detector = PIIDetector(enabled_patterns=["credit_card"])

        # Valid Visa card (passes Luhn check)
        content = "Card: 4532-1488-0343-6467"
        result = detector.detect(content)

        assert result.total_matches >= 1
        assert PIIType.CREDIT_CARD in result.pii_types_found

    def test_detect_phone(self):
        """Test detecting phone numbers."""
        detector = PIIDetector(enabled_patterns=["phone"])

        test_cases = [
            "(123) 456-7890",
            "123-456-7890",
            "123.456.7890",
            "1234567890",
            "+1 123 456 7890",
        ]

        for phone in test_cases:
            content = f"Phone: {phone}"
            result = detector.detect(content)
            assert result.total_matches >= 1, f"Failed to detect: {phone}"

    def test_detect_email(self):
        """Test detecting email addresses."""
        detector = PIIDetector(enabled_patterns=["email"])

        test_cases = [
            "user@example.com",
            "john.doe@company.co.uk",
            "test+tag@domain.org",
        ]

        for email in test_cases:
            content = f"Email: {email}"
            result = detector.detect(content)
            assert result.total_matches >= 1, f"Failed to detect: {email}"
            assert PIIType.EMAIL in result.pii_types_found

    def test_detect_ip_address(self):
        """Test detecting IP addresses."""
        detector = PIIDetector(enabled_patterns=["ip_address"])

        content = "Server IP: 192.168.1.1"
        result = detector.detect(content)

        assert result.total_matches >= 1
        assert PIIType.IP_ADDRESS in result.pii_types_found

    def test_detect_multiple_types(self):
        """Test detecting multiple PII types in same content."""
        detector = PIIDetector(enabled_patterns=["ssn", "email", "phone"])

        content = """
        Contact: john@example.com
        Phone: 555-123-4567
        SSN: 234-56-7890
        """

        result = detector.detect(content)

        assert result.total_matches >= 3
        assert PIIType.SSN in result.pii_types_found
        assert PIIType.EMAIL in result.pii_types_found
        assert PIIType.PHONE in result.pii_types_found

    def test_detect_empty_content(self):
        """Test detecting PII in empty content."""
        detector = PIIDetector()
        result = detector.detect("")

        assert result.total_matches == 0
        assert len(result.pii_types_found) == 0

    def test_detect_no_pii(self):
        """Test detecting PII when none exists."""
        detector = PIIDetector()
        content = "This is just regular text with no PII."

        result = detector.detect(content)

        assert result.total_matches == 0

    def test_confidence_with_context(self):
        """Test that context keywords increase confidence."""
        detector = PIIDetector(enabled_patterns=["ssn"])

        # With context keyword
        content_with_context = "Social Security Number: 234-56-7890"
        result_with = detector.detect(content_with_context)

        # Without context keyword
        content_without = "Number: 234-56-7890"
        result_without = detector.detect(content_without)

        # Both should detect, but context should increase confidence
        assert result_with.total_matches >= 1
        assert result_without.total_matches >= 1

        if result_with.matches and result_without.matches:
            assert result_with.matches[0].confidence >= result_without.matches[0].confidence

    def test_validate_ssn_invalid(self):
        """Test SSN validation rejects invalid patterns."""
        detector = PIIDetector(enabled_patterns=["ssn"])

        invalid_ssns = [
            "000-00-0000",  # All zeros - should be completely rejected
            "666-12-3456",  # Starts with 666 - should have reduced confidence
            "900-12-3456",  # Starts with 900+ - should have reduced confidence
        ]

        for ssn in invalid_ssns:
            content = f"SSN: {ssn}"
            result = detector.detect(content)
            # All zeros should not be detected at all
            if ssn == "000-00-0000":
                assert result.total_matches == 0, f"Should completely reject: {ssn}"
            # Others should have reduced confidence (below high confidence threshold)
            elif result.matches:
                assert result.matches[0].confidence < 0.8, f"Should have reduced confidence: {ssn}"

    def test_context_window(self):
        """Test that context window is captured."""
        detector = PIIDetector(enabled_patterns=["email"])

        content = "Please contact us at support@example.com for assistance."
        result = detector.detect(content, context_window=20)

        assert result.total_matches >= 1
        match = result.matches[0]
        assert match.context is not None
        assert "support@example.com" in match.context


class TestPIIMatch:
    """Tests for PIIMatch dataclass."""

    def test_pii_match_creation(self):
        """Test creating PIIMatch."""
        match = PIIMatch(
            pii_type=PIIType.EMAIL,
            value="test@example.com",
            start_pos=10,
            end_pos=26,
            confidence=0.95,
            context="Email: test@example.com here",
        )

        assert match.pii_type == PIIType.EMAIL
        assert match.value == "test@example.com"
        assert match.confidence == 0.95


class TestPIIDetectionResult:
    """Tests for PIIDetectionResult."""

    def test_detection_result_creation(self):
        """Test creating PIIDetectionResult."""
        result = PIIDetectionResult()

        assert result.total_matches == 0
        assert result.high_confidence_matches == 0
        assert len(result.pii_types_found) == 0

    def test_add_match(self):
        """Test adding matches to result."""
        result = PIIDetectionResult()

        match1 = PIIMatch(
            pii_type=PIIType.EMAIL,
            value="test@example.com",
            start_pos=0,
            end_pos=16,
            confidence=0.95,
        )

        match2 = PIIMatch(
            pii_type=PIIType.SSN,
            value="123-45-6789",
            start_pos=20,
            end_pos=31,
            confidence=0.85,
        )

        result.add_match(match1)
        result.add_match(match2)

        assert result.total_matches == 2
        assert result.high_confidence_matches == 2
        assert PIIType.EMAIL in result.pii_types_found
        assert PIIType.SSN in result.pii_types_found

    def test_high_confidence_threshold(self):
        """Test high confidence match counting."""
        result = PIIDetectionResult()

        high_conf = PIIMatch(
            pii_type=PIIType.EMAIL,
            value="test@example.com",
            start_pos=0,
            end_pos=16,
            confidence=0.9,
        )

        low_conf = PIIMatch(
            pii_type=PIIType.PHONE,
            value="1234567890",
            start_pos=20,
            end_pos=30,
            confidence=0.6,
        )

        result.add_match(high_conf)
        result.add_match(low_conf)

        assert result.total_matches == 2
        assert result.high_confidence_matches == 1  # Only high_conf >= 0.8


class TestExpandedPIIDetection:
    """Tests for expanded PII detection patterns (20+ types)."""

    def test_detect_itin(self):
        """Test detecting ITIN (Individual Taxpayer Identification Number)."""
        detector = PIIDetector(enabled_patterns=["itin"])

        test_cases = [
            "ITIN: 900-70-1234",
            "Tax ID 912-34-5678",
            "900701234",
        ]

        for itin in test_cases:
            content = f"ITIN: {itin}"
            result = detector.detect(content)
            assert result.total_matches >= 1, f"Failed to detect ITIN: {itin}"

    def test_detect_ein(self):
        """Test detecting EIN (Employer Identification Number)."""
        detector = PIIDetector(enabled_patterns=["ein"])

        test_cases = [
            "EIN: 12-3456789",
            "Federal Tax ID 12-3456789",
            "123456789",
        ]

        for ein in test_cases:
            content = f"EIN: {ein}"
            result = detector.detect(content)
            assert result.total_matches >= 1, f"Failed to detect EIN: {ein}"

    def test_detect_bank_account(self):
        """Test detecting bank account numbers."""
        detector = PIIDetector(enabled_patterns=["bank_account"])

        test_cases = [
            "Account: 12345678",  # 8 digits
            "Account: 123456789012",  # 12 digits
            "Account: 12345678901234567",  # 17 digits
        ]

        for account in test_cases:
            content = f"Bank {account}"
            result = detector.detect(content)
            assert result.total_matches >= 1, f"Failed to detect: {account}"

    def test_detect_routing_number(self):
        """Test detecting routing numbers."""
        detector = PIIDetector(enabled_patterns=["routing_number"])

        content = "Routing: 123456789"
        result = detector.detect(content)
        assert result.total_matches >= 1

    def test_detect_medical_record_number(self):
        """Test detecting medical record numbers."""
        detector = PIIDetector(enabled_patterns=["medical_record"])

        test_cases = [
            "MRN: 1234567",
            "Medical Record #12345678",
            "Patient ID MR-123456789",
        ]

        for mrn in test_cases:
            content = mrn
            result = detector.detect(content)
            assert result.total_matches >= 1, f"Failed to detect: {mrn}"

    def test_detect_medicare_number(self):
        """Test detecting Medicare numbers."""
        detector = PIIDetector(enabled_patterns=["medicare"])

        test_cases = [
            "1234567A12",
            "123456789AB1234",
        ]

        for medicare in test_cases:
            content = f"Medicare: {medicare}"
            result = detector.detect(content)
            assert result.total_matches >= 1, f"Failed to detect: {medicare}"

    def test_detect_dea_number(self):
        """Test detecting DEA numbers."""
        detector = PIIDetector(enabled_patterns=["dea_number"])

        test_cases = [
            "AB1234567",
            "FG9876543",
        ]

        for dea in test_cases:
            content = f"DEA: {dea}"
            result = detector.detect(content)
            assert result.total_matches >= 1, f"Failed to detect: {dea}"

    def test_detect_date_of_birth(self):
        """Test detecting dates of birth."""
        detector = PIIDetector(enabled_patterns=["date_of_birth"])

        test_cases = [
            "DOB: 01/15/1990",
            "Born: 12-25-1985",
            "Birthday: 1995-06-30",
        ]

        for dob in test_cases:
            content = dob
            result = detector.detect(content)
            assert result.total_matches >= 1, f"Failed to detect: {dob}"

    def test_detect_vehicle_vin(self):
        """Test detecting Vehicle Identification Numbers."""
        detector = PIIDetector(enabled_patterns=["vehicle_vin"])

        test_cases = [
            "1HGBH41JXMN109186",
            "JH4KA7561PC008269",
        ]

        for vin in test_cases:
            content = f"VIN: {vin}"
            result = detector.detect(content)
            assert result.total_matches >= 1, f"Failed to detect: {vin}"

    def test_detect_mac_address(self):
        """Test detecting MAC addresses."""
        detector = PIIDetector(enabled_patterns=["mac_address"])

        test_cases = [
            "00:1B:44:11:3A:B7",
            "00-1B-44-11-3A-B7",
        ]

        for mac in test_cases:
            content = f"MAC: {mac}"
            result = detector.detect(content)
            assert result.total_matches >= 1, f"Failed to detect: {mac}"

    def test_detect_crypto_wallet(self):
        """Test detecting cryptocurrency wallet addresses."""
        detector = PIIDetector(enabled_patterns=["crypto_wallet"])

        test_cases = [
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",  # Bitcoin
            "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",  # Ethereum
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",  # Bitcoin bech32
        ]

        for wallet in test_cases:
            content = f"Wallet: {wallet}"
            result = detector.detect(content)
            assert result.total_matches >= 1, f"Failed to detect: {wallet}"

    def test_detect_passport(self):
        """Test detecting passport numbers."""
        detector = PIIDetector(enabled_patterns=["passport"])

        test_cases = [
            "A12345678",  # US passport
            "123456789",  # Numeric passport
        ]

        for passport in test_cases:
            content = f"Passport: {passport}"
            result = detector.detect(content)
            assert result.total_matches >= 1, f"Failed to detect: {passport}"

    def test_comprehensive_document_scan(self):
        """Test scanning a document with multiple PII types."""
        detector = PIIDetector()  # All patterns enabled

        content = """
        EMPLOYEE INFORMATION

        Name: John Doe
        SSN: 123-45-6789
        ITIN: 900-70-1234
        DOB: 01/15/1985
        Email: john.doe@company.com
        Phone: (555) 123-4567

        FINANCIAL INFORMATION
        Bank Account: 123456789012
        Routing Number: 987654321
        Credit Card: 4532-1488-0343-6467

        MEDICAL INFORMATION
        Medical Record: MRN-12345678
        Medicare: 1234567A12

        TECHNICAL INFORMATION
        IP Address: 192.168.1.100
        MAC Address: 00:1B:44:11:3A:B7

        VEHICLE
        VIN: 1HGBH41JXMN109186
        """

        result = detector.detect(content)

        # Should detect multiple types
        assert result.total_matches >= 10
        assert len(result.pii_types_found) >= 8

        # Verify specific types are found
        expected_types = [
            PIIType.SSN,
            PIIType.EMAIL,
            PIIType.PHONE,
            PIIType.BANK_ACCOUNT,
            PIIType.CREDIT_CARD,
            PIIType.IP_ADDRESS,
        ]

        for pii_type in expected_types:
            assert pii_type in result.pii_types_found, f"Missing: {pii_type.value}"

    def test_context_aware_confidence_boost(self):
        """Test that context keywords boost confidence scores."""
        detector = PIIDetector(enabled_patterns=["bank_account", "routing_number"])

        # With context
        content_with_context = "Bank Account Number: 123456789012"
        result_with = detector.detect(content_with_context)

        # Without context
        content_without = "Number: 123456789012"
        result_without = detector.detect(content_without)

        # Both should detect
        assert result_with.total_matches >= 1
        assert result_without.total_matches >= 1

        # Context should boost confidence
        if result_with.matches and result_without.matches:
            with_conf = max(m.confidence for m in result_with.matches)
            without_conf = max(m.confidence for m in result_without.matches)
            assert with_conf >= without_conf

    def test_no_false_positives_on_normal_text(self):
        """Test that normal text doesn't trigger false positives."""
        detector = PIIDetector()

        normal_text = """
        This is a regular business document about our company's
        quarterly performance. We saw growth in Q3 2024 and expect
        continued success in Q4. Our team of 150 employees worked
        hard to achieve these results.
        """

        result = detector.detect(normal_text)

        # Should have very few or no matches
        assert result.total_matches <= 2  # Allow for potential date/number matches


class TestPIIDetectorAdvanced:
    """Advanced tests for PII detector edge cases and optimizations."""

    def test_unknown_pattern_warning(self):
        """Test that unknown patterns trigger a warning."""
        # This should log a warning but not crash
        detector = PIIDetector(enabled_patterns=["ssn", "unknown_pattern_xyz"])

        # Should still work with valid patterns
        assert PIIType.SSN in detector.enabled_patterns
        # Unknown pattern should be ignored
        assert len(detector.enabled_patterns) >= 1

    def test_chunked_detection_large_content(self):
        """Test that large content is processed in chunks."""
        detector = PIIDetector(enabled_patterns=["email"])

        # Create content that will be processed in chunks
        chunk_size = 500  # Small chunk size for testing
        large_content = "Normal text. " * 50  # ~650 chars
        large_content += "Email: test1@example.com. "
        large_content += "Normal text. " * 50  # Another ~650 chars
        large_content += "Email: test2@example.com. "
        large_content += "Normal text. " * 50  # Another ~650 chars

        # Force chunked processing by using small chunk size
        result = detector.detect(large_content, chunk_size=chunk_size)

        # Should detect PII across chunks
        assert result.total_matches >= 2
        assert PIIType.EMAIL in result.pii_types_found

    def test_chunked_detection_boundary_handling(self):
        """Test that PII at chunk boundaries is detected correctly."""
        detector = PIIDetector(enabled_patterns=["email"])

        # Create content where email is near chunk boundary
        chunk_size = 100
        content = "x" * 85 + "Email: test@example.com" + "x" * 100

        result = detector.detect(content, chunk_size=chunk_size)

        # Should detect email even if it spans chunk boundary
        assert result.total_matches >= 1
        assert PIIType.EMAIL in result.pii_types_found

    def test_credit_card_luhn_validation(self):
        """Test credit card Luhn algorithm validation."""
        detector = PIIDetector(enabled_patterns=["credit_card"])

        # Valid Visa card (passes Luhn check)
        valid_card = "4532-1488-0343-6467"
        result_valid = detector.detect(f"Credit Card: {valid_card}")

        # Invalid card (fails Luhn check)
        invalid_card = "4532-1488-0343-6468"  # Last digit changed
        result_invalid = detector.detect(f"Number: {invalid_card}")

        # Both should be detected, but valid should have higher confidence
        assert result_valid.total_matches >= 1
        assert result_invalid.total_matches >= 1

        if result_valid.matches and result_invalid.matches:
            valid_conf = result_valid.matches[0].confidence
            invalid_conf = result_invalid.matches[0].confidence
            # Valid card with context should have higher confidence
            assert valid_conf >= invalid_conf

    def test_ssn_validation_edge_cases(self):
        """Test SSN validation for edge cases."""
        detector = PIIDetector(enabled_patterns=["ssn"])

        # Test case: 123456789 (sequential) - should be rejected
        content1 = "SSN: 123456789"
        result1 = detector.detect(content1)
        assert result1.total_matches == 0, "Sequential SSN should be rejected"

        # Test case: 666-12-3456 (starts with 666) - should have reduced confidence
        content2 = "SSN: 666-12-3456"
        result2 = detector.detect(content2)
        if result2.matches:
            assert result2.matches[0].confidence < 0.8, "666 SSN should have reduced confidence"

        # Test case: 900-12-3456 (starts with 900+) - should have reduced confidence
        content3 = "SSN: 900-12-3456"
        result3 = detector.detect(content3)
        if result3.matches:
            assert result3.matches[0].confidence < 0.8, "900+ SSN should have reduced confidence"

    def test_low_confidence_filtering(self):
        """Test that very low confidence matches are filtered out."""
        detector = PIIDetector(enabled_patterns=["bank_account"])

        # Bank account without context - low confidence
        content = "Number: 12345678"
        result = detector.detect(content)

        # Should detect but all matches should have confidence >= 0.5
        for match in result.matches:
            assert match.confidence >= 0.5

    def test_duplicate_detection_in_chunks(self):
        """Test that duplicates at chunk boundaries are handled."""
        detector = PIIDetector(enabled_patterns=["email"])

        # Create content where email appears at chunk boundary
        chunk_size = 100
        email = "test@example.com"
        content = "x" * 85 + f"Email: {email}" + "x" * 100

        result = detector.detect(content, chunk_size=chunk_size)

        # Should detect email (may be 1 or 2 depending on boundary handling)
        email_matches = [m for m in result.matches if m.pii_type == PIIType.EMAIL]
        assert len(email_matches) >= 1
        assert len(email_matches) <= 2  # Allow for boundary case

    def test_context_window_size(self):
        """Test different context window sizes."""
        detector = PIIDetector(enabled_patterns=["email"])

        content = "Please contact support@example.com for help with your account."

        # Small context window
        result_small = detector.detect(content, context_window=10)
        assert result_small.total_matches >= 1
        if result_small.matches:
            assert len(result_small.matches[0].context) <= 50  # Approximate

        # Large context window
        result_large = detector.detect(content, context_window=50)
        assert result_large.total_matches >= 1
        if result_large.matches:
            assert len(result_large.matches[0].context) >= len(result_small.matches[0].context)

    def test_multiple_same_type_matches(self):
        """Test detecting multiple instances of the same PII type."""
        detector = PIIDetector(enabled_patterns=["email"])

        content = """
        Contact: john@example.com
        CC: jane@example.com
        BCC: admin@example.com
        """

        result = detector.detect(content)

        # Should detect all 3 emails
        assert result.total_matches >= 3
        email_matches = [m for m in result.matches if m.pii_type == PIIType.EMAIL]
        assert len(email_matches) >= 3

    def test_pattern_with_special_characters(self):
        """Test patterns with special regex characters."""
        detector = PIIDetector(enabled_patterns=["ip_address"])

        # IPv4 with dots (special regex character)
        content = "Server: 192.168.1.1"
        result = detector.detect(content)

        assert result.total_matches >= 1
        assert PIIType.IP_ADDRESS in result.pii_types_found

    def test_case_insensitive_detection(self):
        """Test that detection is case-insensitive."""
        detector = PIIDetector(enabled_patterns=["dea_number"])

        test_cases = [
            "DEA: AB1234567",
            "dea: AB1234567",
            "Dea: AB1234567",
        ]

        for content in test_cases:
            result = detector.detect(content)
            assert result.total_matches >= 1, f"Failed for: {content}"

    def test_overlapping_patterns(self):
        """Test handling of overlapping pattern matches."""
        detector = PIIDetector(enabled_patterns=["routing_number", "bank_account"])

        # 9 digits could match both routing number and bank account
        content = "Account: 123456789"
        result = detector.detect(content)

        # Should detect at least one match
        assert result.total_matches >= 1

    def test_empty_enabled_patterns(self):
        """Test detector with empty pattern list."""
        detector = PIIDetector(enabled_patterns=[])

        content = "SSN: 123-45-6789, Email: test@example.com"
        result = detector.detect(content)

        # Should not detect anything
        assert result.total_matches == 0

    def test_all_patterns_enabled_by_default(self):
        """Test that all patterns are enabled by default."""
        detector = PIIDetector()

        # Should have all PIIType patterns enabled
        assert len(detector.enabled_patterns) == len(PIIType)

    def test_position_tracking(self):
        """Test that match positions are tracked correctly."""
        detector = PIIDetector(enabled_patterns=["email"])

        content = "Contact: test@example.com for help"
        result = detector.detect(content)

        assert result.total_matches >= 1
        match = result.matches[0]

        # Verify position
        assert match.start_pos >= 0
        assert match.end_pos > match.start_pos
        assert content[match.start_pos:match.end_pos] == match.value

