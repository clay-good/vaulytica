"""PII (Personally Identifiable Information) detection using regex patterns."""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Set

import structlog

logger = structlog.get_logger(__name__)


class PIIType(Enum):
    """Types of PII that can be detected."""

    SSN = "ssn"
    ITIN = "itin"  # Individual Taxpayer Identification Number
    EIN = "ein"  # Employer Identification Number
    CREDIT_CARD = "credit_card"
    PHONE = "phone"
    EMAIL = "email"
    BANK_ACCOUNT = "bank_account"
    ROUTING_NUMBER = "routing_number"
    PASSPORT = "passport"
    DRIVERS_LICENSE = "drivers_license"
    IP_ADDRESS = "ip_address"
    MEDICAL_RECORD = "medical_record_number"
    HEALTH_INSURANCE = "health_insurance_number"
    MEDICARE = "medicare_number"
    MEDICAID = "medicaid_number"
    DEA_NUMBER = "dea_number"  # Drug Enforcement Administration
    NPI = "npi"  # National Provider Identifier
    DATE_OF_BIRTH = "date_of_birth"
    VEHICLE_VIN = "vehicle_vin"
    MAC_ADDRESS = "mac_address"
    CRYPTO_WALLET = "crypto_wallet_address"


@dataclass
class PIIMatch:
    """Represents a PII match found in content."""

    pii_type: PIIType
    value: str
    start_pos: int
    end_pos: int
    confidence: float  # 0.0 to 1.0
    context: Optional[str] = None  # Surrounding text for context


@dataclass
class PIIDetectionResult:
    """Results from PII detection."""

    matches: List[PIIMatch] = field(default_factory=list)
    pii_types_found: Set[PIIType] = field(default_factory=set)
    total_matches: int = 0
    high_confidence_matches: int = 0

    def add_match(self, match: PIIMatch) -> None:
        """Add a match to the results."""
        self.matches.append(match)
        self.pii_types_found.add(match.pii_type)
        self.total_matches += 1
        if match.confidence >= 0.8:
            self.high_confidence_matches += 1

    def _update_stats(self) -> None:
        """Update statistics from matches list."""
        self.pii_types_found = set()
        self.total_matches = len(self.matches)
        self.high_confidence_matches = 0

        for match in self.matches:
            self.pii_types_found.add(match.pii_type)
            if match.confidence >= 0.8:
                self.high_confidence_matches += 1


class PIIDetector:
    """Detects PII in text content using regex patterns."""

    # Regex patterns for different PII types
    PATTERNS = {
        PIIType.SSN: [
            # SSN: 123-45-6789 or 123 45 6789 or 123456789
            (r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b", 0.9),
        ],
        PIIType.ITIN: [
            # ITIN: 9XX-XX-XXXX (starts with 9)
            (r"\b9\d{2}[-\s]?\d{2}[-\s]?\d{4}\b", 0.85),
        ],
        PIIType.EIN: [
            # EIN: XX-XXXXXXX (Employer Identification Number)
            (r"\b\d{2}[-\s]?\d{7}\b", 0.7),
        ],
        PIIType.CREDIT_CARD: [
            # Visa: 4xxx-xxxx-xxxx-xxxx
            (r"\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", 0.85),
            # Mastercard: 5xxx-xxxx-xxxx-xxxx
            (r"\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", 0.85),
            # Amex: 3xxx-xxxxxx-xxxxx
            (r"\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b", 0.85),
            # Discover: 6xxx-xxxx-xxxx-xxxx
            (r"\b6(?:011|5\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", 0.85),
            # Generic 16-digit card
            (r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", 0.6),
        ],
        PIIType.PHONE: [
            # US phone: (123) 456-7890, 123-456-7890, 123.456.7890, 1234567890
            (r"\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b", 0.8),
            # International: +XX XXX XXX XXXX
            (r"\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}", 0.7),
        ],
        PIIType.EMAIL: [
            # Email address
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", 0.95),
        ],
        PIIType.BANK_ACCOUNT: [
            # Bank account: 8-17 digits
            (r"\b\d{8,17}\b", 0.5),  # Low confidence without context
        ],
        PIIType.ROUTING_NUMBER: [
            # US routing number: 9 digits
            (r"\b\d{9}\b", 0.5),  # Low confidence without context
        ],
        PIIType.PASSPORT: [
            # US Passport: 9 digits or 1 letter + 8 digits
            (r"\b[A-Z]\d{8}\b", 0.7),
            (r"\b\d{9}\b", 0.4),  # Could be other things
        ],
        PIIType.IP_ADDRESS: [
            # IPv4 address
            (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", 0.9),
            # IPv6 address (simplified)
            (r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", 0.9),
        ],
        PIIType.MEDICAL_RECORD: [
            # Medical Record Number: typically 6-10 digits with optional prefix
            (r"\b(?:MRN|MR|MEDICAL)[-\s]?#?[-\s]?\d{6,10}\b", 0.8),
            (r"\b\d{6,10}\b", 0.4),  # Low confidence without context
        ],
        PIIType.HEALTH_INSURANCE: [
            # Health Insurance Number: varies by provider, typically alphanumeric
            (r"\b[A-Z]{2,3}\d{8,12}\b", 0.6),
        ],
        PIIType.MEDICARE: [
            # Medicare Number: 1-9 digits + 1-2 letters + 2-4 digits
            (r"\b\d{1,9}[A-Z]{1,2}\d{2,4}\b", 0.85),
        ],
        PIIType.MEDICAID: [
            # Medicaid Number: varies by state, typically 8-14 alphanumeric
            # Must have at least 2 digits and at least 1 letter to avoid matching pure words/numbers
            # This is a very low confidence pattern - should only match with strong context
            (r"\b(?=.*[A-Z])(?=.*\d.*\d)[A-Z0-9]{8,14}\b", 0.3),  # Very low confidence without context
        ],
        PIIType.DEA_NUMBER: [
            # DEA Number: 2 letters + 7 digits
            (r"\b[A-Z]{2}\d{7}\b", 0.8),
        ],
        PIIType.NPI: [
            # National Provider Identifier: 10 digits
            (r"\b\d{10}\b", 0.5),  # Low confidence without context
        ],
        PIIType.DATE_OF_BIRTH: [
            # DOB: MM/DD/YYYY, MM-DD-YYYY, YYYY-MM-DD
            (r"\b(?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12][0-9]|3[01])[-/](?:19|20)\d{2}\b", 0.85),
            (r"\b(?:19|20)\d{2}[-/](?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12][0-9]|3[01])\b", 0.85),
        ],
        PIIType.VEHICLE_VIN: [
            # Vehicle Identification Number: 17 alphanumeric characters
            (r"\b[A-HJ-NPR-Z0-9]{17}\b", 0.8),
        ],
        PIIType.MAC_ADDRESS: [
            # MAC Address: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
            (r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", 0.95),
        ],
        PIIType.CRYPTO_WALLET: [
            # Bitcoin legacy address: 26-35 alphanumeric starting with 1 or 3
            (r"\b[13][a-zA-Z0-9]{25,34}\b", 0.8),
            # Bitcoin bech32 address: bc1 followed by 39-59 alphanumeric (lowercase)
            (r"\bbc1[a-z0-9]{39,59}\b", 0.85),
            # Ethereum address: 0x followed by 38-42 hex characters (allows for some variation)
            (r"\b0x[a-fA-F0-9]{38,42}\b", 0.9),
        ],
    }

    # Context keywords that increase confidence
    CONTEXT_KEYWORDS = {
        PIIType.SSN: ["ssn", "social security", "social-security", "ss#"],
        PIIType.ITIN: ["itin", "taxpayer id", "tax id"],
        PIIType.EIN: ["ein", "employer id", "federal tax", "fein"],
        PIIType.CREDIT_CARD: ["card", "credit", "visa", "mastercard", "amex", "discover", "payment"],
        PIIType.PHONE: ["phone", "tel", "mobile", "cell", "contact", "call"],
        PIIType.BANK_ACCOUNT: ["account", "bank", "checking", "savings", "account number"],
        PIIType.ROUTING_NUMBER: ["routing", "aba", "bank", "routing number"],
        PIIType.PASSPORT: ["passport", "travel document", "passport number"],
        PIIType.MEDICAL_RECORD: ["mrn", "medical record", "patient id", "chart number"],
        PIIType.HEALTH_INSURANCE: ["insurance", "policy", "member id", "subscriber"],
        PIIType.MEDICARE: ["medicare", "cms", "health insurance"],
        PIIType.MEDICAID: ["medicaid", "medical assistance"],
        PIIType.DEA_NUMBER: ["dea", "drug enforcement", "prescriber"],
        PIIType.NPI: ["npi", "provider", "national provider"],
        PIIType.DATE_OF_BIRTH: ["dob", "birth", "birthday", "born"],
        PIIType.VEHICLE_VIN: ["vin", "vehicle", "car", "automobile"],
        PIIType.MAC_ADDRESS: ["mac", "hardware", "network", "adapter"],
        PIIType.CRYPTO_WALLET: ["bitcoin", "btc", "ethereum", "eth", "wallet", "crypto"],
    }

    # Mapping from short names to PIIType enums for easier test usage
    PATTERN_NAME_MAP = {
        "ssn": PIIType.SSN,
        "itin": PIIType.ITIN,
        "ein": PIIType.EIN,
        "credit_card": PIIType.CREDIT_CARD,
        "phone": PIIType.PHONE,
        "email": PIIType.EMAIL,
        "bank_account": PIIType.BANK_ACCOUNT,
        "routing_number": PIIType.ROUTING_NUMBER,
        "passport": PIIType.PASSPORT,
        "drivers_license": PIIType.DRIVERS_LICENSE,
        "ip_address": PIIType.IP_ADDRESS,
        "medical_record": PIIType.MEDICAL_RECORD,
        "medical_record_number": PIIType.MEDICAL_RECORD,
        "health_insurance": PIIType.HEALTH_INSURANCE,
        "health_insurance_number": PIIType.HEALTH_INSURANCE,
        "medicare": PIIType.MEDICARE,
        "medicare_number": PIIType.MEDICARE,
        "medicaid": PIIType.MEDICAID,
        "medicaid_number": PIIType.MEDICAID,
        "dea_number": PIIType.DEA_NUMBER,
        "npi": PIIType.NPI,
        "date_of_birth": PIIType.DATE_OF_BIRTH,
        "dob": PIIType.DATE_OF_BIRTH,
        "vehicle_vin": PIIType.VEHICLE_VIN,
        "vin": PIIType.VEHICLE_VIN,
        "mac_address": PIIType.MAC_ADDRESS,
        "crypto_wallet": PIIType.CRYPTO_WALLET,
        "crypto_wallet_address": PIIType.CRYPTO_WALLET,
    }

    def __init__(self, enabled_patterns: Optional[List[str]] = None):
        """Initialize PII detector.

        Args:
            enabled_patterns: List of PII pattern names to enable (default: all)
        """
        self.enabled_patterns = set()

        if enabled_patterns is not None:
            # Convert string names to PIIType enums
            for pattern_name in enabled_patterns:
                pattern_key = pattern_name.lower()

                # Try direct enum value lookup first
                try:
                    pii_type = PIIType(pattern_key)
                    self.enabled_patterns.add(pii_type)
                    continue
                except ValueError:
                    pass

                # Try pattern name map
                if pattern_key in self.PATTERN_NAME_MAP:
                    self.enabled_patterns.add(self.PATTERN_NAME_MAP[pattern_key])
                else:
                    logger.warning("unknown_pii_pattern", pattern=pattern_name)
        else:
            # Enable all patterns by default
            self.enabled_patterns = set(PIIType)

        logger.info("pii_detector_initialized", enabled_patterns=len(self.enabled_patterns))

    def _detect_chunked(self, content: str, context_window: int, chunk_size: int) -> PIIDetectionResult:
        """Detect PII in large content using chunked processing.

        Args:
            content: Text content to scan
            context_window: Number of characters to include in context
            chunk_size: Size of each chunk

        Returns:
            PIIDetectionResult with all matches found
        """
        result = PIIDetectionResult()
        overlap = min(context_window * 2, chunk_size // 2)  # Overlap to catch patterns at chunk boundaries, but not more than half chunk

        logger.info("pii_detection_chunked", content_size=len(content), chunk_size=chunk_size)

        # Process content in overlapping chunks
        offset = 0
        while offset < len(content):
            chunk_end = min(offset + chunk_size, len(content))
            chunk = content[offset:chunk_end]

            # Detect PII in this chunk
            chunk_result = self._detect_in_chunk(chunk, context_window, offset)

            # Merge results, avoiding duplicates at boundaries
            for match in chunk_result.matches:
                # Check if this match is a duplicate from overlap region
                is_duplicate = False
                for existing_match in result.matches:
                    if (existing_match.pii_type == match.pii_type and
                        existing_match.value == match.value and
                        abs(existing_match.start_pos - match.start_pos) < overlap):
                        is_duplicate = True
                        break

                if not is_duplicate:
                    result.matches.append(match)

            # Move to next chunk with overlap (ensure we always make progress)
            step = max(1, chunk_size - overlap)
            offset += step

        # Update result statistics
        result._update_stats()

        return result

    def _detect_in_chunk(self, content: str, context_window: int, offset: int) -> PIIDetectionResult:
        """Detect PII in a single chunk.

        Args:
            content: Text chunk to scan
            context_window: Number of characters to include in context
            offset: Offset of this chunk in the original content

        Returns:
            PIIDetectionResult with matches found in this chunk
        """
        result = PIIDetectionResult()

        # Scan for each enabled PII type
        for pii_type in self.enabled_patterns:
            if pii_type not in self.PATTERNS:
                continue

            patterns = self.PATTERNS[pii_type]

            for pattern, base_confidence in patterns:
                try:
                    regex = re.compile(pattern, re.IGNORECASE)

                    for match in regex.finditer(content):
                        value = match.group(0)
                        start_pos = match.start() + offset  # Adjust for chunk offset
                        end_pos = match.end() + offset

                        # Get context (within chunk)
                        context_start = max(0, match.start() - context_window)
                        context_end = min(len(content), match.end() + context_window)
                        context = content[context_start:context_end]

                        # Adjust confidence based on context
                        confidence = self._calculate_confidence(
                            pii_type, value, context, base_confidence
                        )

                        # Only include matches with reasonable confidence
                        if confidence >= 0.5:
                            pii_match = PIIMatch(
                                pii_type=pii_type,
                                value=value,
                                start_pos=start_pos,
                                end_pos=end_pos,
                                context=context,
                                confidence=confidence,
                            )
                            result.matches.append(pii_match)

                except Exception as e:
                    logger.error("pii_pattern_error", pii_type=pii_type.value, error=str(e))

        return result

    def detect(self, content: str, context_window: int = 50, chunk_size: int = 1000000) -> PIIDetectionResult:
        """Detect PII in content.

        Args:
            content: Text content to scan
            context_window: Number of characters to include in context
            chunk_size: Size of chunks for processing large content (default: 1MB)

        Returns:
            PIIDetectionResult with all matches found
        """
        if not content:
            return PIIDetectionResult()

        # For large content, process in chunks to reduce memory usage
        if len(content) > chunk_size:
            return self._detect_chunked(content, context_window, chunk_size)

        result = PIIDetectionResult()

        # Scan for each enabled PII type
        for pii_type in self.enabled_patterns:
            if pii_type not in self.PATTERNS:
                continue

            patterns = self.PATTERNS[pii_type]

            for pattern, base_confidence in patterns:
                try:
                    regex = re.compile(pattern, re.IGNORECASE)

                    for match in regex.finditer(content):
                        value = match.group(0)
                        start_pos = match.start()
                        end_pos = match.end()

                        # Get context
                        context_start = max(0, start_pos - context_window)
                        context_end = min(len(content), end_pos + context_window)
                        context = content[context_start:context_end]

                        # Adjust confidence based on context
                        confidence = self._calculate_confidence(
                            pii_type, value, context, base_confidence
                        )

                        # Only include matches with reasonable confidence
                        if confidence >= 0.5:
                            pii_match = PIIMatch(
                                pii_type=pii_type,
                                value=value,
                                start_pos=start_pos,
                                end_pos=end_pos,
                                confidence=confidence,
                                context=context,
                            )
                            result.add_match(pii_match)

                except re.error as e:
                    logger.error("regex_error", pattern=pattern, error=str(e))

        logger.info(
            "pii_detection_complete",
            total_matches=result.total_matches,
            high_confidence=result.high_confidence_matches,
            types_found=len(result.pii_types_found),
        )

        return result

    def _calculate_confidence(
        self, pii_type: PIIType, value: str, context: str, base_confidence: float
    ) -> float:
        """Calculate confidence score based on context.

        Args:
            pii_type: Type of PII
            value: Matched value
            context: Surrounding text
            base_confidence: Base confidence from pattern

        Returns:
            Adjusted confidence score (0.0 to 1.0)
        """
        confidence = base_confidence

        # Check for context keywords
        if pii_type in self.CONTEXT_KEYWORDS:
            context_lower = context.lower()
            for keyword in self.CONTEXT_KEYWORDS[pii_type]:
                if keyword in context_lower:
                    confidence = min(1.0, confidence + 0.1)
                    break

        # Additional validation for specific types
        if pii_type == PIIType.SSN:
            confidence = self._validate_ssn(value, confidence)
        elif pii_type == PIIType.CREDIT_CARD:
            confidence = self._validate_credit_card(value, confidence)

        return confidence

    def _validate_ssn(self, value: str, confidence: float) -> float:
        """Validate SSN format and adjust confidence.

        Args:
            value: SSN value
            confidence: Current confidence

        Returns:
            Adjusted confidence
        """
        # Remove separators
        digits = re.sub(r"[-\s]", "", value)

        # Invalid SSN patterns - completely reject these
        if digits == "000000000" or digits == "123456789":
            return 0.0

        # First 3 digits can't be 000, 666, or 900-999
        # Reduce confidence significantly for invalid patterns
        first_three = int(digits[:3])
        if first_three == 0 or first_three == 666 or first_three >= 900:
            return max(0.5, confidence - 0.3)  # Reduce more to stay below 0.8 even with context boost

        return confidence

    def _validate_credit_card(self, value: str, confidence: float) -> float:
        """Validate credit card using Luhn algorithm.

        Args:
            value: Credit card number
            confidence: Current confidence

        Returns:
            Adjusted confidence
        """
        # Remove separators
        digits = re.sub(r"[-\s]", "", value)

        # Luhn algorithm
        def luhn_check(card_number: str) -> bool:
            def digits_of(n):
                return [int(d) for d in str(n)]

            digits = digits_of(card_number)
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(digits_of(d * 2))
            return checksum % 10 == 0

        if luhn_check(digits):
            return min(1.0, confidence + 0.1)
        else:
            return max(0.0, confidence - 0.3)

