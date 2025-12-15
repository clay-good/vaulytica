"""PII (Personally Identifiable Information) detection using regex patterns."""

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import structlog
import yaml

logger = structlog.get_logger(__name__)

# Default path for PII patterns configuration
DEFAULT_PII_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "pii_patterns.yaml"


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
    """Detects PII in text content using regex patterns.

    Patterns can be loaded from a YAML configuration file or use built-in defaults.
    The configuration file allows customization of patterns, confidence scores,
    and context keywords without code changes.
    """

    # Default regex patterns for different PII types (used as fallback)
    DEFAULT_PATTERNS: Dict[PIIType, List[tuple]] = {
        PIIType.SSN: [
            (r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b", 0.9),
        ],
        PIIType.ITIN: [
            (r"\b9\d{2}[-\s]?\d{2}[-\s]?\d{4}\b", 0.85),
        ],
        PIIType.EIN: [
            (r"\b\d{2}[-\s]?\d{7}\b", 0.7),
        ],
        PIIType.CREDIT_CARD: [
            (r"\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", 0.85),
            (r"\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", 0.85),
            (r"\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b", 0.85),
            (r"\b6(?:011|5\d{2})[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", 0.85),
            (r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", 0.6),
        ],
        PIIType.PHONE: [
            (r"\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b", 0.8),
            (r"\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}", 0.7),
        ],
        PIIType.EMAIL: [
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", 0.95),
        ],
        PIIType.BANK_ACCOUNT: [
            (r"\b\d{8,17}\b", 0.5),
        ],
        PIIType.ROUTING_NUMBER: [
            (r"\b\d{9}\b", 0.5),
        ],
        PIIType.PASSPORT: [
            (r"\b[A-Z]\d{8}\b", 0.7),
            (r"\b\d{9}\b", 0.4),
        ],
        PIIType.IP_ADDRESS: [
            (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", 0.9),
            (r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", 0.9),
        ],
        PIIType.MEDICAL_RECORD: [
            (r"\b(?:MRN|MR|MEDICAL)[-\s]?#?[-\s]?\d{6,10}\b", 0.8),
            (r"\b\d{6,10}\b", 0.4),
        ],
        PIIType.HEALTH_INSURANCE: [
            (r"\b[A-Z]{2,3}\d{8,12}\b", 0.6),
        ],
        PIIType.MEDICARE: [
            (r"\b\d{1,9}[A-Z]{1,2}\d{2,4}\b", 0.85),
        ],
        PIIType.MEDICAID: [
            (r"\b(?=.*[A-Z])(?=.*\d.*\d)[A-Z0-9]{8,14}\b", 0.3),
        ],
        PIIType.DEA_NUMBER: [
            (r"\b[A-Z]{2}\d{7}\b", 0.8),
        ],
        PIIType.NPI: [
            (r"\b\d{10}\b", 0.5),
        ],
        PIIType.DATE_OF_BIRTH: [
            (r"\b(?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12][0-9]|3[01])[-/](?:19|20)\d{2}\b", 0.85),
            (r"\b(?:19|20)\d{2}[-/](?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12][0-9]|3[01])\b", 0.85),
        ],
        PIIType.VEHICLE_VIN: [
            (r"\b[A-HJ-NPR-Z0-9]{17}\b", 0.8),
        ],
        PIIType.MAC_ADDRESS: [
            (r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", 0.95),
        ],
        PIIType.CRYPTO_WALLET: [
            (r"\b[13][a-zA-Z0-9]{25,34}\b", 0.8),
            (r"\bbc1[a-z0-9]{39,59}\b", 0.85),
            (r"\b0x[a-fA-F0-9]{38,42}\b", 0.9),
        ],
    }

    # Default context keywords that increase confidence
    DEFAULT_CONTEXT_KEYWORDS: Dict[PIIType, List[str]] = {
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
    PATTERN_NAME_MAP: Dict[str, PIIType] = {
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

    # Class-level backwards compatibility aliases
    PATTERNS = DEFAULT_PATTERNS
    CONTEXT_KEYWORDS = DEFAULT_CONTEXT_KEYWORDS

    def __init__(
        self,
        enabled_patterns: Optional[List[str]] = None,
        config_path: Optional[Path] = None,
    ):
        """Initialize PII detector.

        Args:
            enabled_patterns: List of PII pattern names to enable (default: all from config)
            config_path: Path to YAML configuration file (default: built-in config)
        """
        # Load patterns from config file or use defaults
        self._load_config(config_path)

        self.enabled_patterns: Set[PIIType] = set()

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
            # Enable all patterns that are enabled in config
            self.enabled_patterns = set(self.patterns.keys())

        logger.info(
            "pii_detector_initialized",
            enabled_patterns=len(self.enabled_patterns),
            config_loaded=self._config_loaded,
        )

    def _load_config(self, config_path: Optional[Path] = None) -> None:
        """Load PII patterns from YAML configuration file.

        Args:
            config_path: Path to YAML config file (default: built-in config)
        """
        self._config_loaded = False
        self.patterns: Dict[PIIType, List[tuple]] = {}
        self.context_keywords: Dict[PIIType, List[str]] = {}
        self.min_confidence: Dict[PIIType, float] = {}
        self.validate_luhn: Set[PIIType] = set()
        self.custom_patterns: Dict[str, Dict[str, Any]] = {}

        # Determine config path
        if config_path is None:
            config_path = DEFAULT_PII_CONFIG_PATH

        # Try to load from config file
        if config_path.exists():
            try:
                with open(config_path, "r") as f:
                    config = yaml.safe_load(f)

                if config:
                    self._parse_config(config)
                    self._config_loaded = True
                    logger.info("pii_config_loaded", path=str(config_path))
                    return
            except Exception as e:
                logger.warning(
                    "pii_config_load_failed",
                    path=str(config_path),
                    error=str(e),
                )

        # Fall back to defaults
        logger.info("pii_using_default_patterns")
        self.patterns = self.DEFAULT_PATTERNS.copy()
        self.context_keywords = self.DEFAULT_CONTEXT_KEYWORDS.copy()
        self.min_confidence = {pii_type: 0.5 for pii_type in PIIType}
        self.validate_luhn.add(PIIType.CREDIT_CARD)

    def _parse_config(self, config: Dict[str, Any]) -> None:
        """Parse YAML configuration into internal structures.

        Args:
            config: Parsed YAML configuration dictionary
        """
        # Map config keys to PIIType enums
        config_to_pii_type = {
            "ssn": PIIType.SSN,
            "itin": PIIType.ITIN,
            "ein": PIIType.EIN,
            "credit_card": PIIType.CREDIT_CARD,
            "bank_account": PIIType.BANK_ACCOUNT,
            "routing_number": PIIType.ROUTING_NUMBER,
            "phone": PIIType.PHONE,
            "email": PIIType.EMAIL,
            "medical_record": PIIType.MEDICAL_RECORD,
            "health_insurance": PIIType.HEALTH_INSURANCE,
            "medicare": PIIType.MEDICARE,
            "medicaid": PIIType.MEDICAID,
            "dea_number": PIIType.DEA_NUMBER,
            "npi": PIIType.NPI,
            "passport": PIIType.PASSPORT,
            "drivers_license": PIIType.DRIVERS_LICENSE,
            "date_of_birth": PIIType.DATE_OF_BIRTH,
            "ip_address": PIIType.IP_ADDRESS,
            "mac_address": PIIType.MAC_ADDRESS,
            "vehicle_vin": PIIType.VEHICLE_VIN,
            "crypto_wallet": PIIType.CRYPTO_WALLET,
        }

        for config_key, pii_type in config_to_pii_type.items():
            if config_key not in config:
                # Use defaults for missing patterns
                if pii_type in self.DEFAULT_PATTERNS:
                    self.patterns[pii_type] = self.DEFAULT_PATTERNS[pii_type]
                if pii_type in self.DEFAULT_CONTEXT_KEYWORDS:
                    self.context_keywords[pii_type] = self.DEFAULT_CONTEXT_KEYWORDS[pii_type]
                self.min_confidence[pii_type] = 0.5
                continue

            pattern_config = config[config_key]

            # Skip disabled patterns
            if not pattern_config.get("enabled", True):
                continue

            # Parse patterns
            pattern_list = []
            for p in pattern_config.get("patterns", []):
                pattern_str = p.get("pattern", "")
                confidence = p.get("confidence", 0.5)
                if pattern_str:
                    pattern_list.append((pattern_str, confidence))

            if pattern_list:
                self.patterns[pii_type] = pattern_list
            elif pii_type in self.DEFAULT_PATTERNS:
                # Use default if no patterns defined
                self.patterns[pii_type] = self.DEFAULT_PATTERNS[pii_type]

            # Parse context keywords
            keywords = pattern_config.get("context_keywords", [])
            if keywords:
                self.context_keywords[pii_type] = keywords
            elif pii_type in self.DEFAULT_CONTEXT_KEYWORDS:
                self.context_keywords[pii_type] = self.DEFAULT_CONTEXT_KEYWORDS[pii_type]

            # Parse min_confidence
            self.min_confidence[pii_type] = pattern_config.get("min_confidence", 0.5)

            # Parse special validation flags
            if pattern_config.get("validate_luhn", False):
                self.validate_luhn.add(pii_type)

        # Parse custom patterns
        if "custom" in config and config["custom"]:
            self.custom_patterns = config["custom"]
            logger.info("custom_patterns_loaded", count=len(self.custom_patterns))

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
            if pii_type not in self.patterns:
                continue

            patterns = self.patterns[pii_type]
            min_conf = self.min_confidence.get(pii_type, 0.5)

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

                        # Only include matches above minimum confidence threshold
                        if confidence >= min_conf:
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
            if pii_type not in self.patterns:
                continue

            patterns = self.patterns[pii_type]
            min_conf = self.min_confidence.get(pii_type, 0.5)

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

                        # Only include matches above minimum confidence threshold
                        if confidence >= min_conf:
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
        if pii_type in self.context_keywords:
            context_lower = context.lower()
            for keyword in self.context_keywords[pii_type]:
                if keyword in context_lower:
                    confidence = min(1.0, confidence + 0.1)
                    break

        # Additional validation for specific types
        if pii_type == PIIType.SSN:
            confidence = self._validate_ssn(value, confidence)
        elif pii_type == PIIType.CREDIT_CARD and pii_type in self.validate_luhn:
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

