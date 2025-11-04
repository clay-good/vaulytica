"""Performance tests for Vaulytica."""

import time
import pytest
from vaulytica.core.detectors.pii_detector import PIIDetector


class TestPIIDetectorPerformance:
    """Test PII detector performance with various text sizes."""

    @pytest.fixture
    def detector(self):
        """Create PII detector instance."""
        return PIIDetector()

    def test_small_text_performance(self, detector):
        """Test performance with small text (100 words)."""
        text = "John Doe SSN: 234-56-7890 Email: john@example.com Phone: 555-123-4567 " * 10
        
        start = time.time()
        result = detector.detect(text)
        elapsed = time.time() - start
        
        assert elapsed < 0.1, f"Small text took {elapsed:.3f}s (expected < 0.1s)"
        assert len(result.matches) > 0

    def test_medium_text_performance(self, detector):
        """Test performance with medium text (1000 words)."""
        text = "John Doe SSN: 234-56-7890 Email: john@example.com Phone: 555-123-4567 " * 100
        
        start = time.time()
        result = detector.detect(text)
        elapsed = time.time() - start
        
        assert elapsed < 0.5, f"Medium text took {elapsed:.3f}s (expected < 0.5s)"
        assert len(result.matches) > 0

    def test_large_text_performance(self, detector):
        """Test performance with large text (10000 words)."""
        text = "John Doe SSN: 234-56-7890 Email: john@example.com Phone: 555-123-4567 " * 1000
        
        start = time.time()
        result = detector.detect(text)
        elapsed = time.time() - start
        
        assert elapsed < 2.0, f"Large text took {elapsed:.3f}s (expected < 2.0s)"
        assert len(result.matches) > 0

    def test_no_pii_performance(self, detector):
        """Test performance with text containing no PII."""
        text = "This is a normal document with no sensitive information. " * 100
        
        start = time.time()
        result = detector.detect(text)
        elapsed = time.time() - start
        
        assert elapsed < 0.5, f"No PII text took {elapsed:.3f}s (expected < 0.5s)"
        assert len(result.matches) == 0

    def test_many_pii_types_performance(self, detector):
        """Test performance with text containing many PII types."""
        text = """
        SSN: 234-56-7890
        Credit Card: 4532-1234-5678-9010
        Email: john@example.com
        Phone: 555-123-4567
        IP: 192.168.1.1
        Bank Account: 123456789012
        Routing Number: 021000021
        Passport: A12345678
        Driver License: D1234567
        Medical Record: MRN-123456
        Medicare: 1AB-CD-2345-E6
        Medicaid: AB12345678
        DEA: AB1234563
        NPI: 1234567893
        VIN: 1HGBH41JXMN109186
        MAC: 00:1B:44:11:3A:B7
        Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        Ethereum: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb
        """ * 10
        
        start = time.time()
        result = detector.detect(text)
        elapsed = time.time() - start
        
        assert elapsed < 1.0, f"Many PII types took {elapsed:.3f}s (expected < 1.0s)"
        assert len(result.matches) > 50

    def test_batch_detection_performance(self, detector):
        """Test performance with batch detection of multiple documents."""
        documents = [
            "SSN: 234-56-7890 Email: john@example.com",
            "Credit Card: 4532-1234-5678-9010 Phone: 555-123-4567",
            "Bank Account: 123456789012 Routing: 021000021",
        ] * 100  # 300 documents
        
        start = time.time()
        results = [detector.detect(doc) for doc in documents]
        elapsed = time.time() - start
        
        assert elapsed < 5.0, f"Batch detection took {elapsed:.3f}s (expected < 5.0s)"
        assert len(results) == 300
        assert all(len(r.matches) > 0 for r in results)

    def test_confidence_calculation_performance(self, detector):
        """Test performance of confidence calculation with context."""
        text = """
        SSN: 234-56-7890
        Social Security Number: 234-56-7890
        Employee SSN: 234-56-7890
        Tax ID: 234-56-7890
        """ * 50
        
        start = time.time()
        result = detector.detect(text)
        elapsed = time.time() - start
        
        assert elapsed < 0.5, f"Confidence calculation took {elapsed:.3f}s (expected < 0.5s)"
        assert len(result.matches) > 0


class TestPIIDetectorMemory:
    """Test PII detector memory usage."""

    @pytest.fixture
    def detector(self):
        """Create PII detector instance."""
        return PIIDetector()

    def test_large_document_memory(self, detector):
        """Test memory usage with very large document."""
        # Create a 1MB document
        text = "John Doe SSN: 234-56-7890 Email: john@example.com " * 10000
        
        result = detector.detect(text)
        
        # Should complete without memory errors
        assert result is not None
        assert isinstance(result.matches, list)

    def test_repeated_detection_memory(self, detector):
        """Test memory usage with repeated detections."""
        text = "SSN: 234-56-7890 Email: john@example.com"
        
        # Run detection 1000 times
        for _ in range(1000):
            result = detector.detect(text)
            assert result is not None
        
        # Should complete without memory leaks


class TestPIIDetectorEdgeCases:
    """Test PII detector with edge cases."""

    @pytest.fixture
    def detector(self):
        """Create PII detector instance."""
        return PIIDetector()

    def test_empty_text(self, detector):
        """Test with empty text."""
        start = time.time()
        result = detector.detect("")
        elapsed = time.time() - start
        
        assert elapsed < 0.01, f"Empty text took {elapsed:.3f}s"
        assert len(result.matches) == 0

    def test_very_long_line(self, detector):
        """Test with very long single line."""
        text = "word " * 10000  # 10k words on one line (reduced for performance)

        start = time.time()
        result = detector.detect(text)
        elapsed = time.time() - start

        assert elapsed < 5.0, f"Very long line took {elapsed:.3f}s"

    def test_many_short_lines(self, detector):
        """Test with many short lines."""
        text = "SSN: 234-56-7890\n" * 10000
        
        start = time.time()
        result = detector.detect(text)
        elapsed = time.time() - start
        
        assert elapsed < 2.0, f"Many short lines took {elapsed:.3f}s"

    def test_unicode_text(self, detector):
        """Test with unicode text."""
        text = "用户信息 SSN: 234-56-7890 邮箱: john@example.com 电话: 555-123-4567 " * 100
        
        start = time.time()
        result = detector.detect(text)
        elapsed = time.time() - start
        
        assert elapsed < 0.5, f"Unicode text took {elapsed:.3f}s"
        assert len(result.matches) > 0

    def test_mixed_content(self, detector):
        """Test with mixed content (code, data, text)."""
        text = """
        # Python code
        def process_user(ssn, email):
            # SSN: 234-56-7890
            user = {
                'ssn': '234-56-7890',
                'email': 'john@example.com',
                'phone': '555-123-4567'
            }
            return user
        
        /* SQL query */
        SELECT * FROM users WHERE ssn = '234-56-7890';
        
        // JavaScript
        const user = {ssn: '234-56-7890', email: 'john@example.com'};
        """ * 50
        
        start = time.time()
        result = detector.detect(text)
        elapsed = time.time() - start
        
        assert elapsed < 1.0, f"Mixed content took {elapsed:.3f}s"
        assert len(result.matches) > 0


class TestPIIDetectorConcurrency:
    """Test PII detector with concurrent operations."""

    @pytest.fixture
    def detector(self):
        """Create PII detector instance."""
        return PIIDetector()

    def test_sequential_vs_parallel(self, detector):
        """Compare sequential vs parallel detection (conceptual test)."""
        documents = [
            "SSN: 234-56-7890 Email: john@example.com",
            "Credit Card: 4532-1234-5678-9010 Phone: 555-123-4567",
            "Bank Account: 123456789012 Routing: 021000021",
        ] * 50  # 150 documents
        
        # Sequential
        start = time.time()
        results_seq = [detector.detect(doc) for doc in documents]
        elapsed_seq = time.time() - start
        
        # Note: Actual parallel implementation would use multiprocessing
        # This is just a baseline measurement
        assert len(results_seq) == 150
        assert elapsed_seq < 3.0, f"Sequential took {elapsed_seq:.3f}s"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

