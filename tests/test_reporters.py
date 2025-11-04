"""Tests for report generators."""

import json
import csv
import pytest
from datetime import datetime, timezone
from pathlib import Path

from vaulytica.core.reporters.base import ScanReport
from vaulytica.core.reporters.csv_reporter import CSVReporter
from vaulytica.core.reporters.json_reporter import JSONReporter
from vaulytica.core.scanners.file_scanner import FileInfo, FilePermission
from vaulytica.core.detectors.pii_detector import PIIDetectionResult, PIIMatch, PIIType


@pytest.fixture
def sample_scan_report():
    """Create a sample scan report for testing."""
    file1 = FileInfo(
        id="file1",
        name="test1.pdf",
        mime_type="application/pdf",
        owner_email="owner@example.com",
        owner_name="Owner",
        created_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        modified_time=datetime(2024, 1, 2, tzinfo=timezone.utc),
        size=1024,
        is_public=True,
        risk_score=100,
    )

    file2 = FileInfo(
        id="file2",
        name="test2.docx",
        mime_type="application/vnd.google-apps.document",
        owner_email="owner@example.com",
        owner_name="Owner",
        created_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
        modified_time=datetime(2024, 1, 2, tzinfo=timezone.utc),
        size=2048,
        is_shared_externally=True,
        external_domains=["other.com"],
        external_emails=["user@other.com"],
        risk_score=60,
    )

    report = ScanReport(
        scan_id="test123",
        scan_time=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        domain="example.com",
        files_scanned=100,
        files_with_issues=2,
        files=[file1, file2],
    )

    report.calculate_summary()
    return report


class TestScanReport:
    """Tests for ScanReport."""

    def test_calculate_summary(self, sample_scan_report):
        """Test summary calculation."""
        summary = sample_scan_report.summary

        assert summary["total_files"] == 2
        assert summary["public_files"] == 1
        assert summary["externally_shared"] == 1
        assert summary["high_risk"] == 1
        assert summary["medium_risk"] == 1
        assert summary["low_risk"] == 0


class TestCSVReporter:
    """Tests for CSVReporter."""

    def test_init(self, tmp_path):
        """Test CSVReporter initialization."""
        reporter = CSVReporter(tmp_path)
        assert reporter.output_dir == tmp_path
        assert reporter.output_dir.exists()

    def test_generate_csv(self, tmp_path, sample_scan_report):
        """Test generating CSV report."""
        reporter = CSVReporter(tmp_path)
        output_path = reporter.generate(sample_scan_report)

        assert output_path.exists()
        assert output_path.suffix == ".csv"

        # Read and verify CSV content
        with open(output_path, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            rows = list(reader)

            assert len(rows) == 2

            # Check first file (public)
            assert rows[0]["file_id"] == "file1"
            assert rows[0]["file_name"] == "test1.pdf"
            assert rows[0]["is_public"] == "Yes"
            assert rows[0]["risk_level"] == "HIGH"

            # Check second file (external)
            assert rows[1]["file_id"] == "file2"
            assert rows[1]["is_shared_externally"] == "Yes"
            assert rows[1]["risk_level"] == "MEDIUM"

    def test_generate_csv_custom_path(self, tmp_path, sample_scan_report):
        """Test generating CSV with custom output path."""
        reporter = CSVReporter(tmp_path)
        custom_path = tmp_path / "custom_report.csv"

        output_path = reporter.generate(sample_scan_report, output_file=custom_path)

        assert output_path == custom_path
        assert output_path.exists()

    def test_generate_summary(self, tmp_path, sample_scan_report):
        """Test generating summary CSV."""
        reporter = CSVReporter(tmp_path)
        output_path = reporter.generate_summary(sample_scan_report)

        assert output_path.exists()
        assert "summary" in output_path.name

        # Read and verify summary content
        with open(output_path, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            rows = list(reader)

            # Check that summary metrics are present
            metrics = {row["metric"]: row["value"] for row in rows}
            assert "Scan ID" in metrics
            assert metrics["Scan ID"] == "test123"
            assert "Total Files" in metrics
            assert metrics["Total Files"] == "2"

    def test_generate_csv_with_pii(self, tmp_path, sample_scan_report):
        """Test generating CSV with PII data."""
        # Add PII results to report
        pii_result = PIIDetectionResult()
        pii_match = PIIMatch(
            pii_type=PIIType.EMAIL,
            value="test@example.com",
            start_pos=0,
            end_pos=16,
            confidence=0.95,
            context="Email: test@example.com",
        )
        pii_result.add_match(pii_match)

        sample_scan_report.pii_results = {"file1": pii_result}
        sample_scan_report.calculate_summary()

        reporter = CSVReporter(tmp_path)
        output_path = reporter.generate(sample_scan_report)

        # Read and verify PII data
        with open(output_path, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            rows = list(reader)

            # Check first file has PII
            assert rows[0]["has_pii"] == "Yes"
            assert "email" in rows[0]["pii_types"]
            assert rows[0]["pii_count"] == "1"

            # Check second file has no PII
            assert rows[1]["has_pii"] == "No"
            assert rows[1]["pii_types"] == ""
            assert rows[1]["pii_count"] == "0"

    def test_generate_summary_with_pii(self, tmp_path, sample_scan_report):
        """Test generating summary CSV with PII data."""
        # Add PII results to report
        pii_result = PIIDetectionResult()
        pii_match = PIIMatch(
            pii_type=PIIType.SSN,
            value="123-45-6789",
            start_pos=0,
            end_pos=11,
            confidence=0.95,
            context="SSN: 123-45-6789",
        )
        pii_result.add_match(pii_match)

        sample_scan_report.pii_results = {"file1": pii_result}
        sample_scan_report.calculate_summary()

        reporter = CSVReporter(tmp_path)
        output_path = reporter.generate_summary(sample_scan_report)

        # Read and verify PII metrics are included
        with open(output_path, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            rows = list(reader)

            metrics = {row["metric"]: row["value"] for row in rows}
            assert "Files with PII" in metrics
            assert "Total PII Matches" in metrics

    def test_generate_csv_without_summary(self, tmp_path, sample_scan_report):
        """Test generating CSV when summary hasn't been calculated."""
        # Clear summary to test auto-calculation
        sample_scan_report.summary = {}

        reporter = CSVReporter(tmp_path)
        output_path = reporter.generate(sample_scan_report)

        assert output_path.exists()
        # Summary should be auto-calculated
        assert sample_scan_report.summary

    def test_generate_summary_without_summary(self, tmp_path, sample_scan_report):
        """Test generating summary CSV when summary hasn't been calculated."""
        # Clear summary to test auto-calculation
        sample_scan_report.summary = {}

        reporter = CSVReporter(tmp_path)
        output_path = reporter.generate_summary(sample_scan_report)

        assert output_path.exists()
        # Summary should be auto-calculated
        assert sample_scan_report.summary

    def test_generate_csv_low_risk_file(self, tmp_path):
        """Test generating CSV with low risk file."""
        file_info = FileInfo(
            id="file3",
            name="test3.txt",
            mime_type="text/plain",
            owner_email="owner@example.com",
            owner_name="Owner",
            created_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            modified_time=datetime(2024, 1, 2, tzinfo=timezone.utc),
            size=100,
            risk_score=25,  # Low risk
        )

        report = ScanReport(
            scan_id="test456",
            scan_time=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            domain="example.com",
            files_scanned=1,
            files_with_issues=0,
            files=[file_info],
        )
        report.calculate_summary()

        reporter = CSVReporter(tmp_path)
        output_path = reporter.generate(report)

        # Read and verify risk level
        with open(output_path, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            rows = list(reader)

            assert rows[0]["risk_level"] == "LOW"
            assert rows[0]["risk_score"] == "25"

    def test_generate_summary_custom_path(self, tmp_path, sample_scan_report):
        """Test generating summary CSV with custom output path."""
        reporter = CSVReporter(tmp_path)
        custom_path = tmp_path / "custom_summary.csv"

        output_path = reporter.generate_summary(sample_scan_report, output_file=custom_path)

        assert output_path == custom_path
        assert output_path.exists()


class TestJSONReporter:
    """Tests for JSONReporter."""

    def test_init(self, tmp_path):
        """Test JSONReporter initialization."""
        reporter = JSONReporter(tmp_path)
        assert reporter.output_dir == tmp_path
        assert reporter.output_dir.exists()

    def test_generate_json(self, tmp_path, sample_scan_report):
        """Test generating JSON report."""
        reporter = JSONReporter(tmp_path)
        output_path = reporter.generate(sample_scan_report)

        assert output_path.exists()
        assert output_path.suffix == ".json"

        # Read and verify JSON content
        with open(output_path, "r", encoding="utf-8") as jsonfile:
            data = json.load(jsonfile)

            assert data["scan_id"] == "test123"
            assert data["domain"] == "example.com"
            assert data["files_scanned"] == 100
            assert data["files_with_issues"] == 2
            assert len(data["files"]) == 2

            # Check first file
            file1 = data["files"][0]
            assert file1["id"] == "file1"
            assert file1["name"] == "test1.pdf"
            assert file1["sharing"]["is_public"] is True
            assert file1["risk"]["level"] == "HIGH"
            assert file1["risk"]["score"] == 100

            # Check second file
            file2 = data["files"][1]
            assert file2["id"] == "file2"
            assert file2["sharing"]["is_shared_externally"] is True
            assert "other.com" in file2["sharing"]["external_domains"]

    def test_generate_json_custom_path(self, tmp_path, sample_scan_report):
        """Test generating JSON with custom output path."""
        reporter = JSONReporter(tmp_path)
        custom_path = tmp_path / "custom_report.json"

        output_path = reporter.generate(sample_scan_report, output_file=custom_path)

        assert output_path == custom_path
        assert output_path.exists()

    def test_generate_json_with_pii(self, tmp_path, sample_scan_report):
        """Test generating JSON report with PII data."""
        # Add PII results to report
        pii_result = PIIDetectionResult()
        pii_match = PIIMatch(
            pii_type=PIIType.EMAIL,
            value="test@example.com",
            start_pos=0,
            end_pos=16,
            confidence=0.95,
            context="Email: test@example.com",
        )
        pii_result.add_match(pii_match)

        sample_scan_report.pii_results = {"file1": pii_result}
        sample_scan_report.calculate_summary()

        reporter = JSONReporter(tmp_path)
        output_path = reporter.generate(sample_scan_report)

        # Read and verify PII data
        with open(output_path, "r", encoding="utf-8") as jsonfile:
            data = json.load(jsonfile)

            file1 = data["files"][0]
            assert "pii" in file1
            assert file1["pii"]["total_matches"] == 1
            assert "email" in file1["pii"]["types_found"]
            assert len(file1["pii"]["matches"]) == 1
            assert file1["pii"]["matches"][0]["type"] == "email"

    def test_json_structure(self, tmp_path, sample_scan_report):
        """Test JSON report structure."""
        reporter = JSONReporter(tmp_path)
        output_path = reporter.generate(sample_scan_report)

        with open(output_path, "r", encoding="utf-8") as jsonfile:
            data = json.load(jsonfile)

            # Check top-level structure
            assert "scan_id" in data
            assert "scan_time" in data
            assert "domain" in data
            assert "files_scanned" in data
            assert "files_with_issues" in data
            assert "summary" in data
            assert "files" in data

            # Check file structure
            file = data["files"][0]
            assert "id" in file
            assert "name" in file
            assert "owner" in file
            assert "sharing" in file
            assert "risk" in file

            # Check owner structure
            assert "email" in file["owner"]
            assert "name" in file["owner"]

            # Check sharing structure
            assert "is_public" in file["sharing"]
            assert "is_shared_externally" in file["sharing"]
            assert "permissions" in file["sharing"]

            # Check risk structure
            assert "score" in file["risk"]
            assert "level" in file["risk"]

    def test_json_without_summary(self, tmp_path, sample_scan_report):
        """Test generating JSON when summary hasn't been calculated."""
        # Clear summary to test auto-calculation
        sample_scan_report.summary = {}

        reporter = JSONReporter(tmp_path)
        output_path = reporter.generate(sample_scan_report)

        assert output_path.exists()
        # Summary should be auto-calculated
        assert sample_scan_report.summary

        with open(output_path, "r", encoding="utf-8") as jsonfile:
            data = json.load(jsonfile)
            assert "summary" in data
            assert data["summary"]

    def test_json_low_risk_file(self, tmp_path):
        """Test generating JSON with low risk file."""
        file_info = FileInfo(
            id="file3",
            name="test3.txt",
            mime_type="text/plain",
            owner_email="owner@example.com",
            owner_name="Owner",
            created_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            modified_time=datetime(2024, 1, 2, tzinfo=timezone.utc),
            size=100,
            risk_score=25,  # Low risk
        )

        report = ScanReport(
            scan_id="test456",
            scan_time=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            domain="example.com",
            files_scanned=1,
            files_with_issues=0,
            files=[file_info],
        )
        report.calculate_summary()

        reporter = JSONReporter(tmp_path)
        output_path = reporter.generate(report)

        # Read and verify risk level
        with open(output_path, "r", encoding="utf-8") as jsonfile:
            data = json.load(jsonfile)

            file = data["files"][0]
            assert file["risk"]["level"] == "LOW"
            assert file["risk"]["score"] == 25

    def test_json_permission_conversion(self, tmp_path):
        """Test JSON permission conversion."""
        permission = FilePermission(
            id="perm1",
            type="user",
            role="reader",
            email_address="user@example.com",
            domain="example.com",
            display_name="Test User",
            deleted=False,
        )

        file_info = FileInfo(
            id="file4",
            name="test4.txt",
            mime_type="text/plain",
            owner_email="owner@example.com",
            owner_name="Owner",
            created_time=datetime(2024, 1, 1, tzinfo=timezone.utc),
            modified_time=datetime(2024, 1, 2, tzinfo=timezone.utc),
            size=100,
            risk_score=50,
            permissions=[permission],
        )

        report = ScanReport(
            scan_id="test789",
            scan_time=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
            domain="example.com",
            files_scanned=1,
            files_with_issues=0,
            files=[file_info],
        )
        report.calculate_summary()

        reporter = JSONReporter(tmp_path)
        output_path = reporter.generate(report)

        # Read and verify permission data
        with open(output_path, "r", encoding="utf-8") as jsonfile:
            data = json.load(jsonfile)

            file = data["files"][0]
            assert len(file["sharing"]["permissions"]) == 1
            perm = file["sharing"]["permissions"][0]
            assert perm["id"] == "perm1"
            assert perm["type"] == "user"
            assert perm["role"] == "reader"
            assert perm["email_address"] == "user@example.com"
            assert perm["domain"] == "example.com"
            assert perm["display_name"] == "Test User"
            assert perm["deleted"] is False

