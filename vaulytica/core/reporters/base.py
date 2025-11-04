"""Base reporter interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from vaulytica.core.scanners.file_scanner import FileInfo
from vaulytica.core.detectors.pii_detector import PIIDetectionResult


@dataclass
class ScanReport:
    """Represents a complete scan report."""

    scan_id: str
    scan_time: datetime
    domain: str
    files_scanned: int
    files_with_issues: int
    files: List[FileInfo] = field(default_factory=list)
    pii_results: Optional[dict] = None  # file_id -> PIIDetectionResult
    summary: dict = field(default_factory=dict)

    def calculate_summary(self) -> None:
        """Calculate summary statistics."""
        self.summary = {
            "total_files": len(self.files),
            "public_files": sum(1 for f in self.files if f.is_public),
            "externally_shared": sum(1 for f in self.files if f.is_shared_externally),
            "high_risk": sum(1 for f in self.files if f.risk_score >= 75),
            "medium_risk": sum(1 for f in self.files if 50 <= f.risk_score < 75),
            "low_risk": sum(1 for f in self.files if f.risk_score < 50),
        }

        if self.pii_results:
            self.summary["files_with_pii"] = sum(
                1 for result in self.pii_results.values() if result.total_matches > 0
            )
            self.summary["total_pii_matches"] = sum(
                result.total_matches for result in self.pii_results.values()
            )


class BaseReporter(ABC):
    """Base class for report generators."""

    def __init__(self, output_dir: Path):
        """Initialize reporter.

        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    def generate(self, report: ScanReport, output_file: Optional[Path] = None) -> Path:
        """Generate a report.

        Args:
            report: ScanReport to generate from
            output_file: Optional output file path

        Returns:
            Path to generated report file
        """
        pass

    def _get_output_path(
        self, report: ScanReport, extension: str, output_file: Optional[Path] = None
    ) -> Path:
        """Get output file path.

        Args:
            report: ScanReport
            extension: File extension (e.g., 'csv', 'json')
            output_file: Optional custom output file

        Returns:
            Path to output file
        """
        if output_file:
            return Path(output_file)

        timestamp = report.scan_time.strftime("%Y%m%d_%H%M%S")
        filename = f"vaulytica_report_{report.scan_id}_{timestamp}.{extension}"
        return self.output_dir / filename

