"""JSON report generator."""

import json
from pathlib import Path
from typing import Optional, Any, Dict

import structlog

from vaulytica.core.reporters.base import BaseReporter, ScanReport
from vaulytica.core.scanners.file_scanner import FileInfo, FilePermission
from vaulytica.core.detectors.pii_detector import PIIDetectionResult, PIIMatch

logger = structlog.get_logger(__name__)


class JSONReporter(BaseReporter):
    """Generates JSON reports from scan results."""

    def generate(self, report: ScanReport, output_file: Optional[Path] = None) -> Path:
        """Generate a JSON report.

        Args:
            report: ScanReport to generate from
            output_file: Optional output file path

        Returns:
            Path to generated JSON file
        """
        output_path = self._get_output_path(report, "json", output_file)

        logger.info("generating_json_report", output_path=str(output_path))

        # Calculate summary if not already done
        if not report.summary:
            report.calculate_summary()

        # Build JSON structure
        report_data = {
            "scan_id": report.scan_id,
            "scan_time": report.scan_time.isoformat(),
            "domain": report.domain,
            "files_scanned": report.files_scanned,
            "files_with_issues": report.files_with_issues,
            "summary": report.summary,
            "files": [self._file_to_dict(file_info, report) for file_info in report.files],
        }

        # Write JSON file
        with open(output_path, "w", encoding="utf-8") as jsonfile:
            json.dump(report_data, jsonfile, indent=2, ensure_ascii=False)

        logger.info(
            "json_report_generated",
            output_path=str(output_path),
            file_count=len(report.files),
        )

        return output_path

    def _file_to_dict(self, file_info: FileInfo, report: ScanReport) -> Dict[str, Any]:
        """Convert FileInfo to dictionary.

        Args:
            file_info: FileInfo object
            report: ScanReport for PII data

        Returns:
            Dictionary representation
        """
        # Determine risk level
        if file_info.risk_score >= 75:
            risk_level = "HIGH"
        elif file_info.risk_score >= 50:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        file_dict = {
            "id": file_info.id,
            "name": file_info.name,
            "mime_type": file_info.mime_type,
            "owner": {
                "email": file_info.owner_email,
                "name": file_info.owner_name,
            },
            "size_bytes": file_info.size,
            "created_time": file_info.created_time.isoformat(),
            "modified_time": file_info.modified_time.isoformat(),
            "web_view_link": file_info.web_view_link,
            "sharing": {
                "is_public": file_info.is_public,
                "is_shared_externally": file_info.is_shared_externally,
                "external_domains": file_info.external_domains,
                "external_emails": file_info.external_emails,
                "permissions": [self._permission_to_dict(p) for p in file_info.permissions],
            },
            "risk": {
                "score": file_info.risk_score,
                "level": risk_level,
            },
        }

        # Add PII information if available
        if report.pii_results and file_info.id in report.pii_results:
            pii_result = report.pii_results[file_info.id]
            file_dict["pii"] = self._pii_result_to_dict(pii_result)

        return file_dict

    def _permission_to_dict(self, permission: FilePermission) -> Dict[str, Any]:
        """Convert FilePermission to dictionary.

        Args:
            permission: FilePermission object

        Returns:
            Dictionary representation
        """
        return {
            "id": permission.id,
            "type": permission.type,
            "role": permission.role,
            "email_address": permission.email_address,
            "domain": permission.domain,
            "display_name": permission.display_name,
            "deleted": permission.deleted,
        }

    def _pii_result_to_dict(self, pii_result: PIIDetectionResult) -> Dict[str, Any]:
        """Convert PIIDetectionResult to dictionary.

        Args:
            pii_result: PIIDetectionResult object

        Returns:
            Dictionary representation
        """
        return {
            "total_matches": pii_result.total_matches,
            "high_confidence_matches": pii_result.high_confidence_matches,
            "types_found": [pt.value for pt in pii_result.pii_types_found],
            "matches": [self._pii_match_to_dict(match) for match in pii_result.matches],
        }

    def _pii_match_to_dict(self, match: PIIMatch) -> Dict[str, Any]:
        """Convert PIIMatch to dictionary.

        Args:
            match: PIIMatch object

        Returns:
            Dictionary representation
        """
        return {
            "type": match.pii_type.value,
            "value": match.value,  # Note: In production, consider redacting this
            "start_pos": match.start_pos,
            "end_pos": match.end_pos,
            "confidence": match.confidence,
            "context": match.context,
        }

