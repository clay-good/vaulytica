"""CSV report generator."""

import csv
from pathlib import Path
from typing import Optional

import structlog

from vaulytica.core.reporters.base import BaseReporter, ScanReport

logger = structlog.get_logger(__name__)


class CSVReporter(BaseReporter):
    """Generates CSV reports from scan results."""

    def generate(self, report: ScanReport, output_file: Optional[Path] = None) -> Path:
        """Generate a CSV report.

        Args:
            report: ScanReport to generate from
            output_file: Optional output file path

        Returns:
            Path to generated CSV file
        """
        output_path = self._get_output_path(report, "csv", output_file)

        logger.info("generating_csv_report", output_path=str(output_path))

        # Calculate summary if not already done
        if not report.summary:
            report.calculate_summary()

        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            # Define CSV columns
            fieldnames = [
                "file_id",
                "file_name",
                "owner_email",
                "owner_name",
                "mime_type",
                "size_bytes",
                "created_time",
                "modified_time",
                "web_view_link",
                "is_public",
                "is_shared_externally",
                "external_domains",
                "external_emails",
                "permission_count",
                "risk_score",
                "risk_level",
                "has_pii",
                "pii_types",
                "pii_count",
            ]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            # Write file data
            for file_info in report.files:
                # Determine risk level
                if file_info.risk_score >= 75:
                    risk_level = "HIGH"
                elif file_info.risk_score >= 50:
                    risk_level = "MEDIUM"
                else:
                    risk_level = "LOW"

                # Get PII information if available
                has_pii = False
                pii_types = ""
                pii_count = 0

                if report.pii_results and file_info.id in report.pii_results:
                    pii_result = report.pii_results[file_info.id]
                    has_pii = pii_result.total_matches > 0
                    pii_types = ", ".join(sorted(pt.value for pt in pii_result.pii_types_found))
                    pii_count = pii_result.total_matches

                row = {
                    "file_id": file_info.id,
                    "file_name": file_info.name,
                    "owner_email": file_info.owner_email,
                    "owner_name": file_info.owner_name,
                    "mime_type": file_info.mime_type,
                    "size_bytes": file_info.size or "",
                    "created_time": file_info.created_time.isoformat(),
                    "modified_time": file_info.modified_time.isoformat(),
                    "web_view_link": file_info.web_view_link or "",
                    "is_public": "Yes" if file_info.is_public else "No",
                    "is_shared_externally": "Yes" if file_info.is_shared_externally else "No",
                    "external_domains": ", ".join(file_info.external_domains),
                    "external_emails": ", ".join(file_info.external_emails),
                    "permission_count": len(file_info.permissions),
                    "risk_score": file_info.risk_score,
                    "risk_level": risk_level,
                    "has_pii": "Yes" if has_pii else "No",
                    "pii_types": pii_types,
                    "pii_count": pii_count,
                }

                writer.writerow(row)

        logger.info(
            "csv_report_generated",
            output_path=str(output_path),
            file_count=len(report.files),
        )

        return output_path

    def generate_summary(self, report: ScanReport, output_file: Optional[Path] = None) -> Path:
        """Generate a summary CSV report.

        Args:
            report: ScanReport to generate from
            output_file: Optional output file path

        Returns:
            Path to generated summary CSV file
        """
        if output_file:
            output_path = Path(output_file)
        else:
            timestamp = report.scan_time.strftime("%Y%m%d_%H%M%S")
            filename = f"vaulytica_summary_{report.scan_id}_{timestamp}.csv"
            output_path = self.output_dir / filename

        logger.info("generating_csv_summary", output_path=str(output_path))

        # Calculate summary if not already done
        if not report.summary:
            report.calculate_summary()

        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = ["metric", "value"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            # Write summary data
            summary_rows = [
                {"metric": "Scan ID", "value": report.scan_id},
                {"metric": "Scan Time", "value": report.scan_time.isoformat()},
                {"metric": "Domain", "value": report.domain},
                {"metric": "Total Files", "value": report.summary.get("total_files", 0)},
                {"metric": "Public Files", "value": report.summary.get("public_files", 0)},
                {
                    "metric": "Externally Shared Files",
                    "value": report.summary.get("externally_shared", 0),
                },
                {"metric": "High Risk Files", "value": report.summary.get("high_risk", 0)},
                {"metric": "Medium Risk Files", "value": report.summary.get("medium_risk", 0)},
                {"metric": "Low Risk Files", "value": report.summary.get("low_risk", 0)},
            ]

            if "files_with_pii" in report.summary:
                summary_rows.extend(
                    [
                        {
                            "metric": "Files with PII",
                            "value": report.summary.get("files_with_pii", 0),
                        },
                        {
                            "metric": "Total PII Matches",
                            "value": report.summary.get("total_pii_matches", 0),
                        },
                    ]
                )

            for row in summary_rows:
                writer.writerow(row)

        logger.info("csv_summary_generated", output_path=str(output_path))

        return output_path

