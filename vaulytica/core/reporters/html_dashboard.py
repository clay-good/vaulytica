"""
HTML dashboard generator for Vaulytica.

Creates interactive HTML dashboards with charts and visualizations.
"""

from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path
import json
import structlog

logger = structlog.get_logger(__name__)


class HTMLDashboardGenerator:
    """
    Generates interactive HTML dashboards with charts and visualizations.

    Uses Chart.js for charts and modern CSS for styling.
    """

    def __init__(self):
        """Initialize HTML dashboard generator."""
        self.template = self._get_template()

    def generate(
        self,
        scan_results: List[Dict],
        metrics: Optional[Dict] = None,
        output_path: str = "dashboard.html"
    ) -> str:
        """
        Generate HTML dashboard from scan results.

        Args:
            scan_results: List of scan result dictionaries OR dict with 'files', 'users', 'oauth_apps' keys
            metrics: Optional metrics dictionary
            output_path: Path to save the dashboard

        Returns:
            Path to generated dashboard
        """
        try:
            # Normalize scan_results to a list of file dictionaries
            normalized_results = self._normalize_scan_results(scan_results)

            # Process scan results
            stats = self._calculate_statistics(normalized_results)

            # Generate charts data
            charts_data = self._generate_charts_data(normalized_results, stats)

            # Generate HTML
            html = self._render_dashboard(stats, charts_data, metrics)

            # Save to file
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(html)

            logger.info("dashboard_generated", output_path=output_path)
            return str(output_file)

        except Exception as e:
            logger.error("failed_to_generate_dashboard", error=str(e))
            raise

    def _normalize_scan_results(self, scan_results) -> List[Dict]:
        """Normalize scan results to a list of file dictionaries.

        Args:
            scan_results: Either a list of dicts/FileInfo objects, or a dict with 'files' key

        Returns:
            List of file dictionaries
        """
        if scan_results is None:
            return []

        # If it's a dict with 'files' key, extract and convert files
        if isinstance(scan_results, dict):
            files = scan_results.get('files', [])
            normalized = []
            for f in files:
                if hasattr(f, '__dict__'):
                    # Convert dataclass/object to dict
                    file_dict = {
                        'id': getattr(f, 'id', ''),
                        'name': getattr(f, 'name', ''),
                        'owner_email': getattr(f, 'owner_email', ''),
                        'mime_type': getattr(f, 'mime_type', ''),
                        'is_public': getattr(f, 'is_public', False),
                        'has_external_sharing': getattr(f, 'is_shared_externally', False),
                        'risk_score': getattr(f, 'risk_score', 0),
                        'pii_findings': getattr(f, 'pii_findings', None) or getattr(f, 'pii_types', None),
                    }
                    normalized.append(file_dict)
                elif isinstance(f, dict):
                    normalized.append(f)
            return normalized

        # If it's already a list, convert any objects to dicts
        if isinstance(scan_results, list):
            normalized = []
            for item in scan_results:
                if hasattr(item, '__dict__') and not isinstance(item, dict):
                    # Convert dataclass/object to dict
                    file_dict = {
                        'id': getattr(item, 'id', ''),
                        'name': getattr(item, 'name', ''),
                        'owner_email': getattr(item, 'owner_email', ''),
                        'mime_type': getattr(item, 'mime_type', ''),
                        'is_public': getattr(item, 'is_public', False),
                        'has_external_sharing': getattr(item, 'is_shared_externally', False),
                        'risk_score': getattr(item, 'risk_score', 0),
                        'pii_findings': getattr(item, 'pii_findings', None) or getattr(item, 'pii_types', None),
                    }
                    normalized.append(file_dict)
                elif isinstance(item, dict):
                    normalized.append(item)
            return normalized

        return []

    def _calculate_statistics(self, scan_results: List[Dict]) -> Dict:
        """Calculate statistics from scan results."""
        total_files = len(scan_results)
        external_shares = sum(1 for r in scan_results if r.get('has_external_sharing'))
        public_shares = sum(1 for r in scan_results if r.get('is_public'))
        pii_files = sum(1 for r in scan_results if r.get('pii_findings'))

        # Risk score distribution
        high_risk = sum(1 for r in scan_results if r.get('risk_score', 0) >= 7)
        medium_risk = sum(1 for r in scan_results if 4 <= r.get('risk_score', 0) < 7)
        low_risk = sum(1 for r in scan_results if r.get('risk_score', 0) < 4)

        # PII types
        pii_types = {}
        for result in scan_results:
            if result.get('pii_findings'):
                for finding in result['pii_findings']:
                    pii_type = finding.get('type', 'unknown')
                    pii_types[pii_type] = pii_types.get(pii_type, 0) + 1

        # File types
        file_types = {}
        for result in scan_results:
            mime_type = result.get('mime_type', 'unknown')
            file_types[mime_type] = file_types.get(mime_type, 0) + 1

        # Owners
        owners = {}
        for result in scan_results:
            owner = result.get('owner_email', 'unknown')
            owners[owner] = owners.get(owner, 0) + 1

        return {
            'total_files': total_files,
            'external_shares': external_shares,
            'public_shares': public_shares,
            'pii_files': pii_files,
            'high_risk': high_risk,
            'medium_risk': medium_risk,
            'low_risk': low_risk,
            'pii_types': pii_types,
            'file_types': file_types,
            'owners': owners,
        }

    def _generate_charts_data(self, scan_results: List[Dict], stats: Dict) -> Dict:
        """Generate data for charts."""
        # Professional monochrome color palette
        risk_colors = ['#1f2937', '#6b7280', '#d1d5db']  # Dark gray, medium gray, light gray
        sharing_colors = ['#374151', '#6b7280', '#9ca3af']  # Gray scale

        return {
            'risk_distribution': {
                'labels': ['High Risk', 'Medium Risk', 'Low Risk'],
                'data': [stats['high_risk'], stats['medium_risk'], stats['low_risk']],
                'colors': risk_colors
            },
            'sharing_status': {
                'labels': ['External Shares', 'Public Shares', 'Internal Only'],
                'data': [
                    stats['external_shares'],
                    stats['public_shares'],
                    stats['total_files'] - stats['external_shares'] - stats['public_shares']
                ],
                'colors': sharing_colors
            },
            'pii_types': {
                'labels': list(stats['pii_types'].keys())[:10],  # Top 10
                'data': list(stats['pii_types'].values())[:10],
                'colors': self._generate_colors(len(list(stats['pii_types'].keys())[:10]))
            },
            'file_types': {
                'labels': list(stats['file_types'].keys())[:10],  # Top 10
                'data': list(stats['file_types'].values())[:10],
                'colors': self._generate_colors(len(list(stats['file_types'].keys())[:10]))
            },
            'top_owners': {
                'labels': list(sorted(stats['owners'].items(), key=lambda x: x[1], reverse=True)[:10]),
                'data': [v for k, v in sorted(stats['owners'].items(), key=lambda x: x[1], reverse=True)[:10]],
            }
        }

    def _generate_colors(self, count: int) -> List[str]:
        """Generate a list of professional monochrome colors for charts."""
        # Professional grayscale palette
        colors = [
            '#1f2937', '#374151', '#4b5563', '#6b7280', '#9ca3af',
            '#d1d5db', '#e5e7eb', '#f3f4f6', '#2d3748', '#4a5568'
        ]
        return (colors * ((count // len(colors)) + 1))[:count]

    def _render_dashboard(self, stats: Dict, charts_data: Dict, metrics: Optional[Dict]) -> str:
        """Render the HTML dashboard."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vaulytica Security Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f8f9fa;
            min-height: 100vh;
            padding: 24px;
            color: #1f2937;
            line-height: 1.5;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}

        .header {{
            background: #ffffff;
            border: 1px solid #e5e7eb;
            padding: 32px;
            margin-bottom: 24px;
        }}

        .header h1 {{
            color: #111827;
            font-size: 1.875rem;
            font-weight: 600;
            margin-bottom: 8px;
            letter-spacing: -0.025em;
        }}

        .header .subtitle {{
            color: #6b7280;
            font-size: 0.875rem;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}

        .stat-card {{
            background: #ffffff;
            border: 1px solid #e5e7eb;
            padding: 20px;
        }}

        .stat-card .label {{
            color: #6b7280;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 8px;
            font-weight: 500;
        }}

        .stat-card .value {{
            color: #111827;
            font-size: 2rem;
            font-weight: 600;
        }}

        .stat-card.alert .value {{
            color: #1f2937;
            font-weight: 700;
        }}

        .stat-card.alert {{
            border-left: 4px solid #374151;
        }}

        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
            gap: 24px;
            margin-bottom: 24px;
        }}

        .chart-card {{
            background: #ffffff;
            border: 1px solid #e5e7eb;
            padding: 24px;
        }}

        .chart-card h3 {{
            color: #111827;
            margin-bottom: 16px;
            font-size: 1rem;
            font-weight: 600;
            padding-bottom: 12px;
            border-bottom: 1px solid #e5e7eb;
        }}

        .chart-container {{
            position: relative;
            height: 280px;
        }}

        .footer {{
            background: #ffffff;
            border: 1px solid #e5e7eb;
            padding: 16px;
            text-align: center;
            color: #9ca3af;
            font-size: 0.75rem;
        }}

        .footer a {{
            color: #6b7280;
            text-decoration: none;
        }}

        .footer a:hover {{
            text-decoration: underline;
        }}

        @media print {{
            body {{
                background: #ffffff;
                padding: 0;
            }}
            .stat-card, .chart-card, .header, .footer {{
                border: 1px solid #d1d5db;
                box-shadow: none;
            }}
            .chart-container {{
                height: 250px;
            }}
        }}

        @media (max-width: 768px) {{
            .charts-grid {{
                grid-template-columns: 1fr;
            }}
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Vaulytica Security Report</h1>
            <p class="subtitle">Report generated: {timestamp}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="label">Total Files Scanned</div>
                <div class="value">{stats['total_files']:,}</div>
            </div>
            <div class="stat-card alert">
                <div class="label">High Risk Files</div>
                <div class="value">{stats['high_risk']:,}</div>
            </div>
            <div class="stat-card alert">
                <div class="label">Files with PII</div>
                <div class="value">{stats['pii_files']:,}</div>
            </div>
            <div class="stat-card alert">
                <div class="label">External Shares</div>
                <div class="value">{stats['external_shares']:,}</div>
            </div>
            <div class="stat-card alert">
                <div class="label">Public Shares</div>
                <div class="value">{stats['public_shares']:,}</div>
            </div>
            <div class="stat-card">
                <div class="label">Low Risk Files</div>
                <div class="value">{stats['low_risk']:,}</div>
            </div>
        </div>

        <div class="charts-grid">
            <div class="chart-card">
                <h3>Risk Distribution</h3>
                <div class="chart-container">
                    <canvas id="riskChart"></canvas>
                </div>
            </div>

            <div class="chart-card">
                <h3>Sharing Status</h3>
                <div class="chart-container">
                    <canvas id="sharingChart"></canvas>
                </div>
            </div>

            <div class="chart-card">
                <h3>PII Types Detected</h3>
                <div class="chart-container">
                    <canvas id="piiChart"></canvas>
                </div>
            </div>

            <div class="chart-card">
                <h3>File Types Distribution</h3>
                <div class="chart-container">
                    <canvas id="fileTypesChart"></canvas>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>Generated by Vaulytica | <a href="https://github.com/clay-good/vaulytica">github.com/clay-good/vaulytica</a></p>
        </div>
    </div>

    <script>
        // Chart.js configuration - professional monochrome theme
        Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';
        Chart.defaults.color = '#6b7280';

        // Risk Distribution Chart
        new Chart(document.getElementById('riskChart'), {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(charts_data['risk_distribution']['labels'])},
                datasets: [{{
                    data: {json.dumps(charts_data['risk_distribution']['data'])},
                    backgroundColor: {json.dumps(charts_data['risk_distribution']['colors'])},
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{
                            padding: 16,
                            usePointStyle: true,
                            pointStyle: 'rectRounded'
                        }}
                    }}
                }}
            }}
        }});

        // Sharing Status Chart
        new Chart(document.getElementById('sharingChart'), {{
            type: 'pie',
            data: {{
                labels: {json.dumps(charts_data['sharing_status']['labels'])},
                datasets: [{{
                    data: {json.dumps(charts_data['sharing_status']['data'])},
                    backgroundColor: {json.dumps(charts_data['sharing_status']['colors'])},
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{
                            padding: 16,
                            usePointStyle: true,
                            pointStyle: 'rectRounded'
                        }}
                    }}
                }}
            }}
        }});

        // PII Types Chart
        new Chart(document.getElementById('piiChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(charts_data['pii_types']['labels'])},
                datasets: [{{
                    label: 'Detections',
                    data: {json.dumps(charts_data['pii_types']['data'])},
                    backgroundColor: '#374151',
                    borderRadius: 2
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        grid: {{
                            color: '#e5e7eb'
                        }}
                    }},
                    x: {{
                        grid: {{
                            display: false
                        }}
                    }}
                }}
            }}
        }});

        // File Types Chart
        new Chart(document.getElementById('fileTypesChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(charts_data['file_types']['labels'])},
                datasets: [{{
                    label: 'Files',
                    data: {json.dumps(charts_data['file_types']['data'])},
                    backgroundColor: '#6b7280',
                    borderRadius: 2
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: false
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        grid: {{
                            color: '#e5e7eb'
                        }}
                    }},
                    x: {{
                        grid: {{
                            display: false
                        }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>"""

        return html

    def _get_template(self) -> str:
        """Get the HTML template."""
        # Template is embedded in _render_dashboard method
        return ""

