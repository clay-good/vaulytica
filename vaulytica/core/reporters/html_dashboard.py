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
            scan_results: List of scan result dictionaries
            metrics: Optional metrics dictionary
            output_path: Path to save the dashboard

        Returns:
            Path to generated dashboard
        """
        try:
            # Process scan results
            stats = self._calculate_statistics(scan_results)

            # Generate charts data
            charts_data = self._generate_charts_data(scan_results, stats)

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
        return {
            'risk_distribution': {
                'labels': ['High Risk', 'Medium Risk', 'Low Risk'],
                'data': [stats['high_risk'], stats['medium_risk'], stats['low_risk']],
                'colors': ['#ef4444', '#f59e0b', '#10b981']
            },
            'sharing_status': {
                'labels': ['External Shares', 'Public Shares', 'Internal Only'],
                'data': [
                    stats['external_shares'],
                    stats['public_shares'],
                    stats['total_files'] - stats['external_shares'] - stats['public_shares']
                ],
                'colors': ['#f59e0b', '#ef4444', '#10b981']
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
        """Generate a list of colors for charts."""
        colors = [
            '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
            '#ec4899', '#14b8a6', '#f97316', '#06b6d4', '#84cc16'
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
    <title>Vaulytica Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}

        .header {{
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}

        .header h1 {{
            color: #1f2937;
            font-size: 2.5rem;
            margin-bottom: 10px;
        }}

        .header .subtitle {{
            color: #6b7280;
            font-size: 1rem;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}

        .stat-card {{
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            transition: transform 0.2s;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
        }}

        .stat-card .label {{
            color: #6b7280;
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 10px;
        }}

        .stat-card .value {{
            color: #1f2937;
            font-size: 2.5rem;
            font-weight: bold;
        }}

        .stat-card.danger .value {{
            color: #ef4444;
        }}

        .stat-card.warning .value {{
            color: #f59e0b;
        }}

        .stat-card.success .value {{
            color: #10b981;
        }}

        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}

        .chart-card {{
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}

        .chart-card h3 {{
            color: #1f2937;
            margin-bottom: 20px;
            font-size: 1.25rem;
        }}

        .chart-container {{
            position: relative;
            height: 300px;
        }}

        .footer {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            color: #6b7280;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}

        @media (max-width: 768px) {{
            .charts-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Vaulytica Dashboard</h1>
            <p class="subtitle">Generated on {timestamp}</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="label">Total Files Scanned</div>
                <div class="value">{stats['total_files']:,}</div>
            </div>
            <div class="stat-card danger">
                <div class="label">High Risk Files</div>
                <div class="value">{stats['high_risk']:,}</div>
            </div>
            <div class="stat-card warning">
                <div class="label">Files with PII</div>
                <div class="value">{stats['pii_files']:,}</div>
            </div>
            <div class="stat-card warning">
                <div class="label">External Shares</div>
                <div class="value">{stats['external_shares']:,}</div>
            </div>
            <div class="stat-card danger">
                <div class="label">Public Shares</div>
                <div class="value">{stats['public_shares']:,}</div>
            </div>
            <div class="stat-card success">
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
                <h3>Top PII Types Detected</h3>
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
            <p>Generated by Vaulytica v1.0 | <a href="https://github.com/clay-good/vaulytica" style="color: #667eea;">GitHub</a></p>
        </div>
    </div>

    <script>
        // Chart.js configuration
        Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif';

        // Risk Distribution Chart
        new Chart(document.getElementById('riskChart'), {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(charts_data['risk_distribution']['labels'])},
                datasets: [{{
                    data: {json.dumps(charts_data['risk_distribution']['data'])},
                    backgroundColor: {json.dumps(charts_data['risk_distribution']['colors'])},
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom',
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
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom',
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
                    backgroundColor: '#667eea',
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: false,
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true
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
                    backgroundColor: '#764ba2',
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        display: false,
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true
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

