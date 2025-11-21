"""Shadow IT discovery and analysis commands."""

from pathlib import Path
from typing import Optional
import csv
import json

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.panel import Panel
from rich import box

from vaulytica.core.auth.client import GoogleWorkspaceClient
from vaulytica.core.analyzers.shadow_it_analyzer import (
    ShadowITAnalyzer,
    ShadowITRiskLevel,
)

console = Console()


@click.group(name="shadow-it")
def shadow_it_group() -> None:
    """Shadow IT discovery and risk analysis commands."""
    pass


@shadow_it_group.command(name="analyze")
@click.option(
    "--credentials",
    "-c",
    required=True,
    type=click.Path(exists=True),
    help="Path to service account credentials JSON file",
)
@click.option(
    "--admin-email",
    "-a",
    required=True,
    help="Admin email for domain-wide delegation",
)
@click.option(
    "--domain",
    "-d",
    required=True,
    help="Google Workspace domain to analyze",
)
@click.option(
    "--approval-list",
    type=click.Path(exists=True),
    help="Path to approved apps JSON file",
)
@click.option(
    "--stale-days",
    type=int,
    default=90,
    help="Days to consider OAuth grant stale (default: 90)",
)
@click.option(
    "--max-users",
    type=int,
    help="Maximum users to analyze (for testing)",
)
@click.option(
    "--no-audit-logs",
    is_flag=True,
    help="Skip audit log analysis (faster but less accurate)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path for results",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "csv", "html"], case_sensitive=False),
    default="json",
    help="Output format (default: json)",
)
def analyze(
    credentials: str,
    admin_email: str,
    domain: str,
    approval_list: Optional[str],
    stale_days: int,
    max_users: Optional[int],
    no_audit_logs: bool,
    output: Optional[Path],
    format: str,
) -> None:
    """Analyze OAuth apps for Shadow IT risks.

    This command discovers unauthorized OAuth applications, analyzes their risk level,
    identifies stale grants, and generates a comprehensive remediation playbook.

    Example:
        vaulytica shadow-it analyze \\
            --credentials service-account.json \\
            --admin-email admin@example.com \\
            --domain example.com \\
            --approval-list approved-apps.json \\
            --output shadow-it-report.json
    """
    try:
        # Initialize client
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            progress.add_task("Initializing Google Workspace client...", total=None)
            client = GoogleWorkspaceClient(
                credentials_path=credentials,
                admin_email=admin_email,
            )

        console.print("[green]✓[/green] Client initialized successfully")

        # Initialize Shadow IT Analyzer
        analyzer = ShadowITAnalyzer(
            client=client,
            domain=domain,
            approval_list_path=approval_list,
            stale_days=stale_days,
        )

        console.print(
            f"\n[bold]Shadow IT Analysis Configuration:[/bold]\n"
            f"  Domain: {domain}\n"
            f"  Stale Days Threshold: {stale_days}\n"
            f"  Approved Apps Loaded: {len(analyzer.approved_apps)}\n"
            f"  Include Audit Logs: {not no_audit_logs}"
        )

        # Run analysis
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Analyzing Shadow IT risks...", total=None)
            result = analyzer.analyze(
                include_audit_logs=not no_audit_logs,
                max_users=max_users,
            )
            progress.update(task, completed=True)

        console.print("[green]✓[/green] Analysis complete\n")

        # Display executive summary
        console.print(
            Panel(
                result.executive_summary,
                title="[bold cyan]Executive Summary[/bold cyan]",
                border_style="cyan",
                padding=(1, 2),
            )
        )

        # Display statistics
        stats_table = Table(title="\n📊 Shadow IT Statistics", box=box.ROUNDED)
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Count", style="yellow", justify="right")

        stats_table.add_row("Total Apps Analyzed", str(result.total_apps_analyzed))
        stats_table.add_row("Shadow IT Apps", str(result.shadow_it_apps))
        stats_table.add_row("Approved Apps", str(result.approved_apps))
        stats_table.add_row("", "")  # Separator
        stats_table.add_row("Critical Findings", str(result.critical_findings))
        stats_table.add_row("High Findings", str(result.high_findings))
        stats_table.add_row("Medium Findings", str(result.medium_findings))
        stats_table.add_row("Low Findings", str(result.low_findings))
        stats_table.add_row("", "")  # Separator
        stats_table.add_row("Stale Grants", str(result.stale_grants))
        stats_table.add_row("Data Exfiltration Risks", str(result.data_exfiltration_risks))
        stats_table.add_row("Admin Access Risks", str(result.admin_access_risks))

        console.print(stats_table)

        # Display top findings
        if result.findings:
            findings_table = Table(
                title="\n🔍 Top Shadow IT Findings (Top 10)",
                box=box.ROUNDED,
            )
            findings_table.add_column("Risk", style="bold")
            findings_table.add_column("Category", style="cyan")
            findings_table.add_column("App Name", style="yellow")
            findings_table.add_column("Users", justify="right")
            findings_table.add_column("Score", justify="right")

            # Sort by risk level and score
            risk_order = {
                ShadowITRiskLevel.CRITICAL: 0,
                ShadowITRiskLevel.HIGH: 1,
                ShadowITRiskLevel.MEDIUM: 2,
                ShadowITRiskLevel.LOW: 3,
                ShadowITRiskLevel.INFO: 4,
            }
            sorted_findings = sorted(
                result.findings,
                key=lambda f: (risk_order.get(f.risk_level, 999), -f.risk_score),
            )

            risk_emojis = {
                ShadowITRiskLevel.CRITICAL: "🔴",
                ShadowITRiskLevel.HIGH: "🟠",
                ShadowITRiskLevel.MEDIUM: "🟡",
                ShadowITRiskLevel.LOW: "🟢",
                ShadowITRiskLevel.INFO: "ℹ️",
            }

            for finding in sorted_findings[:10]:
                emoji = risk_emojis.get(finding.risk_level, "")
                findings_table.add_row(
                    f"{emoji} {finding.risk_level.value.upper()}",
                    finding.category.value.replace("_", " ").title(),
                    finding.app_name[:40],
                    str(finding.user_count),
                    str(finding.risk_score),
                )

            console.print(findings_table)

        # Display remediation playbook
        if result.remediation_playbook:
            console.print("\n[bold cyan]📋 Remediation Playbook:[/bold cyan]\n")
            for item in result.remediation_playbook:
                urgency_colors = {
                    "immediate": "red bold",
                    "high": "yellow bold",
                    "medium": "cyan",
                    "low": "white",
                    "preventive": "green",
                }
                color = urgency_colors.get(item["urgency"], "white")

                console.print(
                    f"[{color}]Priority {item['priority']}: {item['title']}[/{color}]"
                )
                console.print(f"  {item['description']}")
                console.print(f"  Timeline: {item['timeline']}")
                if len(item.get("actions", [])) > 0:
                    console.print("  Actions:")
                    for action in item["actions"][:3]:  # Show first 3 actions
                        console.print(f"    • {action}")
                console.print()

        # Save to file if specified
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)

            if format == "json":
                _save_json_report(result, output)
            elif format == "csv":
                _save_csv_report(result, output)
            elif format == "html":
                _save_html_report(result, output)

            console.print(f"\n[green]✓[/green] Report saved to: {output}")

        console.print(
            f"\n[bold green]Shadow IT analysis complete![/bold green] "
            f"Analyzed {result.total_apps_analyzed} apps, "
            f"found {result.shadow_it_apps} Shadow IT apps with "
            f"{len(result.findings)} total findings."
        )

    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}", style="red")
        raise click.Abort()


@shadow_it_group.command(name="export-template")
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default="approved-apps.json",
    help="Output path for approval template (default: approved-apps.json)",
)
def export_template(output: Path) -> None:
    """Export a template for the approved apps list.

    This creates a JSON template file that you can fill out with your
    organization's approved OAuth applications.

    Example:
        vaulytica shadow-it export-template -o my-approved-apps.json
    """
    try:
        from vaulytica.core.analyzers.shadow_it_analyzer import ShadowITAnalyzer

        # Create a dummy analyzer just to export template
        analyzer = ShadowITAnalyzer(
            client=None,  # type: ignore
            domain="example.com",
        )
        analyzer.export_approval_template(str(output))

        console.print(f"[green]✓[/green] Approval template exported to: {output}")
        console.print(
            "\n[cyan]Next steps:[/cyan]\n"
            "1. Edit the JSON file and add your approved apps\n"
            "2. Use --approval-list flag when running analysis\n"
        )

    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}", style="red")
        raise click.Abort()


def _save_json_report(result, output: Path) -> None:
    """Save analysis result as JSON."""
    data = {
        "timestamp": result.timestamp.isoformat(),
        "summary": {
            "total_apps_analyzed": result.total_apps_analyzed,
            "shadow_it_apps": result.shadow_it_apps,
            "approved_apps": result.approved_apps,
            "critical_findings": result.critical_findings,
            "high_findings": result.high_findings,
            "medium_findings": result.medium_findings,
            "low_findings": result.low_findings,
            "stale_grants": result.stale_grants,
            "data_exfiltration_risks": result.data_exfiltration_risks,
            "admin_access_risks": result.admin_access_risks,
        },
        "executive_summary": result.executive_summary,
        "findings": [
            {
                "category": f.category.value,
                "risk_level": f.risk_level.value,
                "app_name": f.app_name,
                "client_id": f.client_id,
                "user_count": f.user_count,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "remediation_steps": f.remediation_steps,
                "risk_score": f.risk_score,
                "scopes": f.scopes,
                "metadata": f.metadata,
            }
            for f in result.findings
        ],
        "unapproved_apps": result.unapproved_app_list,
        "remediation_playbook": result.remediation_playbook,
    }

    with open(output, "w") as f:
        json.dump(data, f, indent=2)


def _save_csv_report(result, output: Path) -> None:
    """Save findings as CSV."""
    with open(output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Risk Level",
            "Category",
            "App Name",
            "Client ID",
            "User Count",
            "Risk Score",
            "Title",
            "Description",
        ])

        for finding in result.findings:
            writer.writerow([
                finding.risk_level.value,
                finding.category.value,
                finding.app_name,
                finding.client_id,
                finding.user_count,
                finding.risk_score,
                finding.title,
                finding.description,
            ])


def _save_html_report(result, output: Path) -> None:
    """Save analysis result as HTML."""
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Shadow IT Analysis Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .card h3 {{
            margin: 0 0 10px 0;
            color: #666;
            font-size: 14px;
        }}
        .card .value {{
            font-size: 32px;
            font-weight: bold;
            color: #333;
        }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .finding {{
            background: white;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #28a745; }}
        .finding h3 {{
            margin: 0 0 10px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #667eea;
            color: white;
        }}
        .remediation {{
            background: white;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Shadow IT Analysis Report</h1>
        <p>Generated: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    </div>

    <div class="summary-cards">
        <div class="card">
            <h3>Total Apps</h3>
            <div class="value">{result.total_apps_analyzed}</div>
        </div>
        <div class="card">
            <h3>Shadow IT Apps</h3>
            <div class="value critical">{result.shadow_it_apps}</div>
        </div>
        <div class="card">
            <h3>Critical Findings</h3>
            <div class="value critical">{result.critical_findings}</div>
        </div>
        <div class="card">
            <h3>High Findings</h3>
            <div class="value high">{result.high_findings}</div>
        </div>
        <div class="card">
            <h3>Stale Grants</h3>
            <div class="value medium">{result.stale_grants}</div>
        </div>
        <div class="card">
            <h3>Data Risks</h3>
            <div class="value high">{result.data_exfiltration_risks}</div>
        </div>
    </div>

    <div class="card">
        <h2>Executive Summary</h2>
        <p>{result.executive_summary.replace(chr(10), '<br>')}</p>
    </div>

    <h2 style="margin-top: 30px;">Findings</h2>
    """

    # Add findings
    for finding in result.findings[:20]:  # Top 20 findings
        risk_class = finding.risk_level.value
        html_content += f"""
    <div class="finding {risk_class}">
        <h3>{finding.title}</h3>
        <p><strong>Risk Level:</strong> <span class="{risk_class}">{finding.risk_level.value.upper()}</span></p>
        <p><strong>App:</strong> {finding.app_name} | <strong>Users:</strong> {finding.user_count} | <strong>Score:</strong> {finding.risk_score}</p>
        <p>{finding.description}</p>
        <p><strong>Evidence:</strong></p>
        <ul>
        """
        for evidence in finding.evidence:
            html_content += f"<li>{evidence}</li>"
        html_content += """
        </ul>
    </div>
        """

    # Add remediation playbook
    html_content += """
    <h2 style="margin-top: 30px;">Remediation Playbook</h2>
    """

    for item in result.remediation_playbook:
        html_content += f"""
    <div class="remediation">
        <h3>Priority {item['priority']}: {item['title']}</h3>
        <p><strong>Urgency:</strong> {item['urgency'].upper()} | <strong>Timeline:</strong> {item['timeline']}</p>
        <p>{item['description']}</p>
        <p><strong>Actions:</strong></p>
        <ul>
        """
        for action in item.get("actions", []):
            html_content += f"<li>{action}</li>"
        html_content += """
        </ul>
    </div>
        """

    html_content += """
</body>
</html>
    """

    with open(output, "w") as f:
        f.write(html_content)
