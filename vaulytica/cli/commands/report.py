"""Report command implementations."""

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from vaulytica.storage.state import StateManager
from vaulytica.core.reporters.html_dashboard import HTMLDashboardGenerator

console = Console()


def generate_report_command(
    ctx: click.Context,
    format: str,
    output: Path,
    scan_id: Optional[str],
) -> None:
    """Generate a report from scan results."""
    console.print("[cyan]Generating report...[/cyan]")
    console.print(f"[cyan]Format:[/cyan] {format}")
    console.print(f"[cyan]Output:[/cyan] {output}")

    if scan_id:
        console.print(f"[cyan]Scan ID:[/cyan] {scan_id}")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Loading scan data...", total=None)

            # Initialize state manager
            state_manager = StateManager()

            # Get scan history
            if scan_id:
                # Get specific scan
                scan_history = state_manager.get_scan_history(limit=1000)
                scan_data = next((s for s in scan_history if str(s["id"]) == scan_id), None)
                if not scan_data:
                    console.print(f"[red]Error: Scan ID {scan_id} not found[/red]")
                    raise click.Abort()
                scans = [scan_data]
            else:
                # Get recent scans
                scans = state_manager.get_scan_history(limit=10)

            progress.update(task, description=f"[green]✓[/green] Loaded {len(scans)} scan(s)")

            # Generate report
            report_task = progress.add_task("Generating report...", total=None)

            if format == "csv":
                _generate_csv_report(scans, output)
            elif format == "json":
                _generate_json_report(scans, output)
            elif format == "html":
                _generate_html_report(scans, output)
            else:
                console.print(f"[red]Error: Unsupported format '{format}'[/red]")
                raise click.Abort()

            progress.update(report_task, description="[green]✓[/green] Report generated")

        console.print(f"\n[green]✓[/green] Report saved to: {output}")

        # Display summary
        _display_summary(scans)

    except Exception as e:
        console.print(f"[red]Error generating report: {e}[/red]")
        raise click.Abort()


def _generate_csv_report(scans: List[Dict[str, Any]], output: Path) -> None:
    """Generate CSV report."""
    output.parent.mkdir(parents=True, exist_ok=True)

    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Scan ID",
            "Scan Type",
            "Domain",
            "Start Time",
            "End Time",
            "Status",
            "Files Scanned",
            "Issues Found",
        ])

        for scan in scans:
            writer.writerow([
                scan.get("id", ""),
                scan.get("scan_type", ""),
                scan.get("domain", ""),
                scan.get("start_time", ""),
                scan.get("end_time", ""),
                scan.get("status", ""),
                scan.get("files_scanned", 0),
                scan.get("issues_found", 0),
            ])


def _generate_json_report(scans: List[Dict[str, Any]], output: Path) -> None:
    """Generate JSON report."""
    output.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "generated_at": datetime.now().isoformat(),
        "total_scans": len(scans),
        "scans": scans,
    }

    with open(output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


def _generate_html_report(scans: List[Dict[str, Any]], output: Path) -> None:
    """Generate HTML report."""
    output.parent.mkdir(parents=True, exist_ok=True)

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Vaulytica Scan Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px;
        }}
        .summary {{
            background-color: white;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #3498db;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .status-completed {{
            color: #27ae60;
            font-weight: bold;
        }}
        .status-failed {{
            color: #e74c3c;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Vaulytica Scan Report</h1>
        <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>

    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Scans:</strong> {len(scans)}</p>
        <p><strong>Total Files Scanned:</strong> {sum(s.get('files_scanned', 0) for s in scans)}</p>
        <p><strong>Total Issues Found:</strong> {sum(s.get('issues_found', 0) for s in scans)}</p>
    </div>

    <table>
        <thead>
            <tr>
                <th>Scan ID</th>
                <th>Type</th>
                <th>Domain</th>
                <th>Start Time</th>
                <th>Status</th>
                <th>Files Scanned</th>
                <th>Issues Found</th>
            </tr>
        </thead>
        <tbody>
"""

    for scan in scans:
        status_class = "status-completed" if scan.get("status") == "completed" else "status-failed"
        html += f"""
            <tr>
                <td>{scan.get('id', '')}</td>
                <td>{scan.get('scan_type', '')}</td>
                <td>{scan.get('domain', '')}</td>
                <td>{scan.get('start_time', '')}</td>
                <td class="{status_class}">{scan.get('status', '')}</td>
                <td>{scan.get('files_scanned', 0)}</td>
                <td>{scan.get('issues_found', 0)}</td>
            </tr>
"""

    html += """
        </tbody>
    </table>
</body>
</html>
"""

    with open(output, "w", encoding="utf-8") as f:
        f.write(html)


def _display_summary(scans: List[Dict[str, Any]]) -> None:
    """Display summary of scans."""
    console.print("\n[cyan]Report Summary:[/cyan]\n")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    total_files = sum(s.get("files_scanned", 0) for s in scans)
    total_issues = sum(s.get("issues_found", 0) for s in scans)
    completed_scans = sum(1 for s in scans if s.get("status") == "completed")

    table.add_row("Total Scans", str(len(scans)))
    table.add_row("Completed Scans", str(completed_scans))
    table.add_row("Total Files Scanned", str(total_files))
    table.add_row("Total Issues Found", str(total_issues))

    console.print(table)


def generate_dashboard_command(
    ctx: click.Context,
    output: Path,
    scan_id: Optional[str],
) -> None:
    """Generate an interactive HTML dashboard from scan results."""
    console.print("[cyan]Generating dashboard...[/cyan]")
    console.print(f"[cyan]Output:[/cyan] {output}")

    if scan_id:
        console.print(f"[cyan]Scan ID:[/cyan] {scan_id}")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Loading scan data...", total=None)

            # Initialize state manager
            state_manager = StateManager()

            # Get file states (scan results)
            # Note: In a real implementation, you'd want to filter by scan_id
            # For now, we'll get all file states
            conn = state_manager.conn
            cursor = conn.cursor()

            if scan_id:
                # Get files from specific scan
                cursor.execute("""
                    SELECT * FROM file_state
                    WHERE last_scanned >= (
                        SELECT start_time FROM scan_history WHERE id = ?
                    )
                """, (scan_id,))
            else:
                # Get all files
                cursor.execute("SELECT * FROM file_state ORDER BY last_scanned DESC LIMIT 10000")

            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]

            # Convert to list of dicts
            scan_results = []
            for row in rows:
                result = dict(zip(columns, row))
                # Parse metadata if it exists
                if result.get('metadata'):
                    try:
                        metadata = json.loads(result['metadata'])
                        result.update(metadata)
                    except:
                        pass
                scan_results.append(result)

            progress.update(task, description=f"Loaded {len(scan_results)} files")

            if not scan_results:
                console.print("[yellow]No scan results found[/yellow]")
                return

            # Generate dashboard
            progress.update(task, description="Generating dashboard...")

            generator = HTMLDashboardGenerator()
            output_path = generator.generate(scan_results, output_path=str(output))

            progress.update(task, description="Dashboard generated!")

        console.print(f"\n[green]✓[/green] Dashboard generated: {output_path}")
        console.print(f"\n[cyan]Open in browser:[/cyan] file://{Path(output_path).absolute()}")

    except Exception as e:
        console.print(f"\n[red]✗[/red] Failed to generate dashboard: {e}")
        raise

