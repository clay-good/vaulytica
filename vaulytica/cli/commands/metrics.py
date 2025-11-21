"""
CLI commands for metrics and monitoring.
"""

import click
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from vaulytica.core.monitoring.prometheus_exporter import get_exporter

console = Console()


@click.group()
def metrics():
    """Metrics and monitoring commands."""
    pass


@metrics.command()
@click.option(
    '--output',
    '-o',
    type=click.Path(),
    help='Output file path (default: stdout)'
)
@click.option(
    '--format',
    '-f',
    type=click.Choice(['prometheus', 'json', 'text']),
    default='prometheus',
    help='Output format'
)
def export(output, format):
    """
    Export metrics in Prometheus format.

    Examples:
        # Export to stdout
        vaulytica metrics export

        # Export to file
        vaulytica metrics export --output metrics.txt

        # Export as JSON
        vaulytica metrics export --format json
    """
    try:
        exporter = get_exporter()

        if format == 'prometheus':
            metrics_output = exporter.export_metrics()
        elif format == 'json':
            import json
            metrics_output = json.dumps(exporter.get_summary(), indent=2)
        else:  # text
            summary = exporter.get_summary()
            metrics_output = _format_text_summary(summary)

        if output:
            # Write to file
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(metrics_output)
            console.print(f"[green]✓[/green] Metrics exported to: {output}")
        else:
            # Write to stdout
            print(metrics_output)

    except Exception as e:
        console.print(f"[red]✗[/red] Failed to export metrics: {e}", file=sys.stderr)
        sys.exit(1)


@metrics.command()
@click.option(
    '--watch',
    '-w',
    is_flag=True,
    help='Watch mode - refresh every 5 seconds'
)
def show(watch):
    """
    Show current metrics summary.

    Examples:
        # Show metrics once
        vaulytica metrics show

        # Watch metrics (refresh every 5 seconds)
        vaulytica metrics show --watch
    """
    import time

    try:
        while True:
            exporter = get_exporter()
            summary = exporter.get_summary()

            # Clear screen in watch mode
            if watch:
                console.clear()

            # Create metrics table
            table = Table(title="Vaulytica Metrics", show_header=True, header_style="bold magenta")
            table.add_column("Metric", style="cyan", no_wrap=True)
            table.add_column("Value", style="green", justify="right")

            # Add rows
            table.add_row("Uptime", _format_duration(summary['uptime_seconds']))
            table.add_row("Total Scans", str(int(summary['total_scans'])))
            table.add_row("Total Files Scanned", str(int(summary['total_files_scanned'])))
            table.add_row("Total Issues Found", str(int(summary['total_issues_found'])))
            table.add_row("Total PII Detections", str(int(summary['total_pii_detections'])))
            table.add_row("Total Errors", str(int(summary['total_errors'])))
            table.add_row("Active Scans", str(int(summary['active_scans'])))
            table.add_row("Cache Hit Rate", f"{summary['cache_hit_rate']:.2%}")
            table.add_row("Cache Size", str(int(summary['cache_size'])))

            console.print(table)

            if not watch:
                break

            console.print("\n[dim]Refreshing in 5 seconds... (Ctrl+C to stop)[/dim]")
            time.sleep(5)

    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped watching metrics[/yellow]")
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to show metrics: {e}", file=sys.stderr)
        sys.exit(1)


@metrics.command()
def reset():
    """
    Reset all metrics to zero.

    WARNING: This will clear all collected metrics data.
    """
    try:
        from vaulytica.core.monitoring.prometheus_exporter import reset_exporter

        if click.confirm("Are you sure you want to reset all metrics?"):
            reset_exporter()
            console.print("[green]✓[/green] All metrics have been reset")
        else:
            console.print("[yellow]Cancelled[/yellow]")

    except Exception as e:
        console.print(f"[red]✗[/red] Failed to reset metrics: {e}", file=sys.stderr)
        sys.exit(1)


@metrics.command()
@click.option(
    '--port',
    '-p',
    type=int,
    default=9090,
    help='Port to serve metrics on (default: 9090)'
)
@click.option(
    '--host',
    '-h',
    default='0.0.0.0',
    help='Host to bind to (default: 0.0.0.0)'
)
def serve(port, host):
    """
    Start HTTP server to serve Prometheus metrics.

    This starts a simple HTTP server that exposes metrics at /metrics endpoint.
    Useful for Prometheus scraping.

    Examples:
        # Start server on default port 9090
        vaulytica metrics serve

        # Start server on custom port
        vaulytica metrics serve --port 8080

        # Bind to localhost only
        vaulytica metrics serve --host 127.0.0.1
    """
    try:
        from http.server import HTTPServer, BaseHTTPRequestHandler

        exporter = get_exporter()

        class MetricsHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/metrics':
                    metrics_output = exporter.export_metrics()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain; version=0.0.4')
                    self.end_headers()
                    self.wfile.write(metrics_output.encode('utf-8'))
                elif self.path == '/health':
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b'OK')
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format, *args):
                # Suppress default logging
                pass

        server = HTTPServer((host, port), MetricsHandler)

        console.print(Panel(
            f"[green]Prometheus metrics server started[/green]\n\n"
            f"Metrics endpoint: http://{host}:{port}/metrics\n"
            f"Health endpoint:  http://{host}:{port}/health\n\n"
            f"Press Ctrl+C to stop",
            title="Metrics Server",
            border_style="green"
        ))

        server.serve_forever()

    except KeyboardInterrupt:
        console.print("\n[yellow]Metrics server stopped[/yellow]")
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to start metrics server: {e}", file=sys.stderr)
        sys.exit(1)


def _format_duration(seconds: float) -> str:
    """Format duration in human-readable format."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f}h"
    else:
        days = seconds / 86400
        return f"{days:.1f}d"


def _format_text_summary(summary: dict) -> str:
    """Format summary as plain text."""
    lines = [
        "Vaulytica Metrics Summary",
        "=" * 40,
        f"Uptime:              {_format_duration(summary['uptime_seconds'])}",
        f"Total Scans:         {int(summary['total_scans'])}",
        f"Total Files Scanned: {int(summary['total_files_scanned'])}",
        f"Total Issues Found:  {int(summary['total_issues_found'])}",
        f"Total PII Detections: {int(summary['total_pii_detections'])}",
        f"Total Errors:        {int(summary['total_errors'])}",
        f"Active Scans:        {int(summary['active_scans'])}",
        f"Cache Hit Rate:      {summary['cache_hit_rate']:.2%}",
        f"Cache Size:          {int(summary['cache_size'])}",
    ]
    return "\n".join(lines)

