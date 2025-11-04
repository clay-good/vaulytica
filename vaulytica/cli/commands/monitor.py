"""Monitoring and health check commands."""

import json
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.json import JSON

from vaulytica.core.monitoring import (
    HealthChecker,
    get_metrics_collector,
    get_performance_monitor,
)
from vaulytica.core.auth.client import GoogleWorkspaceClient
from vaulytica.config.loader import load_config

console = Console()


@click.group(name="monitor")
def monitor_group():
    """Monitoring and health check commands."""
    pass


@monitor_group.command(name="health")
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True),
    help="Path to configuration file",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
def health_command(config: Optional[str], format: str):
    """Check system health."""
    console.print("[bold blue]Running health checks...[/bold blue]\n")

    # Load config and create client if available
    client = None
    if config:
        try:
            cfg = load_config(config)
            client = GoogleWorkspaceClient.from_config(cfg)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load config: {e}[/yellow]\n")

    # Run health check
    checker = HealthChecker(client=client)
    status = checker.check_health()

    if format == "json":
        # JSON output
        output = {
            "healthy": status.healthy,
            "status": status.status,
            "checks": status.checks,
            "details": status.details,
            "timestamp": status.timestamp.isoformat(),
        }
        console.print(JSON(json.dumps(output, indent=2)))
    else:
        # Table output
        _display_health_status(status)

    # Exit with appropriate code
    if not status.healthy:
        raise click.Exit(1)


def _display_health_status(status):
    """Display health status in table format."""
    # Overall status
    status_color = {
        "healthy": "green",
        "degraded": "yellow",
        "unhealthy": "red",
    }

    color = status_color.get(status.status, "white")
    console.print(
        Panel(
            f"[bold {color}]{status.status.upper()}[/bold {color}]",
            title="Overall Status",
        )
    )
    console.print()

    # Checks table
    table = Table(title="Health Checks")
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Details")

    for check_name, check_result in status.checks.items():
        status_icon = "✓" if check_result else "✗"
        status_color = "green" if check_result else "red"

        # Get details
        details = []
        if check_name in status.details:
            check_details = status.details[check_name]
            if isinstance(check_details, dict):
                for key, value in check_details.items():
                    if key != "error":
                        details.append(f"{key}: {value}")

        details_str = "\n".join(details) if details else "-"

        table.add_row(
            check_name,
            f"[{status_color}]{status_icon}[/{status_color}]",
            details_str,
        )

    console.print(table)


@monitor_group.command(name="metrics")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["prometheus", "json", "table"]),
    default="table",
    help="Output format",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file (default: stdout)",
)
def metrics_command(format: str, output: Optional[str]):
    """Display metrics."""
    collector = get_metrics_collector()

    if format == "prometheus":
        # Prometheus format
        metrics_text = collector.export_prometheus()

        if output:
            with open(output, "w") as f:
                f.write(metrics_text)
            console.print(f"[green]Metrics exported to {output}[/green]")
        else:
            console.print(metrics_text)

    elif format == "json":
        # JSON format
        summary = collector.get_summary()

        if output:
            with open(output, "w") as f:
                json.dump(summary, f, indent=2)
            console.print(f"[green]Metrics exported to {output}[/green]")
        else:
            console.print(JSON(json.dumps(summary, indent=2)))

    else:
        # Table format
        _display_metrics_table(collector)


def _display_metrics_table(collector):
    """Display metrics in table format."""
    # Counters
    if collector.counters:
        table = Table(title="Counters")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="bold green", justify="right")

        for name, counter in collector.counters.items():
            table.add_row(name, str(counter.get()))

        console.print(table)
        console.print()

    # Gauges
    if collector.gauges:
        table = Table(title="Gauges")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="bold yellow", justify="right")

        for name, gauge in collector.gauges.items():
            table.add_row(name, f"{gauge.get():.2f}")

        console.print(table)
        console.print()

    # Histograms
    if collector.histograms:
        table = Table(title="Histograms")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", justify="right")
        table.add_column("Sum", justify="right")
        table.add_column("Avg", justify="right")

        for name, histogram in collector.histograms.items():
            stats = histogram.get_stats()
            table.add_row(
                name,
                str(stats["count"]),
                f"{stats['sum']:.2f}",
                f"{stats['avg']:.2f}",
            )

        console.print(table)


@monitor_group.command(name="performance")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
def performance_command(format: str):
    """Display performance statistics."""
    monitor = get_performance_monitor()
    stats = monitor.get_all_stats()

    if format == "json":
        console.print(JSON(json.dumps(stats, indent=2)))
    else:
        _display_performance_table(stats)


def _display_performance_table(stats: dict):
    """Display performance statistics in table format."""
    if not stats:
        console.print("[yellow]No performance data available[/yellow]")
        return

    table = Table(title="Performance Statistics")
    table.add_column("Operation", style="cyan")
    table.add_column("Count", justify="right")
    table.add_column("Min (ms)", justify="right")
    table.add_column("Avg (ms)", justify="right")
    table.add_column("P95 (ms)", justify="right")
    table.add_column("Max (ms)", justify="right")

    for operation, operation_stats in stats.items():
        table.add_row(
            operation,
            str(operation_stats["count"]),
            f"{operation_stats['min'] * 1000:.2f}",
            f"{operation_stats['avg'] * 1000:.2f}",
            f"{operation_stats['p95'] * 1000:.2f}",
            f"{operation_stats['max'] * 1000:.2f}",
        )

    console.print(table)


@monitor_group.command(name="system")
def system_command():
    """Display system information."""
    checker = HealthChecker()
    info = checker.get_system_info()

    table = Table(title="System Information")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold")

    for key, value in info.items():
        if isinstance(value, float):
            table.add_row(key, f"{value:.2f}")
        else:
            table.add_row(key, str(value))

    console.print(table)

