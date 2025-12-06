"""CLI commands for trend analysis and historical reporting."""

from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
import json

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from vaulytica.storage.history import MetricType, get_history_manager
from vaulytica.core.analyzers.trend_analyzer import TrendAnalyzer, TrendDirection

console = Console()


@click.group()
def trend():
    """Trend analysis and historical reporting."""
    pass


@trend.command("analyze")
@click.option(
    "--metric",
    "-m",
    type=click.Choice([m.value for m in MetricType]),
    required=True,
    help="Metric to analyze",
)
@click.option(
    "--domain",
    "-d",
    required=True,
    help="Domain to analyze",
)
@click.option(
    "--days",
    type=int,
    default=30,
    help="Number of days to analyze (default: 30)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path (JSON)",
)
def analyze_trend(
    metric: str,
    domain: str,
    days: int,
    output: Optional[Path],
) -> None:
    """Analyze trend for a specific metric.

    Examples:

        vaulytica trend analyze -m external_shares -d company.com --days 30

        vaulytica trend analyze -m users_without_2fa -d company.com --days 90
    """
    analyzer = TrendAnalyzer()
    metric_type = MetricType(metric)

    console.print(f"[cyan]Analyzing trend for {metric}...[/cyan]\n")

    trend_data = analyzer.analyze_trend(metric_type, domain, days)

    if not trend_data:
        console.print("[yellow]Insufficient data for trend analysis.[/yellow]")
        console.print("Ensure you have recorded metrics over the specified period.")
        return

    # Determine color based on trend direction
    if trend_data.trend_direction == TrendDirection.IMPROVING.value:
        direction_color = "green"
        direction_icon = "[+]"
    elif trend_data.trend_direction == TrendDirection.DEGRADING.value:
        direction_color = "red"
        direction_icon = "[-]"
    else:
        direction_color = "yellow"
        direction_icon = "[=]"

    # Display results
    console.print(Panel(f"""
[bold]Metric:[/bold] {metric_type.value}
[bold]Domain:[/bold] {domain}
[bold]Period:[/bold] {days} days

[bold]Current Value:[/bold] {trend_data.current_value:.1f}
[bold]Previous Value:[/bold] {trend_data.previous_value:.1f}
[bold]Change:[/bold] {trend_data.change_absolute:+.1f} ({trend_data.change_percent:+.1f}%)
[bold]Trend:[/bold] [{direction_color}]{direction_icon} {trend_data.trend_direction.upper()}[/{direction_color}]
[bold]Data Points:[/bold] {len(trend_data.data_points)}
    """.strip(), title="Trend Analysis", border_style="cyan"))

    # Show data points table
    if len(trend_data.data_points) > 0:
        console.print("\n[bold]Historical Data:[/bold]")

        table = Table(show_header=True, header_style="bold")
        table.add_column("Date")
        table.add_column("Value", justify="right")

        # Show last 10 data points
        for snapshot in trend_data.data_points[-10:]:
            table.add_row(
                snapshot.timestamp.strftime("%Y-%m-%d %H:%M"),
                f"{snapshot.value:.1f}",
            )

        console.print(table)

        if len(trend_data.data_points) > 10:
            console.print(f"[dim]... and {len(trend_data.data_points) - 10} more data points[/dim]")

    # Save to file if requested
    if output:
        data = {
            "metric_type": metric_type.value,
            "domain": domain,
            "period_days": days,
            "current_value": trend_data.current_value,
            "previous_value": trend_data.previous_value,
            "change_absolute": trend_data.change_absolute,
            "change_percent": trend_data.change_percent,
            "trend_direction": trend_data.trend_direction,
            "data_points": [
                {"timestamp": s.timestamp.isoformat(), "value": s.value}
                for s in trend_data.data_points
            ],
        }

        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w") as f:
            json.dump(data, f, indent=2)

        console.print(f"\n[green]Results saved to {output}[/green]")


@trend.command("compare")
@click.option(
    "--metric",
    "-m",
    type=click.Choice([m.value for m in MetricType]),
    required=True,
    help="Metric to compare",
)
@click.option(
    "--domain",
    "-d",
    required=True,
    help="Domain to analyze",
)
@click.option(
    "--from-date",
    type=click.DateTime(formats=["%Y-%m-%d"]),
    required=True,
    help="Start of first period (YYYY-MM-DD)",
)
@click.option(
    "--to-date",
    type=click.DateTime(formats=["%Y-%m-%d"]),
    required=True,
    help="End of first period (YYYY-MM-DD)",
)
@click.option(
    "--compare-from",
    type=click.DateTime(formats=["%Y-%m-%d"]),
    help="Start of second period (default: after first period)",
)
@click.option(
    "--compare-to",
    type=click.DateTime(formats=["%Y-%m-%d"]),
    help="End of second period (default: today)",
)
def compare_periods(
    metric: str,
    domain: str,
    from_date: datetime,
    to_date: datetime,
    compare_from: Optional[datetime],
    compare_to: Optional[datetime],
) -> None:
    """Compare metrics between two time periods.

    Examples:

        vaulytica trend compare -m external_shares -d company.com \\
            --from-date 2024-01-01 --to-date 2024-01-31 \\
            --compare-from 2024-02-01 --compare-to 2024-02-28
    """
    analyzer = TrendAnalyzer()
    metric_type = MetricType(metric)

    # Set defaults for comparison period
    period1_start = from_date.replace(tzinfo=timezone.utc)
    period1_end = to_date.replace(tzinfo=timezone.utc)

    if compare_from:
        period2_start = compare_from.replace(tzinfo=timezone.utc)
    else:
        period2_start = period1_end + timedelta(days=1)

    if compare_to:
        period2_end = compare_to.replace(tzinfo=timezone.utc)
    else:
        period2_end = datetime.now(timezone.utc)

    console.print(f"[cyan]Comparing {metric} between periods...[/cyan]\n")

    result = analyzer.compare_periods(
        metric_type=metric_type,
        domain=domain,
        period1_start=period1_start,
        period1_end=period1_end,
        period2_start=period2_start,
        period2_end=period2_end,
    )

    if not result:
        console.print("[yellow]Insufficient data for comparison.[/yellow]")
        return

    # Determine color based on trend
    if result.trend_direction == TrendDirection.IMPROVING:
        direction_color = "green"
    elif result.trend_direction == TrendDirection.DEGRADING:
        direction_color = "red"
    else:
        direction_color = "yellow"

    console.print(Panel(f"""
[bold]Metric:[/bold] {metric_type.value}
[bold]Domain:[/bold] {domain}

[bold]Period 1:[/bold] {period1_start.strftime('%Y-%m-%d')} to {period1_end.strftime('%Y-%m-%d')}
  Average: {result.period1_avg:.1f}

[bold]Period 2:[/bold] {period2_start.strftime('%Y-%m-%d')} to {period2_end.strftime('%Y-%m-%d')}
  Average: {result.period2_avg:.1f}

[bold]Change:[/bold] {result.change_absolute:+.1f} ({result.change_percent:+.1f}%)
[bold]Trend:[/bold] [{direction_color}]{result.trend_direction.value.upper()}[/{direction_color}]
    """.strip(), title="Period Comparison", border_style="cyan"))


@trend.command("report")
@click.option(
    "--domain",
    "-d",
    required=True,
    help="Domain to analyze",
)
@click.option(
    "--days",
    type=int,
    default=30,
    help="Number of days to analyze (default: 30)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path (JSON)",
)
def generate_report(
    domain: str,
    days: int,
    output: Optional[Path],
) -> None:
    """Generate comprehensive trend report for all metrics.

    Examples:

        vaulytica trend report -d company.com --days 30

        vaulytica trend report -d company.com --days 90 -o report.json
    """
    analyzer = TrendAnalyzer()

    console.print(f"[cyan]Generating trend report for {domain}...[/cyan]\n")

    report = analyzer.generate_trend_report(domain, days)

    # Display summary
    console.print(Panel(f"""
[bold]Domain:[/bold] {report.domain}
[bold]Period:[/bold] {report.period_days} days
[bold]Generated:[/bold] {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}

[bold]Summary:[/bold]
  Metrics Analyzed: {report.summary.get('total_metrics_analyzed', 0)}
  Improving: [green]{report.summary.get('improving', 0)}[/green]
  Degrading: [red]{report.summary.get('degrading', 0)}[/red]
  Stable: [yellow]{report.summary.get('stable', 0)}[/yellow]
  Anomalies Detected: {report.summary.get('anomalies_detected', 0)}
  Overall Direction: {report.summary.get('overall_direction', 'unknown').upper()}
    """.strip(), title="Trend Report", border_style="cyan"))

    # Display trends table
    if report.trends:
        console.print("\n[bold]Metric Trends:[/bold]")

        table = Table(show_header=True, header_style="bold")
        table.add_column("Metric")
        table.add_column("Current", justify="right")
        table.add_column("Previous", justify="right")
        table.add_column("Change", justify="right")
        table.add_column("Trend")

        for trend in report.trends:
            if trend.trend_direction == TrendDirection.IMPROVING.value:
                trend_str = "[green]IMPROVING[/green]"
            elif trend.trend_direction == TrendDirection.DEGRADING.value:
                trend_str = "[red]DEGRADING[/red]"
            else:
                trend_str = "[yellow]STABLE[/yellow]"

            table.add_row(
                trend.metric_type.value,
                f"{trend.current_value:.1f}",
                f"{trend.previous_value:.1f}",
                f"{trend.change_percent:+.1f}%",
                trend_str,
            )

        console.print(table)

    # Display anomalies
    if report.anomalies:
        console.print("\n[bold]Detected Anomalies:[/bold]")

        for anomaly in report.anomalies:
            if anomaly.anomaly_type.value == "spike":
                console.print(f"  [red]SPIKE[/red] {anomaly.metric_type.value}: {anomaly.description}")
            else:
                console.print(f"  [yellow]DROP[/yellow] {anomaly.metric_type.value}: {anomaly.description}")

    # Save to file if requested
    if output:
        data = {
            "domain": report.domain,
            "generated_at": report.generated_at.isoformat(),
            "period_days": report.period_days,
            "summary": report.summary,
            "trends": [
                {
                    "metric_type": t.metric_type.value,
                    "current_value": t.current_value,
                    "previous_value": t.previous_value,
                    "change_absolute": t.change_absolute,
                    "change_percent": t.change_percent,
                    "trend_direction": t.trend_direction,
                }
                for t in report.trends
            ],
            "anomalies": [
                {
                    "type": a.anomaly_type.value,
                    "metric": a.metric_type.value,
                    "timestamp": a.timestamp.isoformat(),
                    "value": a.value,
                    "expected": a.expected_value,
                    "deviation_percent": a.deviation_percent,
                    "description": a.description,
                }
                for a in report.anomalies
            ],
        }

        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w") as f:
            json.dump(data, f, indent=2)

        console.print(f"\n[green]Report saved to {output}[/green]")


@trend.command("week-over-week")
@click.option(
    "--metric",
    "-m",
    type=click.Choice([m.value for m in MetricType]),
    required=True,
    help="Metric to analyze",
)
@click.option(
    "--domain",
    "-d",
    required=True,
    help="Domain to analyze",
)
def week_over_week(metric: str, domain: str) -> None:
    """Show week-over-week change for a metric.

    Examples:

        vaulytica trend week-over-week -m external_shares -d company.com
    """
    analyzer = TrendAnalyzer()
    metric_type = MetricType(metric)

    result = analyzer.get_week_over_week_change(metric_type, domain)

    if not result:
        console.print("[yellow]Insufficient data for week-over-week comparison.[/yellow]")
        return

    if result.trend_direction == TrendDirection.IMPROVING:
        direction_color = "green"
    elif result.trend_direction == TrendDirection.DEGRADING:
        direction_color = "red"
    else:
        direction_color = "yellow"

    console.print(f"[bold]{metric_type.value}[/bold] - Week over Week")
    console.print(f"  Last Week Average: {result.period1_avg:.1f}")
    console.print(f"  This Week Average: {result.period2_avg:.1f}")
    console.print(f"  Change: {result.change_percent:+.1f}% [{direction_color}]{result.trend_direction.value}[/{direction_color}]")


@trend.command("month-over-month")
@click.option(
    "--metric",
    "-m",
    type=click.Choice([m.value for m in MetricType]),
    required=True,
    help="Metric to analyze",
)
@click.option(
    "--domain",
    "-d",
    required=True,
    help="Domain to analyze",
)
def month_over_month(metric: str, domain: str) -> None:
    """Show month-over-month change for a metric.

    Examples:

        vaulytica trend month-over-month -m users_without_2fa -d company.com
    """
    analyzer = TrendAnalyzer()
    metric_type = MetricType(metric)

    result = analyzer.get_month_over_month_change(metric_type, domain)

    if not result:
        console.print("[yellow]Insufficient data for month-over-month comparison.[/yellow]")
        return

    if result.trend_direction == TrendDirection.IMPROVING:
        direction_color = "green"
    elif result.trend_direction == TrendDirection.DEGRADING:
        direction_color = "red"
    else:
        direction_color = "yellow"

    console.print(f"[bold]{metric_type.value}[/bold] - Month over Month")
    console.print(f"  Last Month Average: {result.period1_avg:.1f}")
    console.print(f"  This Month Average: {result.period2_avg:.1f}")
    console.print(f"  Change: {result.change_percent:+.1f}% [{direction_color}]{result.trend_direction.value}[/{direction_color}]")


@trend.command("record")
@click.option(
    "--metric",
    "-m",
    type=click.Choice([m.value for m in MetricType]),
    required=True,
    help="Metric type to record",
)
@click.option(
    "--value",
    "-v",
    type=float,
    required=True,
    help="Metric value",
)
@click.option(
    "--domain",
    "-d",
    required=True,
    help="Domain",
)
def record_metric(metric: str, value: float, domain: str) -> None:
    """Manually record a metric value for trend tracking.

    Examples:

        vaulytica trend record -m external_shares -v 42 -d company.com

        vaulytica trend record -m security_score -v 85.5 -d company.com
    """
    history = get_history_manager()
    metric_type = MetricType(metric)

    history.record_metric(metric_type, value, domain)

    console.print(f"[green]Recorded:[/green] {metric_type.value} = {value} for {domain}")
