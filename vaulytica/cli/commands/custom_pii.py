"""CLI commands for managing custom PII patterns."""

import click
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import structlog

from vaulytica.core.pii.custom_patterns import CustomPIIPatternManager

logger = structlog.get_logger(__name__)
console = Console()


@click.group(name="custom-pii")
def custom_pii_group():
    """Manage custom PII patterns for industry-specific detection."""
    pass


@custom_pii_group.command(name="list")
@click.option(
    "--config",
    type=click.Path(exists=True, path_type=Path),
    help="Path to custom patterns configuration file",
)
@click.option(
    "--category",
    type=str,
    help="Filter by category",
)
@click.option(
    "--severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    help="Filter by severity",
)
@click.option(
    "--enabled-only",
    is_flag=True,
    help="Show only enabled patterns",
)
def list_patterns_command(config, category, severity, enabled_only):
    """List all custom PII patterns."""
    try:
        manager = CustomPIIPatternManager(config_path=config)
        patterns = manager.get_all_patterns()

        # Apply filters
        if category:
            patterns = [p for p in patterns if p.category == category]
        if severity:
            patterns = [p for p in patterns if p.severity == severity]
        if enabled_only:
            patterns = [p for p in patterns if p.enabled]

        if not patterns:
            console.print("[yellow]No custom PII patterns found.[/yellow]")
            return

        # Create table
        table = Table(title="Custom PII Patterns", show_header=True, header_style="bold magenta")
        table.add_column("Name", style="cyan")
        table.add_column("Category", style="green")
        table.add_column("Severity", style="yellow")
        table.add_column("Enabled", style="blue")
        table.add_column("Description")

        for pattern in patterns:
            enabled_icon = "✓" if pattern.enabled else "✗"
            severity_color = {
                "low": "green",
                "medium": "yellow",
                "high": "orange1",
                "critical": "red",
            }.get(pattern.severity, "white")

            table.add_row(
                pattern.name,
                pattern.category,
                f"[{severity_color}]{pattern.severity}[/{severity_color}]",
                enabled_icon,
                pattern.description[:50] + "..." if len(pattern.description) > 50 else pattern.description,
            )

        console.print(table)

        # Show statistics
        stats = manager.get_statistics()
        console.print(f"\n[bold]Total Patterns:[/bold] {stats['total_patterns']}")
        console.print(f"[bold]Enabled:[/bold] {stats['enabled_patterns']}")
        console.print(f"[bold]Disabled:[/bold] {stats['disabled_patterns']}")

    except Exception as e:
        console.print(f"[red]Error listing patterns: {e}[/red]")
        logger.error("list_patterns_failed", error=str(e))
        raise click.Abort()


@custom_pii_group.command(name="add")
@click.option(
    "--config",
    type=click.Path(path_type=Path),
    required=True,
    help="Path to custom patterns configuration file",
)
@click.option("--name", type=str, required=True, help="Pattern name")
@click.option("--pattern", type=str, required=True, help="Regex pattern")
@click.option("--description", type=str, required=True, help="Pattern description")
@click.option(
    "--severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="medium",
    help="Severity level",
)
@click.option("--category", type=str, default="custom", help="Pattern category")
def add_pattern_command(config, name, pattern, description, severity, category):
    """Add a new custom PII pattern."""
    try:
        manager = CustomPIIPatternManager(config_path=config)

        # Validate pattern
        is_valid, error_msg = manager.validate_pattern(pattern)
        if not is_valid:
            console.print(f"[red]Invalid regex pattern: {error_msg}[/red]")
            raise click.Abort()

        # Add pattern
        success = manager.add_pattern(
            name=name,
            pattern=pattern,
            description=description,
            severity=severity,
            category=category,
        )

        if success:
            manager.save_patterns()
            console.print(f"[green]✓ Pattern '{name}' added successfully![/green]")
            console.print(f"  Category: {category}")
            console.print(f"  Severity: {severity}")
            console.print(f"  Pattern: {pattern}")
        else:
            console.print(f"[red]Failed to add pattern '{name}'[/red]")
            raise click.Abort()

    except Exception as e:
        console.print(f"[red]Error adding pattern: {e}[/red]")
        logger.error("add_pattern_failed", error=str(e))
        raise click.Abort()


@custom_pii_group.command(name="remove")
@click.option(
    "--config",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to custom patterns configuration file",
)
@click.option("--name", type=str, required=True, help="Pattern name to remove")
@click.option("--yes", is_flag=True, help="Skip confirmation")
def remove_pattern_command(config, name, yes):
    """Remove a custom PII pattern."""
    try:
        manager = CustomPIIPatternManager(config_path=config)

        pattern = manager.get_pattern(name)
        if not pattern:
            console.print(f"[red]Pattern '{name}' not found[/red]")
            raise click.Abort()

        if not yes:
            if not click.confirm(f"Remove pattern '{name}'?"):
                console.print("[yellow]Cancelled[/yellow]")
                return

        success = manager.remove_pattern(name)
        if success:
            manager.save_patterns()
            console.print(f"[green]✓ Pattern '{name}' removed successfully![/green]")
        else:
            console.print(f"[red]Failed to remove pattern '{name}'[/red]")
            raise click.Abort()

    except Exception as e:
        console.print(f"[red]Error removing pattern: {e}[/red]")
        logger.error("remove_pattern_failed", error=str(e))
        raise click.Abort()


@custom_pii_group.command(name="enable")
@click.option(
    "--config",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to custom patterns configuration file",
)
@click.option("--name", type=str, required=True, help="Pattern name to enable")
def enable_pattern_command(config, name):
    """Enable a custom PII pattern."""
    try:
        manager = CustomPIIPatternManager(config_path=config)

        success = manager.enable_pattern(name)
        if success:
            manager.save_patterns()
            console.print(f"[green]✓ Pattern '{name}' enabled![/green]")
        else:
            console.print(f"[red]Pattern '{name}' not found[/red]")
            raise click.Abort()

    except Exception as e:
        console.print(f"[red]Error enabling pattern: {e}[/red]")
        logger.error("enable_pattern_failed", error=str(e))
        raise click.Abort()


@custom_pii_group.command(name="disable")
@click.option(
    "--config",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to custom patterns configuration file",
)
@click.option("--name", type=str, required=True, help="Pattern name to disable")
def disable_pattern_command(config, name):
    """Disable a custom PII pattern."""
    try:
        manager = CustomPIIPatternManager(config_path=config)

        success = manager.disable_pattern(name)
        if success:
            manager.save_patterns()
            console.print(f"[yellow]Pattern '{name}' disabled[/yellow]")
        else:
            console.print(f"[red]Pattern '{name}' not found[/red]")
            raise click.Abort()

    except Exception as e:
        console.print(f"[red]Error disabling pattern: {e}[/red]")
        logger.error("disable_pattern_failed", error=str(e))
        raise click.Abort()


@custom_pii_group.command(name="test")
@click.option(
    "--config",
    type=click.Path(exists=True, path_type=Path),
    help="Path to custom patterns configuration file",
)
@click.option("--name", type=str, help="Test specific pattern by name")
@click.option("--text", type=str, required=True, help="Text to test against patterns")
def test_pattern_command(config, name, text):
    """Test custom PII patterns against sample text."""
    try:
        manager = CustomPIIPatternManager(config_path=config)

        if name:
            # Test specific pattern
            pattern = manager.get_pattern(name)
            if not pattern:
                console.print(f"[red]Pattern '{name}' not found[/red]")
                raise click.Abort()

            matches = pattern.matches(text)
            if matches:
                console.print(f"[green]✓ Pattern '{name}' matched![/green]")
                console.print(f"  Matches: {matches}")
            else:
                console.print(f"[yellow]Pattern '{name}' did not match[/yellow]")
        else:
            # Test all patterns
            results = manager.scan_text(text)
            if results:
                console.print("[green]✓ Found matches:[/green]")
                for pattern_name, matches in results.items():
                    console.print(f"  {pattern_name}: {matches}")
            else:
                console.print("[yellow]No patterns matched[/yellow]")

    except Exception as e:
        console.print(f"[red]Error testing pattern: {e}[/red]")
        logger.error("test_pattern_failed", error=str(e))
        raise click.Abort()


@custom_pii_group.command(name="validate")
@click.option("--pattern", type=str, required=True, help="Regex pattern to validate")
def validate_pattern_command(pattern):
    """Validate a regex pattern."""
    try:
        manager = CustomPIIPatternManager()
        is_valid, error_msg = manager.validate_pattern(pattern)

        if is_valid:
            console.print("[green]✓ Pattern is valid![/green]")
            console.print(f"  Pattern: {pattern}")
        else:
            console.print("[red]✗ Pattern is invalid[/red]")
            console.print(f"  Error: {error_msg}")
            raise click.Abort()

    except Exception as e:
        console.print(f"[red]Error validating pattern: {e}[/red]")
        logger.error("validate_pattern_failed", error=str(e))
        raise click.Abort()


@custom_pii_group.command(name="stats")
@click.option(
    "--config",
    type=click.Path(exists=True, path_type=Path),
    help="Path to custom patterns configuration file",
)
def stats_command(config):
    """Show statistics about custom PII patterns."""
    try:
        manager = CustomPIIPatternManager(config_path=config)
        stats = manager.get_statistics()

        panel = Panel.fit(
            f"""[bold]Total Patterns:[/bold] {stats['total_patterns']}
[bold]Enabled:[/bold] {stats['enabled_patterns']}
[bold]Disabled:[/bold] {stats['disabled_patterns']}

[bold]By Category:[/bold]
{chr(10).join(f"  {cat}: {count}" for cat, count in stats['categories'].items())}

[bold]By Severity:[/bold]
{chr(10).join(f"  {sev}: {count}" for sev, count in stats['severities'].items())}""",
            title="Custom PII Pattern Statistics",
            border_style="cyan",
        )

        console.print(panel)

    except Exception as e:
        console.print(f"[red]Error getting statistics: {e}[/red]")
        logger.error("stats_failed", error=str(e))
        raise click.Abort()

