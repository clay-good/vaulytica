"""Config command implementation."""

import click
from rich.console import Console
from rich.syntax import Syntax

console = Console()


def config_command(ctx: click.Context) -> None:
    """Show current configuration."""
    from vaulytica.config.loader import load_config

    config_path = ctx.obj.get("config_path")
    console.print(f"[cyan]Configuration file:[/cyan] {config_path}\n")

    try:
        # Read and display the raw config file
        with open(config_path, "r") as f:
            config_content = f.read()

        syntax = Syntax(config_content, "yaml", theme="monokai", line_numbers=True)
        console.print(syntax)

    except FileNotFoundError:
        console.print(
            f"[red]Configuration file not found: {config_path}[/red]\n"
            f"Run [cyan]vaulytica init[/cyan] to create one."
        )
        raise click.Abort()
    except Exception as e:
        console.print(f"[red]Error reading configuration: {e}[/red]")
        raise click.Abort()

