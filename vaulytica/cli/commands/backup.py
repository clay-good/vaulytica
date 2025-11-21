"""Data export and backup commands."""

from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


@click.group(name="backup")
def backup_group():
    """Data export and backup commands."""
    pass


@backup_group.command(name="users")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "csv"]),
    default="json",
    help="Output format (default: json)",
)
@click.option(
    "--backup-dir",
    type=click.Path(),
    help="Backup directory (default: ./backups)",
)
@click.pass_context
def backup_users(
    ctx: click.Context,
    output_format: str,
    backup_dir: Optional[Path],
):
    """Backup all user data."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.backup.backup_manager import BackupManager

    console.print("[cyan]Starting user backup...[/cyan]\n")

    # Load configuration
    config_path = ctx.obj.get("config_path")
    config = load_config(config_path)

    # Create client
    client = create_client_from_config(config)

    # Set backup directory
    if not backup_dir:
        backup_dir = Path("./backups")

    # Create backup manager
    backup_manager = BackupManager(
        client=client,
        backup_dir=backup_dir,
        domain=config.domain,
    )

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Backing up users...", total=None)

            # Perform backup
            metadata = backup_manager.backup_users(output_format=output_format)

            progress.update(task, completed=True)

        # Display success
        console.print(Panel.fit(
            f"[green]✓ User backup completed![/green]\n\n"
            f"Backup ID: {metadata.backup_id}\n"
            f"Users backed up: {metadata.item_count:,}\n"
            f"File size: {metadata.size_bytes / 1024 / 1024:.2f} MB\n"
            f"Location: {metadata.backup_path}",
            border_style="green",
        ))

    except Exception as e:
        console.print(f"[red]Error backing up users: {e}[/red]")
        raise click.Abort()


@backup_group.command(name="groups")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "csv"]),
    default="json",
    help="Output format (default: json)",
)
@click.option(
    "--backup-dir",
    type=click.Path(),
    help="Backup directory (default: ./backups)",
)
@click.pass_context
def backup_groups(
    ctx: click.Context,
    output_format: str,
    backup_dir: Optional[Path],
):
    """Backup all group data."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.backup.backup_manager import BackupManager

    console.print("[cyan]Starting group backup...[/cyan]\n")

    # Load configuration
    config_path = ctx.obj.get("config_path")
    config = load_config(config_path)

    # Create client
    client = create_client_from_config(config)

    # Set backup directory
    if not backup_dir:
        backup_dir = Path("./backups")

    # Create backup manager
    backup_manager = BackupManager(
        client=client,
        backup_dir=backup_dir,
        domain=config.domain,
    )

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Backing up groups...", total=None)

            # Perform backup
            metadata = backup_manager.backup_groups(output_format=output_format)

            progress.update(task, completed=True)

        # Display success
        console.print(Panel.fit(
            f"[green]✓ Group backup completed![/green]\n\n"
            f"Backup ID: {metadata.backup_id}\n"
            f"Groups backed up: {metadata.item_count:,}\n"
            f"File size: {metadata.size_bytes / 1024 / 1024:.2f} MB\n"
            f"Location: {metadata.backup_path}",
            border_style="green",
        ))

    except Exception as e:
        console.print(f"[red]Error backing up groups: {e}[/red]")
        raise click.Abort()


@backup_group.command(name="org-units")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "csv"]),
    default="json",
    help="Output format (default: json)",
)
@click.option(
    "--backup-dir",
    type=click.Path(),
    help="Backup directory (default: ./backups)",
)
@click.pass_context
def backup_org_units(
    ctx: click.Context,
    output_format: str,
    backup_dir: Optional[Path],
):
    """Backup all organizational unit data."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.backup.backup_manager import BackupManager

    console.print("[cyan]Starting organizational unit backup...[/cyan]\n")

    # Load configuration
    config_path = ctx.obj.get("config_path")
    config = load_config(config_path)

    # Create client
    client = create_client_from_config(config)

    # Set backup directory
    if not backup_dir:
        backup_dir = Path("./backups")

    # Create backup manager
    backup_manager = BackupManager(
        client=client,
        backup_dir=backup_dir,
        domain=config.domain,
    )

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Backing up organizational units...", total=None)

            # Perform backup
            metadata = backup_manager.backup_org_units(output_format=output_format)

            progress.update(task, completed=True)

        # Display success
        console.print(Panel.fit(
            f"[green]✓ Organizational unit backup completed![/green]\n\n"
            f"Backup ID: {metadata.backup_id}\n"
            f"OUs backed up: {metadata.item_count:,}\n"
            f"File size: {metadata.size_bytes / 1024 / 1024:.2f} MB\n"
            f"Location: {metadata.backup_path}",
            border_style="green",
        ))

    except Exception as e:
        console.print(f"[red]Error backing up organizational units: {e}[/red]")
        raise click.Abort()


@backup_group.command(name="full")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "csv"]),
    default="json",
    help="Output format (default: json)",
)
@click.option(
    "--backup-dir",
    type=click.Path(),
    help="Backup directory (default: ./backups)",
)
@click.pass_context
def backup_full(
    ctx: click.Context,
    output_format: str,
    backup_dir: Optional[Path],
):
    """Perform a full backup of all data."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.backup.backup_manager import BackupManager

    console.print("[cyan]Starting full backup...[/cyan]\n")

    # Load configuration
    config_path = ctx.obj.get("config_path")
    config = load_config(config_path)

    # Create client
    client = create_client_from_config(config)

    # Set backup directory
    if not backup_dir:
        backup_dir = Path("./backups")

    # Create backup manager
    backup_manager = BackupManager(
        client=client,
        backup_dir=backup_dir,
        domain=config.domain,
    )

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Performing full backup...", total=None)

            # Perform backup
            backups = backup_manager.backup_full(output_format=output_format)

            progress.update(task, completed=True)

        # Display success
        total_items = sum(b.item_count for b in backups)
        total_size = sum(b.size_bytes for b in backups)

        console.print(Panel.fit(
            f"[green]✓ Full backup completed![/green]\n\n"
            f"Backups created: {len(backups)}\n"
            f"Total items: {total_items:,}\n"
            f"Total size: {total_size / 1024 / 1024:.2f} MB\n"
            f"Location: {backup_dir}",
            border_style="green",
        ))

    except Exception as e:
        console.print(f"[red]Error performing full backup: {e}[/red]")
        raise click.Abort()


@backup_group.command(name="list")
@click.option(
    "--backup-dir",
    type=click.Path(),
    help="Backup directory (default: ./backups)",
)
@click.pass_context
def list_backups(ctx: click.Context, backup_dir: Optional[Path]):
    """List all available backups."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.backup.backup_manager import BackupManager

    console.print("[cyan]Listing backups...[/cyan]\n")

    # Load configuration
    config_path = ctx.obj.get("config_path")
    config = load_config(config_path)

    # Create client
    client = create_client_from_config(config)

    # Set backup directory
    if not backup_dir:
        backup_dir = Path("./backups")

    # Create backup manager
    backup_manager = BackupManager(
        client=client,
        backup_dir=backup_dir,
        domain=config.domain,
    )

    try:
        # List backups
        backups = backup_manager.list_backups()

        if not backups:
            console.print("[yellow]No backups found.[/yellow]")
            return

        # Display results
        table = Table(title=f"Available Backups ({len(backups)} total)")
        table.add_column("Backup ID", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Created", style="blue")
        table.add_column("Items", style="yellow", justify="right")
        table.add_column("Size", style="magenta", justify="right")
        table.add_column("Status", style="white")

        for backup in backups:
            size_mb = backup.size_bytes / 1024 / 1024
            table.add_row(
                backup.backup_id,
                backup.backup_type,
                backup.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                f"{backup.item_count:,}",
                f"{size_mb:.2f} MB",
                backup.status,
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error listing backups: {e}[/red]")
        raise click.Abort()

