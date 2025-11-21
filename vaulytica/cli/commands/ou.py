"""Organizational Unit (OU) management commands."""

from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@click.group(name="ou")
def ou_group():
    """Organizational Unit (OU) management commands."""
    pass


@ou_group.command(name="list")
@click.option(
    "--parent",
    help="Parent OU path to filter by (e.g., /Engineering)",
)
@click.option(
    "--output",
    type=click.Path(),
    help="Save results to file (CSV or JSON)",
)
@click.pass_context
def list_ous(ctx: click.Context, parent: Optional[str], output: Optional[Path]):
    """List all organizational units."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.lifecycle.ou_manager import OUManager

    console.print("[cyan]Listing organizational units...[/cyan]\n")

    # Load configuration
    config_path = ctx.obj.get("config_path")
    config = load_config(config_path)

    # Create client
    client = create_client_from_config(config)

    # Create OU manager
    ou_manager = OUManager(client)

    try:
        # List OUs
        ous = ou_manager.list_ous(org_unit_path=parent)

        if not ous:
            console.print("[yellow]No organizational units found.[/yellow]")
            return

        # Display results
        table = Table(title=f"Organizational Units ({len(ous)} total)")
        table.add_column("Name", style="cyan")
        table.add_column("Path", style="green")
        table.add_column("Parent Path", style="blue")
        table.add_column("Block Inheritance", style="yellow")

        for ou in ous:
            table.add_row(
                ou.name,
                ou.org_unit_path,
                ou.parent_org_unit_path,
                "Yes" if ou.block_inheritance else "No",
            )

        console.print(table)

        # Save to file if requested
        if output:
            import json
            import csv

            output_path = Path(output)

            if output_path.suffix == ".json":
                with open(output_path, "w") as f:
                    json.dump(
                        [
                            {
                                "name": ou.name,
                                "org_unit_path": ou.org_unit_path,
                                "parent_org_unit_path": ou.parent_org_unit_path,
                                "description": ou.description,
                                "block_inheritance": ou.block_inheritance,
                            }
                            for ou in ous
                        ],
                        f,
                        indent=2,
                    )
            else:  # CSV
                with open(output_path, "w", newline="") as f:
                    writer = csv.DictWriter(
                        f,
                        fieldnames=["name", "org_unit_path", "parent_org_unit_path", "description", "block_inheritance"],
                    )
                    writer.writeheader()
                    for ou in ous:
                        writer.writerow({
                            "name": ou.name,
                            "org_unit_path": ou.org_unit_path,
                            "parent_org_unit_path": ou.parent_org_unit_path,
                            "description": ou.description or "",
                            "block_inheritance": ou.block_inheritance,
                        })

            console.print(f"\n[green]✓ Results saved to {output_path}[/green]")

    except Exception as e:
        console.print(f"[red]Error listing OUs: {e}[/red]")
        raise click.Abort()


@ou_group.command(name="get")
@click.argument("ou_path")
@click.pass_context
def get_ou(ctx: click.Context, ou_path: str):
    """Get details of a specific organizational unit."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.lifecycle.ou_manager import OUManager

    console.print(f"[cyan]Getting OU: {ou_path}...[/cyan]\n")

    # Load configuration
    config_path = ctx.obj.get("config_path")
    config = load_config(config_path)

    # Create client
    client = create_client_from_config(config)

    # Create OU manager
    ou_manager = OUManager(client)

    try:
        # Get OU
        ou = ou_manager.get_ou(ou_path)

        # Display results
        console.print(Panel.fit(
            f"[bold]Name:[/bold] {ou.name}\n"
            f"[bold]Path:[/bold] {ou.org_unit_path}\n"
            f"[bold]Parent Path:[/bold] {ou.parent_org_unit_path}\n"
            f"[bold]Description:[/bold] {ou.description or 'N/A'}\n"
            f"[bold]Block Inheritance:[/bold] {'Yes' if ou.block_inheritance else 'No'}",
            title="Organizational Unit Details",
            border_style="green",
        ))

    except Exception as e:
        console.print(f"[red]Error getting OU: {e}[/red]")
        raise click.Abort()


@ou_group.command(name="create")
@click.argument("name")
@click.option(
    "--parent",
    default="/",
    help="Parent OU path (default: /)",
)
@click.option(
    "--description",
    help="OU description",
)
@click.option(
    "--block-inheritance",
    is_flag=True,
    help="Block policy inheritance from parent",
)
@click.pass_context
def create_ou(
    ctx: click.Context,
    name: str,
    parent: str,
    description: Optional[str],
    block_inheritance: bool,
):
    """Create a new organizational unit."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.lifecycle.ou_manager import OUManager

    console.print(f"[cyan]Creating OU: {name}...[/cyan]\n")

    # Load configuration
    config_path = ctx.obj.get("config_path")
    config = load_config(config_path)

    # Create client
    client = create_client_from_config(config)

    # Create OU manager
    ou_manager = OUManager(client)

    try:
        # Create OU
        ou = ou_manager.create_ou(
            name=name,
            parent_org_unit_path=parent,
            description=description,
            block_inheritance=block_inheritance,
        )

        # Display success
        console.print(Panel.fit(
            f"[green]✓ OU created successfully![/green]\n\n"
            f"Name: {ou.name}\n"
            f"Path: {ou.org_unit_path}\n"
            f"Parent: {ou.parent_org_unit_path}\n"
            f"Description: {ou.description or 'N/A'}\n"
            f"Block Inheritance: {'Yes' if ou.block_inheritance else 'No'}",
            border_style="green",
        ))

    except Exception as e:
        console.print(f"[red]Error creating OU: {e}[/red]")
        raise click.Abort()


@ou_group.command(name="update")
@click.argument("ou_path")
@click.option("--name", help="New name")
@click.option("--description", help="New description")
@click.option("--parent", help="New parent OU path (moves the OU)")
@click.option("--block-inheritance/--no-block-inheritance", default=None, help="Block policy inheritance")
@click.pass_context
def update_ou(
    ctx: click.Context,
    ou_path: str,
    name: Optional[str],
    description: Optional[str],
    parent: Optional[str],
    block_inheritance: Optional[bool],
):
    """Update an organizational unit."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.lifecycle.ou_manager import OUManager

    console.print(f"[cyan]Updating OU: {ou_path}...[/cyan]\n")

    # Load configuration
    config_path = ctx.obj.get("config_path")
    config = load_config(config_path)

    # Create client
    client = create_client_from_config(config)

    # Create OU manager
    ou_manager = OUManager(client)

    try:
        # Update OU
        ou = ou_manager.update_ou(
            org_unit_path=ou_path,
            name=name,
            description=description,
            parent_org_unit_path=parent,
            block_inheritance=block_inheritance,
        )

        # Display success
        console.print(Panel.fit(
            f"[green]✓ OU updated successfully![/green]\n\n"
            f"Name: {ou.name}\n"
            f"Path: {ou.org_unit_path}\n"
            f"Parent: {ou.parent_org_unit_path}\n"
            f"Description: {ou.description or 'N/A'}\n"
            f"Block Inheritance: {'Yes' if ou.block_inheritance else 'No'}",
            border_style="green",
        ))

    except Exception as e:
        console.print(f"[red]Error updating OU: {e}[/red]")
        raise click.Abort()


@ou_group.command(name="delete")
@click.argument("ou_path")
@click.option(
    "--confirm",
    is_flag=True,
    help="Confirm deletion without prompting",
)
@click.pass_context
def delete_ou(ctx: click.Context, ou_path: str, confirm: bool):
    """Delete an organizational unit."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.lifecycle.ou_manager import OUManager

    # Confirm deletion
    if not confirm:
        if not click.confirm(f"Are you sure you want to delete OU '{ou_path}'?"):
            console.print("[yellow]Deletion cancelled.[/yellow]")
            return

    console.print(f"[cyan]Deleting OU: {ou_path}...[/cyan]\n")

    # Load configuration
    config_path = ctx.obj.get("config_path")
    config = load_config(config_path)

    # Create client
    client = create_client_from_config(config)

    # Create OU manager
    ou_manager = OUManager(client)

    try:
        # Delete OU
        ou_manager.delete_ou(ou_path)

        # Display success
        console.print(Panel.fit(
            f"[green]✓ OU deleted successfully![/green]\n\n"
            f"Path: {ou_path}",
            border_style="green",
        ))

    except Exception as e:
        console.print(f"[red]Error deleting OU: {e}[/red]")
        raise click.Abort()

