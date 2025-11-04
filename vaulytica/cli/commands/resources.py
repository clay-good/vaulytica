"""Calendar resource management commands."""

from pathlib import Path
from typing import Optional, List

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@click.group(name="resources")
def resources_group():
    """Calendar resource management commands."""
    pass


@resources_group.command(name="list")
@click.option(
    "--output",
    type=click.Path(),
    help="Save results to file (CSV or JSON)",
)
@click.pass_context
def list_resources(ctx: click.Context, output: Optional[Path]):
    """List all calendar resources."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.resources.calendar_resource_manager import CalendarResourceManager
    
    console.print("[cyan]Listing calendar resources...[/cyan]\n")
    
    # Load configuration
    config_path = ctx.obj.get("config_path")
    config = load_config(config_path)
    
    # Create client
    client = create_client_from_config(config)
    
    # Create resource manager
    resource_manager = CalendarResourceManager(client)
    
    try:
        # List resources
        resources = resource_manager.list_resources()
        
        if not resources:
            console.print("[yellow]No calendar resources found.[/yellow]")
            return
        
        # Display results
        table = Table(title=f"Calendar Resources ({len(resources)} total)")
        table.add_column("Name", style="cyan")
        table.add_column("Email", style="green")
        table.add_column("Type", style="blue")
        table.add_column("Capacity", style="yellow", justify="right")
        table.add_column("Building", style="magenta")
        
        for resource in resources:
            table.add_row(
                resource.resource_name,
                resource.resource_email,
                resource.resource_type,
                str(resource.capacity) if resource.capacity else "N/A",
                resource.building_id or "N/A",
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
                                "resource_id": r.resource_id,
                                "resource_name": r.resource_name,
                                "resource_email": r.resource_email,
                                "resource_type": r.resource_type,
                                "capacity": r.capacity,
                                "building_id": r.building_id,
                                "floor_name": r.floor_name,
                                "description": r.resource_description,
                            }
                            for r in resources
                        ],
                        f,
                        indent=2,
                    )
            else:  # CSV
                with open(output_path, "w", newline="") as f:
                    writer = csv.DictWriter(
                        f,
                        fieldnames=["resource_id", "resource_name", "resource_email", "resource_type", "capacity", "building_id"],
                    )
                    writer.writeheader()
                    for r in resources:
                        writer.writerow({
                            "resource_id": r.resource_id,
                            "resource_name": r.resource_name,
                            "resource_email": r.resource_email,
                            "resource_type": r.resource_type,
                            "capacity": r.capacity or "",
                            "building_id": r.building_id or "",
                        })
            
            console.print(f"\n[green]✓ Results saved to {output_path}[/green]")
        
    except Exception as e:
        console.print(f"[red]Error listing resources: {e}[/red]")
        raise click.Abort()


@resources_group.command(name="get")
@click.argument("resource_id")
@click.pass_context
def get_resource(ctx: click.Context, resource_id: str):
    """Get details of a specific calendar resource."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.resources.calendar_resource_manager import CalendarResourceManager
    
    console.print(f"[cyan]Getting resource: {resource_id}...[/cyan]\n")
    
    # Load configuration
    config_path = ctx.obj.get("config_path")
    config = load_config(config_path)
    
    # Create client
    client = create_client_from_config(config)
    
    # Create resource manager
    resource_manager = CalendarResourceManager(client)
    
    try:
        # Get resource
        resource = resource_manager.get_resource(resource_id)
        
        # Display results
        features_str = ", ".join(resource.feature_instances) if resource.feature_instances else "None"
        
        console.print(Panel.fit(
            f"[bold]Name:[/bold] {resource.resource_name}\n"
            f"[bold]Email:[/bold] {resource.resource_email}\n"
            f"[bold]Type:[/bold] {resource.resource_type}\n"
            f"[bold]Capacity:[/bold] {resource.capacity or 'N/A'}\n"
            f"[bold]Building:[/bold] {resource.building_id or 'N/A'}\n"
            f"[bold]Floor:[/bold] {resource.floor_name or 'N/A'}\n"
            f"[bold]Section:[/bold] {resource.floor_section or 'N/A'}\n"
            f"[bold]Description:[/bold] {resource.resource_description or 'N/A'}\n"
            f"[bold]Features:[/bold] {features_str}",
            title="Calendar Resource Details",
            border_style="green",
        ))
        
    except Exception as e:
        console.print(f"[red]Error getting resource: {e}[/red]")
        raise click.Abort()


@resources_group.command(name="create")
@click.argument("name")
@click.option(
    "--type",
    "resource_type",
    type=click.Choice(["CONFERENCE_ROOM", "OTHER"]),
    default="CONFERENCE_ROOM",
    help="Resource type (default: CONFERENCE_ROOM)",
)
@click.option(
    "--capacity",
    type=int,
    help="Capacity (number of people)",
)
@click.option(
    "--building",
    help="Building ID",
)
@click.option(
    "--floor",
    help="Floor name",
)
@click.option(
    "--section",
    help="Floor section",
)
@click.option(
    "--description",
    help="Resource description",
)
@click.option(
    "--features",
    help="Comma-separated list of features (e.g., 'Video Conference,Whiteboard')",
)
@click.pass_context
def create_resource(
    ctx: click.Context,
    name: str,
    resource_type: str,
    capacity: Optional[int],
    building: Optional[str],
    floor: Optional[str],
    section: Optional[str],
    description: Optional[str],
    features: Optional[str],
):
    """Create a new calendar resource."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.resources.calendar_resource_manager import CalendarResourceManager
    
    console.print(f"[cyan]Creating resource: {name}...[/cyan]\n")
    
    # Load configuration
    config_path = ctx.obj.get("config_path")
    config = load_config(config_path)
    
    # Create client
    client = create_client_from_config(config)
    
    # Create resource manager
    resource_manager = CalendarResourceManager(client)
    
    # Parse features
    feature_list = None
    if features:
        feature_list = [f.strip() for f in features.split(",")]
    
    try:
        # Create resource
        resource = resource_manager.create_resource(
            resource_name=name,
            resource_type=resource_type,
            capacity=capacity,
            building_id=building,
            floor_name=floor,
            floor_section=section,
            description=description,
            features=feature_list,
        )
        
        # Display success
        console.print(Panel.fit(
            f"[green]✓ Resource created successfully![/green]\n\n"
            f"Name: {resource.resource_name}\n"
            f"Email: {resource.resource_email}\n"
            f"Type: {resource.resource_type}\n"
            f"Capacity: {resource.capacity or 'N/A'}\n"
            f"Building: {resource.building_id or 'N/A'}",
            border_style="green",
        ))
        
    except Exception as e:
        console.print(f"[red]Error creating resource: {e}[/red]")
        raise click.Abort()


@resources_group.command(name="update")
@click.argument("resource_id")
@click.option("--name", help="New name")
@click.option("--capacity", type=int, help="New capacity")
@click.option("--building", help="New building ID")
@click.option("--floor", help="New floor name")
@click.option("--section", help="New floor section")
@click.option("--description", help="New description")
@click.option("--features", help="Comma-separated list of features")
@click.pass_context
def update_resource(
    ctx: click.Context,
    resource_id: str,
    name: Optional[str],
    capacity: Optional[int],
    building: Optional[str],
    floor: Optional[str],
    section: Optional[str],
    description: Optional[str],
    features: Optional[str],
):
    """Update a calendar resource."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.resources.calendar_resource_manager import CalendarResourceManager
    
    console.print(f"[cyan]Updating resource: {resource_id}...[/cyan]\n")
    
    # Load configuration
    config_path = ctx.obj.get("config_path")
    config = load_config(config_path)
    
    # Create client
    client = create_client_from_config(config)
    
    # Create resource manager
    resource_manager = CalendarResourceManager(client)
    
    # Parse features
    feature_list = None
    if features:
        feature_list = [f.strip() for f in features.split(",")]
    
    try:
        # Update resource
        resource = resource_manager.update_resource(
            resource_id=resource_id,
            resource_name=name,
            capacity=capacity,
            building_id=building,
            floor_name=floor,
            floor_section=section,
            description=description,
            features=feature_list,
        )
        
        # Display success
        console.print(Panel.fit(
            f"[green]✓ Resource updated successfully![/green]\n\n"
            f"Name: {resource.resource_name}\n"
            f"Email: {resource.resource_email}\n"
            f"Type: {resource.resource_type}\n"
            f"Capacity: {resource.capacity or 'N/A'}\n"
            f"Building: {resource.building_id or 'N/A'}",
            border_style="green",
        ))
        
    except Exception as e:
        console.print(f"[red]Error updating resource: {e}[/red]")
        raise click.Abort()


@resources_group.command(name="delete")
@click.argument("resource_id")
@click.option(
    "--confirm",
    is_flag=True,
    help="Confirm deletion without prompting",
)
@click.pass_context
def delete_resource(ctx: click.Context, resource_id: str, confirm: bool):
    """Delete a calendar resource."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.resources.calendar_resource_manager import CalendarResourceManager
    
    # Confirm deletion
    if not confirm:
        if not click.confirm(f"Are you sure you want to delete resource '{resource_id}'?"):
            console.print("[yellow]Deletion cancelled.[/yellow]")
            return
    
    console.print(f"[cyan]Deleting resource: {resource_id}...[/cyan]\n")
    
    # Load configuration
    config_path = ctx.obj.get("config_path")
    config = load_config(config_path)
    
    # Create client
    client = create_client_from_config(config)
    
    # Create resource manager
    resource_manager = CalendarResourceManager(client)
    
    try:
        # Delete resource
        resource_manager.delete_resource(resource_id)
        
        # Display success
        console.print(Panel.fit(
            f"[green]✓ Resource deleted successfully![/green]\n\n"
            f"Resource ID: {resource_id}",
            border_style="green",
        ))
        
    except Exception as e:
        console.print(f"[red]Error deleting resource: {e}[/red]")
        raise click.Abort()


@resources_group.command(name="list-buildings")
@click.option(
    "--output",
    type=click.Path(),
    help="Save results to file (CSV or JSON)",
)
@click.pass_context
def list_buildings(ctx: click.Context, output: Optional[Path]):
    """List all buildings."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.resources.calendar_resource_manager import CalendarResourceManager
    
    console.print("[cyan]Listing buildings...[/cyan]\n")
    
    # Load configuration
    config_path = ctx.obj.get("config_path")
    config = load_config(config_path)
    
    # Create client
    client = create_client_from_config(config)
    
    # Create resource manager
    resource_manager = CalendarResourceManager(client)
    
    try:
        # List buildings
        buildings = resource_manager.list_buildings()
        
        if not buildings:
            console.print("[yellow]No buildings found.[/yellow]")
            return
        
        # Display results
        table = Table(title=f"Buildings ({len(buildings)} total)")
        table.add_column("Building ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Description", style="blue")
        
        for building in buildings:
            table.add_row(
                building.building_id,
                building.building_name,
                building.description or "N/A",
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
                                "building_id": b.building_id,
                                "building_name": b.building_name,
                                "description": b.description,
                                "address_lines": b.address_lines,
                            }
                            for b in buildings
                        ],
                        f,
                        indent=2,
                    )
            else:  # CSV
                with open(output_path, "w", newline="") as f:
                    writer = csv.DictWriter(
                        f,
                        fieldnames=["building_id", "building_name", "description"],
                    )
                    writer.writeheader()
                    for b in buildings:
                        writer.writerow({
                            "building_id": b.building_id,
                            "building_name": b.building_name,
                            "description": b.description or "",
                        })
            
            console.print(f"\n[green]✓ Results saved to {output_path}[/green]")
        
    except Exception as e:
        console.print(f"[red]Error listing buildings: {e}[/red]")
        raise click.Abort()

