"""Chrome Enterprise management CLI commands."""

import json
from pathlib import Path
from typing import Optional

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from vaulytica.core.auth.client import GoogleWorkspaceClient
from vaulytica.core.chrome.extension_manager import (
    ChromeExtensionManager,
)
from vaulytica.core.chrome.policy_manager import (
    ChromePolicyManager,
    PolicyScope,
    PolicyTemplate,
)
from vaulytica.core.chrome.security_controls import (
    SecurityControlsManager,
    SecurityLevel,
)

console = Console()


@click.group(name="chrome")
def chrome_group() -> None:
    """Chrome Enterprise management commands."""
    pass


@chrome_group.group(name="policy")
def policy_group() -> None:
    """Chrome policy management."""
    pass


@policy_group.command(name="create")
@click.option(
    "--credentials",
    "-c",
    required=True,
    type=click.Path(exists=True),
    help="Path to service account credentials JSON file",
)
@click.option(
    "--template",
    "-t",
    type=click.Choice([t.value for t in PolicyTemplate], case_sensitive=False),
    required=True,
    help="Policy template to use",
)
@click.option(
    "--org-unit",
    "-o",
    required=True,
    help="Organizational unit path (e.g., /Engineering)",
)
@click.option(
    "--scope",
    type=click.Choice(["user", "device", "managed_guest"], case_sensitive=False),
    default="user",
    help="Policy scope (default: user)",
)
@click.option(
    "--name",
    help="Custom policy name (defaults to template name)",
)
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    help="Save policy to JSON file",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Preview policy without applying",
)
def create_policy(
    credentials: str,
    template: str,
    org_unit: str,
    scope: str,
    name: Optional[str],
    output: Optional[Path],
    dry_run: bool,
) -> None:
    """Create and apply a Chrome policy from template.

    Example:
        vaulytica chrome policy create \\
            --credentials service-account.json \\
            --template secure_browser \\
            --org-unit /Engineering \\
            --dry-run
    """
    try:
        # Initialize client
        client = GoogleWorkspaceClient(
            credentials_path=credentials,
            admin_email="admin@example.com",  # Would be from config
        )

        policy_manager = ChromePolicyManager(client)

        # Convert template string to enum
        template_enum = PolicyTemplate(template)
        scope_enum = PolicyScope(scope)

        # Create policy
        console.print(f"\n[cyan]Creating {template} policy...[/cyan]")

        policy = policy_manager.create_from_template(
            template=template_enum,
            org_unit_path=org_unit,
            scope=scope_enum,
            name=name,
        )

        # Display policy details
        console.print(
            Panel(
                f"[bold]{policy.name}[/bold]\n\n"
                f"{policy.description}\n\n"
                f"Template: {policy.template.value if policy.template else 'N/A'}\n"
                f"Scope: {policy.scope.value}\n"
                f"OU: {policy.org_unit_path}\n"
                f"Policies: {len(policy.policies)}",
                title="[bold cyan]Policy Details[/bold cyan]",
                border_style="cyan",
            )
        )

        # Show policies table
        table = Table(title="\n📋 Policy Settings", box=box.ROUNDED)
        table.add_column("Policy Name", style="cyan")
        table.add_column("Value", style="yellow")

        for key, value in sorted(policy.policies.items())[:20]:  # First 20
            table.add_row(key, str(value))

        if len(policy.policies) > 20:
            table.add_row("...", f"(+{len(policy.policies) - 20} more policies)")

        console.print(table)

        # Validate policy
        validation = policy_manager.validate_policy(policy)

        if validation["warnings"] or validation["recommendations"]:
            console.print("\n[yellow]⚠️  Validation Warnings & Recommendations:[/yellow]")
            for warning in validation["warnings"]:
                console.print(f"  • {warning}")
            for rec in validation["recommendations"]:
                console.print(f"  • [dim]{rec}[/dim]")

        # Save or apply
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            with open(output, "w") as f:
                json.dump(policy.to_dict(), f, indent=2, default=str)
            console.print(f"\n[green]✓[/green] Policy saved to: {output}")

        if dry_run:
            console.print("\n[yellow]Dry run - policy not applied[/yellow]")
        else:
            result = policy_manager.apply_policy(policy, dry_run=False)
            console.print(f"\n[green]✓[/green] {result['message']}")

    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}", style="red")
        raise click.Abort() from e


@policy_group.command(name="templates")
def list_templates() -> None:
    """List available policy templates.

    Example:
        vaulytica chrome policy templates
    """
    table = Table(title="Available Chrome Policy Templates", box=box.ROUNDED)
    table.add_column("Template", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Use Case", style="yellow")

    templates_info = [
        ("secure_browser", "Island Browser-like maximum security", "Security teams, compliance"),
        ("restricted_browsing", "Highly restricted, minimal functionality", "Kiosks, high-security"),
        ("education", "K-12/University with SafeSearch", "Schools, universities"),
        ("healthcare", "HIPAA compliance focused", "Healthcare organizations"),
        ("financial", "PCI-DSS compliance focused", "Financial services"),
        ("developer", "Developer-friendly with security", "Engineering teams"),
        ("kiosk", "Single-app kiosk mode", "Public terminals, displays"),
        ("standard", "Balanced security and usability", "General business use"),
    ]

    for template, desc, use_case in templates_info:
        table.add_row(template, desc, use_case)

    console.print(table)


@chrome_group.group(name="extensions")
def extensions_group() -> None:
    """Chrome extension management."""
    pass


@extensions_group.command(name="create-allowlist")
@click.option(
    "--org-unit",
    "-o",
    required=True,
    help="Organizational unit path",
)
@click.option(
    "--include-google",
    is_flag=True,
    default=True,
    help="Include Google official extensions",
)
@click.option(
    "--include-security",
    is_flag=True,
    default=True,
    help="Include security extensions",
)
@click.option(
    "--include-productivity",
    is_flag=True,
    help="Include productivity extensions",
)
@click.option(
    "--include-password-managers",
    is_flag=True,
    default=True,
    help="Include password manager extensions",
)
@click.option(
    "--add-extension",
    multiple=True,
    help="Add custom extension ID (can specify multiple)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Save allowlist to JSON file",
)
def create_extension_allowlist(
    org_unit: str,
    include_google: bool,
    include_security: bool,
    include_productivity: bool,
    include_password_managers: bool,
    add_extension: tuple,
    output: Optional[Path],
) -> None:
    """Create a secure extension allowlist.

    Example:
        vaulytica chrome extensions create-allowlist \\
            --org-unit /Engineering \\
            --include-security \\
            --add-extension abc123... \\
            --output allowlist.json
    """
    try:
        manager = ChromeExtensionManager()

        # Create allowlist
        allowlist = manager.create_secure_allowlist(
            include_google_official=include_google,
            include_security=include_security,
            include_productivity=include_productivity,
            include_password_managers=include_password_managers,
            custom_extensions=list(add_extension) if add_extension else None,
        )

        # Display allowlist
        table = Table(title=f"\n🔒 Extension Allowlist for {org_unit}", box=box.ROUNDED)
        table.add_column("Extension Name", style="cyan")
        table.add_column("ID", style="yellow")
        table.add_column("Vendor", style="white")
        table.add_column("Category", style="green")
        table.add_column("Risk", style="magenta")

        for ext in sorted(allowlist, key=lambda x: (x.category, x.name)):
            table.add_row(
                ext.name,
                ext.extension_id[:16] + "...",
                ext.vendor,
                ext.category,
                ext.risk_level,
            )

        console.print(table)

        console.print(
            f"\n[bold]Total Extensions:[/bold] {len(allowlist)}\n"
            f"[bold]Verified:[/bold] {sum(1 for e in allowlist if e.verified)}\n"
            f"[bold]Custom:[/bold] {sum(1 for e in allowlist if not e.verified)}"
        )

        # Save to file
        if output:
            policy = manager.create_extension_policy(
                name="extension_allowlist",
                org_unit_path=org_unit,
                policy_type="allowlist",
            )
            policy.allowed = allowlist

            output.parent.mkdir(parents=True, exist_ok=True)
            with open(output, "w") as f:
                json.dump(manager.export_policy_json(policy), f, indent=2)

            console.print(f"\n[green]✓[/green] Allowlist saved to: {output}")

    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}", style="red")
        raise click.Abort() from e


@extensions_group.command(name="catalog")
def extension_catalog() -> None:
    """List verified extensions catalog.

    Example:
        vaulytica chrome extensions catalog
    """
    manager = ChromeExtensionManager()
    catalog = manager.get_extension_catalog()

    # Group by category
    by_category = {}
    for ext in catalog:
        category = ext["category"]
        if category not in by_category:
            by_category[category] = []
        by_category[category].append(ext)

    # Display each category
    for category, extensions in sorted(by_category.items()):
        table = Table(title=f"\n{category.title()} Extensions", box=box.ROUNDED)
        table.add_column("Extension Name", style="cyan")
        table.add_column("Vendor", style="white")
        table.add_column("Risk Level", style="yellow")
        table.add_column("Extension ID", style="dim")

        for ext in sorted(extensions, key=lambda x: x["name"]):
            table.add_row(
                ext["name"],
                ext["vendor"],
                ext["risk_level"],
                ext["extension_id"][:16] + "...",
            )

        console.print(table)


@chrome_group.group(name="security")
def security_group() -> None:
    """Chrome security controls."""
    pass


@security_group.command(name="create-profile")
@click.option(
    "--name",
    "-n",
    required=True,
    help="Security profile name",
)
@click.option(
    "--org-unit",
    "-o",
    required=True,
    help="Organizational unit path",
)
@click.option(
    "--level",
    type=click.Choice([level.value for level in SecurityLevel], case_sensitive=False),
    default="enhanced",
    help="Security level (default: enhanced)",
)
@click.option(
    "--block-productivity",
    is_flag=True,
    help="Block social media and productivity blockers",
)
@click.option(
    "--block-file-sharing",
    is_flag=True,
    help="Block file sharing sites",
)
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    help="Save profile to JSON file",
)
def create_security_profile(
    name: str,
    org_unit: str,
    level: str,
    block_productivity: bool,
    block_file_sharing: bool,
    output: Optional[Path],
) -> None:
    """Create a complete security profile (Island Browser-like).

    Example:
        vaulytica chrome security create-profile \\
            --name "Secure Profile" \\
            --org-unit /Engineering \\
            --level enhanced \\
            --output security-profile.json
    """
    try:
        manager = SecurityControlsManager()
        security_level = SecurityLevel(level)

        # Create complete profile
        profile = manager.create_secure_browser_profile(
            name=name,
            org_unit_path=org_unit,
        )

        # Display profile
        console.print(
            Panel(
                f"[bold]{name}[/bold]\n\n"
                f"{profile['description']}\n\n"
                f"Security Level: {security_level.value}\n"
                f"OU: {org_unit}",
                title="[bold cyan]Security Profile[/bold cyan]",
                border_style="cyan",
            )
        )

        # URL Filtering details
        url_policy = profile["url_filtering"]
        console.print("\n[bold cyan]🔒 URL Filtering:[/bold cyan]")
        console.print(f"  Blocked URLs: {len(url_policy.url_blocklist)}")
        console.print(f"  Allowed URLs: {len(url_policy.url_allowlist)}")
        console.print(f"  Force Safe Search: {'Yes' if url_policy.force_safe_search else 'No'}")
        console.print(f"  Force HTTPS: {'Yes' if url_policy.force_https_only else 'No'}")
        console.print(f"  Block 3rd-party Cookies: {'Yes' if url_policy.block_third_party_cookies else 'No'}")

        # Safe Browsing details
        sb_policy = profile["safe_browsing"]
        console.print("\n[bold cyan]🛡️  Safe Browsing:[/bold cyan]")
        protection_levels = {0: "Disabled", 1: "Standard", 2: "Enhanced"}
        console.print(f"  Protection Level: {protection_levels[sb_policy.protection_level]}")
        console.print(f"  Real-time URL Checks: {'Yes' if sb_policy.real_time_url_checks else 'No'}")
        console.print(f"  Deep Scanning: {'Yes' if sb_policy.deep_scanning_enabled else 'No'}")
        console.print(f"  Password Leak Detection: {'Yes' if sb_policy.password_leak_detection else 'No'}")

        # DLP details
        dlp_policy = profile["dlp"]
        console.print("\n[bold cyan]📋 Data Loss Prevention:[/bold cyan]")
        clipboard_settings = {1: "Allow", 2: "Block", 3: "Ask"}
        console.print(f"  Clipboard: {clipboard_settings[dlp_policy.default_clipboard_setting]}")
        console.print(f"  Screen Capture: {'Yes' if dlp_policy.screen_capture_allowed else 'No'}")
        console.print(f"  Printing: {'Yes' if dlp_policy.printing_enabled else 'No'}")

        # Export
        if output:
            policies = manager.export_security_policies(profile)
            output.parent.mkdir(parents=True, exist_ok=True)
            with open(output, "w") as f:
                json.dump(policies, f, indent=2)

            console.print(f"\n[green]✓[/green] Security profile saved to: {output}")

    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}", style="red")
        raise click.Abort() from e


@security_group.command(name="analyze-url")
@click.argument("url")
def analyze_url(url: str) -> None:
    """Analyze a URL pattern for validity.

    Example:
        vaulytica chrome security analyze-url "*.example.com"
    """
    manager = SecurityControlsManager()
    result = manager.validate_url_pattern(url)

    if result["valid"]:
        console.print(f"\n[green]✓ Valid URL pattern:[/green] {url}")
    else:
        console.print(f"\n[red]✗ Invalid URL pattern:[/red] {url}")

    if result["errors"]:
        console.print("\n[red]Errors:[/red]")
        for error in result["errors"]:
            console.print(f"  • {error}")

    if result["warnings"]:
        console.print("\n[yellow]Warnings:[/yellow]")
        for warning in result["warnings"]:
            console.print(f"  • {warning}")
