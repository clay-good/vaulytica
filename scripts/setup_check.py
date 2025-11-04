#!/usr/bin/env python3
"""
Setup verification script for Vaulytica.
Checks all prerequisites and configuration before first use.
"""

import json
import os
import sys
from pathlib import Path
from typing import List, Tuple

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
except ImportError:
    print("Error: Rich library not installed. Run: poetry install")
    sys.exit(1)

console = Console()


class SetupChecker:
    """Verify Vaulytica setup and configuration."""

    def __init__(self):
        self.checks_passed = 0
        self.checks_failed = 0
        self.warnings = 0
        self.issues: List[Tuple[str, str]] = []

    def check_python_version(self) -> bool:
        """Check Python version is 3.9+."""
        version = sys.version_info
        if version.major == 3 and version.minor >= 9:
            console.print("[green]✓[/green] Python version: {}.{}.{}".format(
                version.major, version.minor, version.micro
            ))
            self.checks_passed += 1
            return True
        else:
            console.print("[red]✗[/red] Python version: {}.{}.{} (requires 3.9+)".format(
                version.major, version.minor, version.micro
            ))
            self.checks_failed += 1
            self.issues.append(("Python Version", "Upgrade to Python 3.9 or higher"))
            return False

    def check_config_file(self) -> bool:
        """Check if config.yaml exists."""
        config_path = Path("config.yaml")
        if config_path.exists():
            console.print(f"[green]✓[/green] Configuration file found: {config_path}")
            self.checks_passed += 1
            return True
        else:
            console.print(f"[red]✗[/red] Configuration file not found: {config_path}")
            self.checks_failed += 1
            self.issues.append(
                ("Configuration", "Run 'vaulytica init' or copy examples/basic-config.yaml to config.yaml")
            )
            return False

    def check_credentials_file(self) -> bool:
        """Check if credentials.json exists."""
        # Try to load config to get credentials path
        config_path = Path("config.yaml")
        if not config_path.exists():
            return False

        try:
            import yaml
            with open(config_path) as f:
                config = yaml.safe_load(f)
            
            creds_path = config.get("google_workspace", {}).get("credentials_path", "./credentials.json")
            creds_file = Path(creds_path)
            
            if creds_file.exists():
                console.print(f"[green]✓[/green] Credentials file found: {creds_file}")
                self.checks_passed += 1
                
                # Validate JSON structure
                try:
                    with open(creds_file) as f:
                        creds_data = json.load(f)
                    
                    required_fields = ["type", "project_id", "private_key", "client_email"]
                    missing_fields = [f for f in required_fields if f not in creds_data]
                    
                    if missing_fields:
                        console.print(f"[yellow]⚠[/yellow] Credentials file missing fields: {', '.join(missing_fields)}")
                        self.warnings += 1
                        self.issues.append(
                            ("Credentials", f"Invalid credentials file. Missing: {', '.join(missing_fields)}")
                        )
                        return False
                    
                    if creds_data.get("type") != "service_account":
                        console.print("[yellow]⚠[/yellow] Credentials type is not 'service_account'")
                        self.warnings += 1
                        self.issues.append(
                            ("Credentials", "Credentials should be for a service account")
                        )
                    
                    return True
                    
                except json.JSONDecodeError:
                    console.print(f"[red]✗[/red] Credentials file is not valid JSON")
                    self.checks_failed += 1
                    self.issues.append(
                        ("Credentials", "Credentials file is corrupted or not valid JSON")
                    )
                    return False
            else:
                console.print(f"[red]✗[/red] Credentials file not found: {creds_file}")
                self.checks_failed += 1
                self.issues.append(
                    ("Credentials", "Download service account JSON from Google Cloud Console")
                )
                return False
                
        except Exception as e:
            console.print(f"[red]✗[/red] Error checking credentials: {e}")
            self.checks_failed += 1
            return False

    def check_config_values(self) -> bool:
        """Check required configuration values."""
        config_path = Path("config.yaml")
        if not config_path.exists():
            return False

        try:
            import yaml
            with open(config_path) as f:
                config = yaml.safe_load(f)
            
            # Check required fields
            gws_config = config.get("google_workspace", {})
            
            required_fields = {
                "domain": "Your Google Workspace domain (e.g., example.com)",
                "impersonate_user": "Admin user email for impersonation",
            }
            
            all_present = True
            for field, description in required_fields.items():
                if not gws_config.get(field):
                    console.print(f"[red]✗[/red] Missing required config: google_workspace.{field}")
                    self.checks_failed += 1
                    self.issues.append(("Configuration", f"Set {field}: {description}"))
                    all_present = False
                else:
                    console.print(f"[green]✓[/green] Config set: google_workspace.{field} = {gws_config[field]}")
                    self.checks_passed += 1
            
            return all_present
            
        except Exception as e:
            console.print(f"[red]✗[/red] Error reading config: {e}")
            self.checks_failed += 1
            return False

    def check_dependencies(self) -> bool:
        """Check if required Python packages are installed."""
        required_packages = [
            "google-api-python-client",
            "google-auth",
            "google-auth-oauthlib",
            "click",
            "rich",
            "structlog",
            "pyyaml",
        ]
        
        all_installed = True
        for package in required_packages:
            try:
                __import__(package.replace("-", "_"))
                self.checks_passed += 1
            except ImportError:
                console.print(f"[red]✗[/red] Missing package: {package}")
                self.checks_failed += 1
                all_installed = False
                self.issues.append(("Dependencies", f"Run 'poetry install' to install {package}"))
        
        if all_installed:
            console.print(f"[green]✓[/green] All required packages installed")
        
        return all_installed

    def check_directories(self) -> bool:
        """Check if required directories exist."""
        dirs = ["reports", "logs"]
        
        for dir_name in dirs:
            dir_path = Path(dir_name)
            if not dir_path.exists():
                console.print(f"[yellow]⚠[/yellow] Directory not found: {dir_path} (will be created automatically)")
                self.warnings += 1
            else:
                console.print(f"[green]✓[/green] Directory exists: {dir_path}")
                self.checks_passed += 1
        
        return True

    def run_all_checks(self) -> bool:
        """Run all setup checks."""
        console.print(Panel.fit(
            "[bold cyan]Vaulytica Setup Verification[/bold cyan]\n"
            "Checking prerequisites and configuration...",
            border_style="cyan"
        ))
        console.print()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Running checks...", total=None)
            
            # Run all checks
            self.check_python_version()
            self.check_dependencies()
            self.check_config_file()
            self.check_credentials_file()
            self.check_config_values()
            self.check_directories()
            
            progress.update(task, description="[green]✓[/green] Checks complete")

        console.print()
        
        # Display summary
        self.display_summary()
        
        return self.checks_failed == 0

    def display_summary(self):
        """Display summary of checks."""
        table = Table(title="Setup Check Summary", show_header=True, header_style="bold cyan")
        table.add_column("Status", style="bold")
        table.add_column("Count", justify="right")
        
        table.add_row("[green]Passed[/green]", str(self.checks_passed))
        table.add_row("[red]Failed[/red]", str(self.checks_failed))
        table.add_row("[yellow]Warnings[/yellow]", str(self.warnings))
        
        console.print(table)
        console.print()
        
        if self.issues:
            console.print("[bold red]Issues Found:[/bold red]\n")
            for category, issue in self.issues:
                console.print(f"  [red]•[/red] [bold]{category}:[/bold] {issue}")
            console.print()
        
        if self.checks_failed == 0:
            console.print(Panel.fit(
                "[bold green]✓ Setup Complete![/bold green]\n\n"
                "You're ready to use Vaulytica. Try:\n"
                "  [cyan]vaulytica test[/cyan] - Test API connection\n"
                "  [cyan]vaulytica scan files --external-only[/cyan] - Run your first scan",
                border_style="green"
            ))
        else:
            console.print(Panel.fit(
                "[bold red]✗ Setup Incomplete[/bold red]\n\n"
                "Please fix the issues above before using Vaulytica.\n"
                "See QUICKSTART.md for detailed setup instructions.",
                border_style="red"
            ))


def main():
    """Main entry point."""
    checker = SetupChecker()
    success = checker.run_all_checks()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

