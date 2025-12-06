"""Jira integration CLI commands."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.markdown import Markdown

from vaulytica.config.loader import load_config
from vaulytica.integrations.jira import (
    JiraClient,
    JiraConfig,
    JiraSecurityReporter,
    JiraError,
    create_jira_client_from_config,
)
from vaulytica.storage.state import StateManager

console = Console()


@click.group(name="jira")
def jira_group():
    """Jira integration commands for creating security issues."""
    pass


@jira_group.command(name="test-connection")
@click.pass_context
def test_connection(ctx):
    """Test connection to Jira."""
    console.print("[cyan]Testing Jira connection...[/cyan]\n")

    try:
        config = ctx.obj.get("config") if ctx.obj else load_config()
        client = create_jira_client_from_config(config)

        if not client:
            console.print("[red]Jira is not configured.[/red]")
            console.print("\nAdd the following to your config.yaml:\n")
            console.print(Panel("""integrations:
  jira:
    enabled: true
    url: "https://your-org.atlassian.net"
    email: "your-email@company.com"
    api_token: "${JIRA_API_TOKEN}"
    project_key: "SEC"
    issue_type: "Task"
    default_priority: "Medium"
    default_labels:
      - vaulytica
      - security""", title="Jira Configuration"))
            raise click.Abort()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Connecting to Jira...", total=None)

            success = client.test_connection()

            if success:
                progress.update(task, description="[green]Connection successful[/green]")
            else:
                progress.update(task, description="[red]Connection failed[/red]")
                raise click.Abort()

        console.print("\n[green]Jira connection test passed.[/green]")
        console.print(f"[cyan]URL:[/cyan] {client.base_url}")
        console.print(f"[cyan]Project:[/cyan] {client.config.project_key}")

    except JiraError as e:
        console.print(f"\n[red]Connection failed: {e}[/red]")
        raise click.Abort()
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        raise click.Abort()


@jira_group.command(name="create-issue")
@click.option("--summary", "-s", required=True, help="Issue summary/title")
@click.option("--description", "-d", default="", help="Issue description")
@click.option("--priority", "-p", type=click.Choice(["Highest", "High", "Medium", "Low", "Lowest"]), default="Medium", help="Issue priority")
@click.option("--labels", "-l", multiple=True, help="Labels to add (can be used multiple times)")
@click.option("--assignee", "-a", help="Assignee account ID")
@click.pass_context
def create_issue(ctx, summary: str, description: str, priority: str, labels: tuple, assignee: Optional[str]):
    """Create a single Jira issue."""
    console.print("[cyan]Creating Jira issue...[/cyan]\n")

    try:
        config = ctx.obj.get("config") if ctx.obj else load_config()
        client = create_jira_client_from_config(config)

        if not client:
            console.print("[red]Jira is not configured. Run 'vaulytica jira test-connection' for setup instructions.[/red]")
            raise click.Abort()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Creating issue...", total=None)

            result = client.create_issue(
                summary=summary,
                description=description or f"Issue created by Vaulytica on {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                priority=priority,
                labels=list(labels) if labels else None,
                assignee=assignee,
            )

            if result.success:
                progress.update(task, description="[green]Issue created[/green]")
            else:
                progress.update(task, description="[red]Failed to create issue[/red]")
                console.print(f"\n[red]Error: {result.error}[/red]")
                raise click.Abort()

        console.print(f"\n[green]Issue created successfully.[/green]")
        console.print(f"[cyan]Key:[/cyan] {result.key}")
        console.print(f"[cyan]URL:[/cyan] {result.url}")

    except JiraError as e:
        console.print(f"\n[red]Error: {e}[/red]")
        raise click.Abort()


@jira_group.command(name="create-from-scan")
@click.option("--scan-type", "-t", type=click.Choice(["files", "users", "oauth", "compliance", "all"]), default="all", help="Type of scan findings to create issues for")
@click.option("--min-risk-score", "-r", type=int, default=70, help="Minimum risk score for creating issues (default: 70)")
@click.option("--dry-run", is_flag=True, help="Show what would be created without actually creating")
@click.option("--limit", "-n", type=int, default=20, help="Maximum number of issues to create")
@click.pass_context
def create_from_scan(ctx, scan_type: str, min_risk_score: int, dry_run: bool, limit: int):
    """Create Jira issues from the latest scan results."""
    console.print("[cyan]Creating Jira issues from scan results...[/cyan]\n")

    try:
        config = ctx.obj.get("config") if ctx.obj else load_config()
        client = create_jira_client_from_config(config)

        if not client and not dry_run:
            console.print("[red]Jira is not configured. Run 'vaulytica jira test-connection' for setup instructions.[/red]")
            raise click.Abort()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Loading scan results...", total=None)

            # Get scan results from state manager
            state_manager = StateManager()
            findings = _get_findings_from_state(state_manager, scan_type, min_risk_score, limit)

            progress.update(task, description=f"Found {len(findings)} findings")

        if not findings:
            console.print("[yellow]No findings match the criteria.[/yellow]")
            return

        # Display findings
        console.print(f"\n[cyan]Found {len(findings)} findings with risk score >= {min_risk_score}[/cyan]\n")

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Type", style="cyan")
        table.add_column("Name", max_width=40)
        table.add_column("Risk Score", justify="right")
        table.add_column("Severity")

        for finding in findings[:10]:
            severity = _get_severity(finding.get("risk_score", 0))
            severity_color = "red" if severity == "critical" else "yellow" if severity == "high" else "white"
            table.add_row(
                finding.get("type", "unknown"),
                finding.get("name", "")[:40],
                str(finding.get("risk_score", 0)),
                f"[{severity_color}]{severity}[/{severity_color}]",
            )

        if len(findings) > 10:
            table.add_row("...", f"... and {len(findings) - 10} more", "", "")

        console.print(table)

        if dry_run:
            console.print("\n[yellow]DRY RUN - No issues were created.[/yellow]")
            return

        # Confirm creation
        console.print("")
        if not click.confirm(f"Create {len(findings)} Jira issue(s)?"):
            console.print("[yellow]Cancelled.[/yellow]")
            return

        # Create issues
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Creating issues...", total=len(findings))

            reporter = JiraSecurityReporter(client)
            results = reporter.create_issues_from_findings(
                findings=findings,
                scan_type=scan_type,
            )

            success_count = sum(1 for r in results if r.success)
            progress.update(task, description=f"Created {success_count}/{len(findings)} issues")

        console.print(f"\n[green]Created {success_count} issue(s) successfully.[/green]")

        # Show created issues
        created_issues = [r for r in results if r.success]
        if created_issues:
            console.print("\n[cyan]Created Issues:[/cyan]")
            for result in created_issues[:10]:
                console.print(f"  - {result.key}: {result.url}")
            if len(created_issues) > 10:
                console.print(f"  ... and {len(created_issues) - 10} more")

        # Show failures
        failed = [r for r in results if not r.success]
        if failed:
            console.print(f"\n[red]{len(failed)} issue(s) failed to create.[/red]")

    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        raise click.Abort()


@jira_group.command(name="weekly-report")
@click.option("--dry-run", is_flag=True, help="Show the report without creating an issue")
@click.pass_context
def weekly_report(ctx, dry_run: bool):
    """Create a weekly security summary issue in Jira."""
    console.print("[cyan]Generating weekly security report...[/cyan]\n")

    try:
        config = ctx.obj.get("config") if ctx.obj else load_config()
        client = create_jira_client_from_config(config)

        if not client and not dry_run:
            console.print("[red]Jira is not configured. Run 'vaulytica jira test-connection' for setup instructions.[/red]")
            raise click.Abort()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Gathering metrics...", total=None)

            # Get summary data from state manager
            state_manager = StateManager()
            summary_data = _get_weekly_summary(state_manager)

            progress.update(task, description="[green]Metrics gathered[/green]")

        # Display summary
        console.print("\n[cyan]Weekly Summary:[/cyan]\n")

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Category")
        table.add_column("Metric")
        table.add_column("Value", justify="right")

        if "files" in summary_data:
            files = summary_data["files"]
            table.add_row("Files", "Total Scanned", str(files.get("total", 0)))
            table.add_row("Files", "High Risk", str(files.get("high_risk", 0)))
            table.add_row("Files", "External Shares", str(files.get("external_shares", 0)))
            table.add_row("Files", "Public", str(files.get("public", 0)))

        if "users" in summary_data:
            users = summary_data["users"]
            table.add_row("Users", "Total", str(users.get("total", 0)))
            table.add_row("Users", "Without 2FA", str(users.get("without_2fa", 0)))
            table.add_row("Users", "Inactive", str(users.get("inactive", 0)))

        if "oauth_apps" in summary_data:
            apps = summary_data["oauth_apps"]
            table.add_row("OAuth Apps", "Total", str(apps.get("total", 0)))
            table.add_row("OAuth Apps", "High Risk", str(apps.get("high_risk", 0)))

        console.print(table)

        if dry_run:
            console.print("\n[yellow]DRY RUN - No issue was created.[/yellow]")
            return

        # Create the issue
        console.print("")
        if not click.confirm("Create weekly report issue in Jira?"):
            console.print("[yellow]Cancelled.[/yellow]")
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Creating weekly report issue...", total=None)

            reporter = JiraSecurityReporter(client)
            result = reporter.create_weekly_report_issue(summary_data)

            if result.success:
                progress.update(task, description="[green]Issue created[/green]")
            else:
                progress.update(task, description="[red]Failed[/red]")
                console.print(f"\n[red]Error: {result.error}[/red]")
                raise click.Abort()

        console.print(f"\n[green]Weekly report created successfully.[/green]")
        console.print(f"[cyan]Key:[/cyan] {result.key}")
        console.print(f"[cyan]URL:[/cyan] {result.url}")

    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        raise click.Abort()


@jira_group.command(name="search")
@click.option("--jql", "-q", default="", help="JQL query (default: project issues)")
@click.option("--status", "-s", help="Filter by status (e.g., 'Open', 'In Progress', 'Done')")
@click.option("--priority", "-p", help="Filter by priority")
@click.option("--limit", "-n", type=int, default=20, help="Maximum results")
@click.pass_context
def search_issues(ctx, jql: str, status: Optional[str], priority: Optional[str], limit: int):
    """Search for Vaulytica-created issues in Jira."""
    console.print("[cyan]Searching Jira issues...[/cyan]\n")

    try:
        config = ctx.obj.get("config") if ctx.obj else load_config()
        client = create_jira_client_from_config(config)

        if not client:
            console.print("[red]Jira is not configured.[/red]")
            raise click.Abort()

        # Build JQL query
        if not jql:
            jql_parts = [f"project = {client.config.project_key}", 'labels = "vaulytica"']
            if status:
                jql_parts.append(f'status = "{status}"')
            if priority:
                jql_parts.append(f'priority = "{priority}"')
            jql = " AND ".join(jql_parts) + " ORDER BY created DESC"

        console.print(f"[dim]JQL: {jql}[/dim]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Searching...", total=None)

            issues = client.search_issues(jql, max_results=limit)

            progress.update(task, description=f"[green]Found {len(issues)} issue(s)[/green]")

        if not issues:
            console.print("[yellow]No issues found.[/yellow]")
            return

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Key", style="cyan")
        table.add_column("Summary", max_width=50)
        table.add_column("Status")
        table.add_column("Priority")
        table.add_column("Assignee")
        table.add_column("Created")

        for issue in issues:
            status_color = "green" if issue.status.lower() == "done" else "yellow" if "progress" in issue.status.lower() else "white"
            priority_color = "red" if issue.priority in ["Highest", "High"] else "white"

            table.add_row(
                issue.key,
                issue.summary[:50],
                f"[{status_color}]{issue.status}[/{status_color}]",
                f"[{priority_color}]{issue.priority}[/{priority_color}]",
                issue.assignee or "-",
                issue.created.strftime("%Y-%m-%d"),
            )

        console.print(table)

    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        raise click.Abort()


@jira_group.command(name="configure")
@click.option("--url", prompt="Jira URL", help="Jira instance URL (e.g., https://your-org.atlassian.net)")
@click.option("--email", prompt="Email", help="Your Jira email address")
@click.option("--project-key", prompt="Project Key", help="Jira project key (e.g., SEC)")
@click.pass_context
def configure(ctx, url: str, email: str, project_key: str):
    """Configure Jira integration settings."""
    console.print("\n[cyan]Jira Configuration[/cyan]\n")

    console.print("Add the following to your config.yaml:\n")

    config_yaml = f"""integrations:
  jira:
    enabled: true
    url: "{url}"
    email: "{email}"
    api_token: "${{JIRA_API_TOKEN}}"  # Set this environment variable
    project_key: "{project_key}"
    issue_type: "Task"
    default_priority: "Medium"
    default_labels:
      - vaulytica
      - security
    priority_mapping:
      critical: "Highest"
      high: "High"
      medium: "Medium"
      low: "Low"
"""

    console.print(Panel(config_yaml, title="config.yaml"))

    console.print("\n[yellow]Important:[/yellow]")
    console.print("1. Generate an API token at: https://id.atlassian.com/manage-profile/security/api-tokens")
    console.print("2. Set the JIRA_API_TOKEN environment variable:")
    console.print("   [dim]export JIRA_API_TOKEN='your-api-token'[/dim]")
    console.print("\n3. Run 'vaulytica jira test-connection' to verify the configuration.")


def _get_findings_from_state(state_manager: StateManager, scan_type: str, min_risk_score: int, limit: int) -> list:
    """Get findings from state manager based on scan type and filters."""
    findings = []

    try:
        conn = state_manager.conn
        cursor = conn.cursor()

        # Get high-risk files
        if scan_type in ("files", "all"):
            cursor.execute("""
                SELECT file_id, name, owner_email, risk_score, is_public, has_external_sharing, metadata
                FROM file_state
                WHERE risk_score >= ?
                ORDER BY risk_score DESC
                LIMIT ?
            """, (min_risk_score, limit))

            for row in cursor.fetchall():
                findings.append({
                    "type": "file",
                    "id": row[0],
                    "name": row[1],
                    "owner_email": row[2],
                    "risk_score": row[3],
                    "is_public": bool(row[4]),
                    "has_external_sharing": bool(row[5]),
                    "severity": _get_severity(row[3]),
                    "description": f"High-risk file '{row[1]}' owned by {row[2]}",
                })

        # Get OAuth app findings (if table exists)
        if scan_type in ("oauth", "all"):
            try:
                cursor.execute("""
                    SELECT client_id, display_text, risk_score, user_count
                    FROM oauth_app_state
                    WHERE risk_score >= ?
                    ORDER BY risk_score DESC
                    LIMIT ?
                """, (min_risk_score, limit))

                for row in cursor.fetchall():
                    findings.append({
                        "type": "oauth_app",
                        "id": row[0],
                        "name": row[1],
                        "risk_score": row[2],
                        "user_count": row[3],
                        "severity": _get_severity(row[2]),
                        "description": f"High-risk OAuth app '{row[1]}' used by {row[3]} user(s)",
                    })
            except Exception:
                pass  # Table may not exist

        # Sort by risk score and limit
        findings.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
        return findings[:limit]

    except Exception as e:
        console.print(f"[yellow]Warning: Error loading findings: {e}[/yellow]")
        return []


def _get_weekly_summary(state_manager: StateManager) -> dict:
    """Get weekly summary statistics from state manager."""
    summary = {}

    try:
        conn = state_manager.conn
        cursor = conn.cursor()

        # File statistics
        cursor.execute("SELECT COUNT(*) FROM file_state")
        total_files = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM file_state WHERE risk_score >= 70")
        high_risk_files = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM file_state WHERE has_external_sharing = 1")
        external_shares = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM file_state WHERE is_public = 1")
        public_files = cursor.fetchone()[0]

        summary["files"] = {
            "total": total_files,
            "high_risk": high_risk_files,
            "external_shares": external_shares,
            "public": public_files,
        }

        # User statistics (if table exists)
        try:
            cursor.execute("SELECT COUNT(*) FROM user_state")
            total_users = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM user_state WHERE two_factor_enabled = 0")
            without_2fa = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM user_state WHERE is_inactive = 1")
            inactive_users = cursor.fetchone()[0]

            summary["users"] = {
                "total": total_users,
                "without_2fa": without_2fa,
                "inactive": inactive_users,
            }
        except Exception:
            pass

        # OAuth app statistics (if table exists)
        try:
            cursor.execute("SELECT COUNT(*) FROM oauth_app_state")
            total_apps = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM oauth_app_state WHERE risk_score >= 70")
            high_risk_apps = cursor.fetchone()[0]

            summary["oauth_apps"] = {
                "total": total_apps,
                "high_risk": high_risk_apps,
            }
        except Exception:
            pass

    except Exception as e:
        console.print(f"[yellow]Warning: Error loading summary: {e}[/yellow]")

    return summary


def _get_severity(risk_score: int) -> str:
    """Convert risk score to severity level."""
    if risk_score >= 90:
        return "critical"
    elif risk_score >= 70:
        return "high"
    elif risk_score >= 40:
        return "medium"
    else:
        return "low"
