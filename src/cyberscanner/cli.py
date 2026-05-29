from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import box

from . import Scanner
from .report import table as table_report, json_report, sarif, html as html_report
from .db.storage import LocalStorage
from .models import Severity

app = typer.Typer(
    name="cyberscanner",
    help="Open-source vulnerability scanner for Python and JavaScript projects.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()

_SEV_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


@app.command("scan")
def scan(
    path: str = typer.Argument(".", help="Project path to scan (default: current directory)"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table | json | sarif | html"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write output to this file"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Exit 1 if any vuln at this severity or above: critical | high | medium | low"),
    no_secrets: bool = typer.Option(False, "--no-secrets", help="Skip secret detection"),
    no_deps: bool = typer.Option(False, "--no-deps", help="Skip dependency scanning"),
) -> None:
    """Scan a project for vulnerabilities and secrets."""
    target = str(Path(path).resolve())

    with console.status(f"[bold cyan]Scanning {target}...[/bold cyan]"):
        scanner = Scanner(target)
        result = scanner.scan(scan_secrets=not no_secrets, scan_deps=not no_deps)

    LocalStorage().save(result)

    if format == "json":
        out = json_report.to_json(result)
        if output:
            Path(output).write_text(out, encoding="utf-8")
            console.print(f"[green]JSON report -> {output}[/green]")
        else:
            sys.stdout.buffer.write(out.encode("utf-8"))
            sys.stdout.buffer.write(b"\n")
            sys.stdout.buffer.flush()

    elif format == "sarif":
        out = sarif.to_sarif_json(result)
        if output:
            Path(output).write_text(out, encoding="utf-8")
            console.print(f"[green]SARIF report -> {output}[/green]")
        else:
            sys.stdout.buffer.write(out.encode("utf-8"))
            sys.stdout.buffer.write(b"\n")
            sys.stdout.buffer.flush()

    elif format == "html":
        out = html_report.to_html(result)
        dest = output or "cyberscanner-report.html"
        Path(dest).write_text(out, encoding="utf-8")
        console.print(f"[green]HTML report -> {dest}[/green]")

    else:
        table_report.print_results(result)

    if fail_on:
        threshold = _SEV_RANK.get(fail_on.lower(), 4)
        rank = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.UNKNOWN: 0}
        if any(rank.get(v.severity, 0) >= threshold for v in result.vulnerabilities):
            raise typer.Exit(code=1)


@app.command("secrets")
def secrets_only(
    path: str = typer.Argument(".", help="Path to scan for secrets"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table | json"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write output to file"),
) -> None:
    """Scan for hardcoded secrets and credentials only."""
    target = str(Path(path).resolve())
    with console.status("[bold cyan]Scanning for secrets...[/bold cyan]"):
        result = Scanner(target).scan(scan_secrets=True, scan_deps=False)

    LocalStorage().save(result)

    if format == "json":
        out = json_report.to_json(result)
        if output:
            Path(output).write_text(out, encoding="utf-8")
            console.print(f"[green]JSON report -> {output}[/green]")
        else:
            sys.stdout.buffer.write(out.encode("utf-8"))
            sys.stdout.buffer.write(b"\n")
            sys.stdout.buffer.flush()
    else:
        table_report.print_results(result)


@app.command("history")
def history(
    limit: int = typer.Option(10, "--limit", "-n", help="Number of past scans to show"),
    scan_id: Optional[str] = typer.Option(None, "--id", help="Show full details for a scan ID"),
    diff: bool = typer.Option(False, "--diff", help="Diff last 2 scans — shows new and fixed vulns"),
    path: Optional[str] = typer.Option(None, "--path", help="Filter history by target path"),
) -> None:
    """Show scan history and trends."""
    storage = LocalStorage()

    if scan_id:
        data = storage.get_scan(scan_id)
        if not data:
            console.print(f"[red]Scan {scan_id!r} not found.[/red]")
            raise typer.Exit(1)
        console.print_json(json.dumps(data, indent=2, default=str))
        return

    if diff:
        new_vulns, fixed_vulns = storage.diff_last_two(target_path=path)
        _print_diff(new_vulns, fixed_vulns)
        return

    scans = storage.list_scans(limit=limit)
    if not scans:
        console.print("[yellow]No history yet. Run [bold]cyberscanner scan[/bold] first.[/yellow]")
        return

    table = Table(title="Scan History", box=box.ROUNDED, show_lines=False)
    table.add_column("ID", style="dim", width=9)
    table.add_column("Timestamp")
    table.add_column("Target")
    table.add_column("Pkgs", justify="right", width=5)
    table.add_column("Vulns", justify="right", width=6)
    table.add_column("Secrets", justify="right", width=8)

    for s in scans:
        vuln_style = "red bold" if s["vuln_count"] else "green"
        secret_style = "red bold" if s["secret_count"] else "green"
        table.add_row(
            s["id"][:8],
            s["timestamp"][:19],
            s["target_path"],
            str(s["packages_scanned"]),
            f"[{vuln_style}]{s['vuln_count']}[/{vuln_style}]",
            f"[{secret_style}]{s['secret_count']}[/{secret_style}]",
        )
    console.print(table)


def _print_diff(new_vulns: list, fixed_vulns: list) -> None:
    if not new_vulns and not fixed_vulns:
        console.print("[green]No changes between the last two scans.[/green]")
        return

    if new_vulns:
        t = Table(title="[bold red]New Vulnerabilities[/bold red]", box=box.ROUNDED)
        t.add_column("Package")
        t.add_column("Version")
        t.add_column("Vuln ID", style="blue")
        t.add_column("Severity")
        for v in new_vulns:
            t.add_row(v["package"], v.get("version", ""), v["vuln_id"], v.get("severity", ""))
        console.print(t)

    if fixed_vulns:
        t = Table(title="[bold green]Fixed Vulnerabilities[/bold green]", box=box.ROUNDED)
        t.add_column("Package")
        t.add_column("Version")
        t.add_column("Vuln ID", style="blue")
        t.add_column("Severity")
        for v in fixed_vulns:
            t.add_row(v["package"], v.get("version", ""), v["vuln_id"], v.get("severity", ""))
        console.print(t)


if __name__ == "__main__":
    app()
