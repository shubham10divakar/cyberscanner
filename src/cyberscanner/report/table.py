from __future__ import annotations

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..models import ScanResult, Severity

_SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.UNKNOWN: "dim",
}

console = Console()


def print_results(result: ScanResult) -> None:
    _print_vuln_table(result)
    if result.secrets:
        _print_secrets_table(result)
    _print_summary(result)


def _print_vuln_table(result: ScanResult) -> None:
    if not result.vulnerabilities:
        console.print("\n[green][OK] No vulnerabilities found in dependencies.[/green]\n")
        return

    table = Table(
        title=f"Vulnerabilities — [bold]{result.target_path}[/bold]",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("Severity", width=10)
    table.add_column("Package", style="bold cyan")
    table.add_column("Version", style="dim")
    table.add_column("Vuln ID", style="blue")
    table.add_column("Title")
    table.add_column("Fix available", style="green")

    for v in result.vulnerabilities:
        fix = ", ".join(f"-> {f}" for f in v.fixed_in) if v.fixed_in else "-"
        title = (v.title[:58] + "...") if len(v.title) > 60 else v.title
        table.add_row(
            Text(v.severity.value, style=_SEV_STYLE.get(v.severity, "")),
            v.package,
            v.version,
            v.vuln_id,
            title,
            fix,
        )

    console.print(table)


def _print_secrets_table(result: ScanResult) -> None:
    table = Table(
        title="[bold red]Secrets / Credentials Detected[/bold red]",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("Severity", width=10)
    table.add_column("Type")
    table.add_column("File")
    table.add_column("Line", justify="right", width=6)
    table.add_column("Preview")

    for s in result.secrets:
        rel = s.file_path.replace(result.target_path, "").lstrip("/\\") or s.file_path
        table.add_row(
            Text(s.severity.value, style=_SEV_STYLE.get(s.severity, "")),
            s.pattern_name,
            rel,
            str(s.line_no),
            s.snippet[:80],
        )

    console.print(table)


def _print_summary(result: ScanResult) -> None:
    s = result.summary
    parts = []
    if s.critical:
        parts.append(f"[bold red]{s.critical} CRITICAL[/bold red]")
    if s.high:
        parts.append(f"[red]{s.high} HIGH[/red]")
    if s.medium:
        parts.append(f"[yellow]{s.medium} MEDIUM[/yellow]")
    if s.low:
        parts.append(f"[cyan]{s.low} LOW[/cyan]")
    if s.total_secrets:
        parts.append(f"[bold magenta]{s.total_secrets} secret(s)[/bold magenta]")

    line = " | ".join(parts) if parts else "[green]All clear[/green]"
    console.print(f"\nResult: {line}")
    console.print(
        f"[dim]Packages: {s.packages_scanned} scanned | "
        f"Files: {s.files_scanned} | "
        f"Scan ID: {result.scan_id[:8]}[/dim]\n"
    )
