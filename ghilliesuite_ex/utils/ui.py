"""
ghilliesuite_ex/utils/ui.py
────────────────
Rich terminal UI helpers — banners, live panels, HitL prompts, and report tables.

All Rich rendering lives here so agent code stays clean and testable.
"""

from __future__ import annotations

import typer
from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from ghilliesuite_ex import __version__
from ghilliesuite_ex.utils.redaction import redact_command, redact_text

# ── Severity colour map ───────────────────────────────────────────────────────
SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def print_banner(console: Console) -> None:
    """Display the GhillieSuite-EX ASCII banner with version info."""
    banner = Text(justify="center")
    banner.append("\n")
    banner.append(
        r"""
  _            _ _   __    __  __     
 | |__   ___ | (_) / _\  /  \/ /     
 | '_ \ / __|| | | \ \  / /\  /  
 | | | | (__ | | | _\ \/ /__/ /__   
 |_| |_|\___||_|_| \__/\____/\___| 
""",
        style="bold cyan",
    )
    banner.append(f"    AI Bug Bounty Orchestrator  ", style="bold white")
    banner.append(f"v{__version__}\n", style="dim")

    console.print(Panel(banner, border_style="bright_blue", padding=(0, 4)))
    console.print(
        Align.center(
            Text(
                "Rules-First Orchestration · SQLite State · Safety Profiles · HitL Gates",
                style="dim italic",
            )
        )
    )
    console.print()


def agent_panel(
    console: Console,
    agent_name: str,
    action: str,
    target: str,
    loop: int,
    max_loops: int,
) -> None:
    """
    Print a bordered panel showing which agent is currently active and what it's doing.
    Called before each agent dispatches a tool.
    """
    agent_colors = {
        "SupervisorAgent": "bright_magenta",
        "ReconAgent": "bright_cyan",
        "ExploitAgent": "bright_red",
        "ReporterAgent": "bright_green",
    }
    color = agent_colors.get(agent_name, "white")
    loop_progress = f"[dim]Loop {loop}/{max_loops}[/dim]"

    content = (
        f"[{color}]● {agent_name}[/{color}]  {loop_progress}\n"
        f"[bold]Action:[/bold]  {action}\n"
        f"[bold]Target:[/bold]  [underline]{target}[/underline]"
    )
    console.print(Panel(content, border_style=color, padding=(0, 2)))


def tool_result_panel(
    console: Console,
    tool_name: str,
    cmd: list[str],
    ok: bool,
    summary: str,
) -> None:
    """Print a compact result panel after a tool finishes."""
    status = "[green]✔ success[/green]" if ok else "[red]✘ error[/red]"
    cmd_str = redact_command(cmd)
    content = (
        f"[bold]{tool_name}[/bold]  {status}\n"
        f"[dim]$ {cmd_str[:120]}[/dim]\n\n"
        f"{redact_text(summary)}"
    )
    console.print(Panel(content, border_style="dim", padding=(0, 2)))


def hitl_prompt(
    console: Console,
    tool_name: str,
    cmd: list[str],
    reason: str,
) -> bool:
    """
    Human-in-the-Loop confirmation prompt.

    Displays the command with credentials masked and the AI's reasoning,
    then asks for explicit [Y/n] confirmation.

    Returns:
        True  → user approved; go ahead and run the tool.
        False → user declined; skip this action silently.
    """
    console.print()
    console.print(Rule("[bold yellow]⚠  Human-in-the-Loop Required[/bold yellow]", style="yellow"))

    cmd_str = redact_command(cmd)
    content = (
        f"[bold yellow]Tool:[/bold yellow]     {tool_name}\n"
        f"[bold yellow]Command:[/bold yellow]  [bright_white]$ {cmd_str}[/bright_white]\n\n"
        f"[bold yellow]AI Reasoning:[/bold yellow]\n{redact_text(reason)}"
    )
    console.print(
        Panel(content, border_style="yellow", title="[yellow]Exploitation Approval[/yellow]", padding=(1, 2))
    )

    approved: bool = Confirm.ask(
        "[bold yellow]Proceed with this tool?[/bold yellow]",
        default=False,           # Default is NO — safe by default
    )

    if approved:
        console.print("[green]✔ Approved — executing...[/green]\n")
    else:
        console.print("[dim]✘ Skipped by user.[/dim]\n")

    return approved


def findings_table(console: Console, findings: list, title: str = "Findings Summary") -> None:
    """
    Print a colour-coded findings table sorted by severity.
    findings: list of Finding dataclass instances.
    """
    if not findings:
        console.print("\n[dim]No findings to display.[/dim]\n")
        return

    console.print()
    console.print(Rule(f"[bold]📋  {title}[/bold]", style="bright_white"))

    table = Table(
        show_lines=True,
        box=box.ROUNDED,
        border_style="bright_white",
        header_style="bold bright_white",
        title=f"[bold]{len(findings)} Finding(s)[/bold]",
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Severity", width=10)
    table.add_column("Title", max_width=40)
    table.add_column("Target", max_width=35)
    table.add_column("Tool", width=12)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings,
        key=lambda f: severity_order.get(f.severity.lower(), 5),
    )

    for i, f in enumerate(sorted_findings, start=1):
        color = SEVERITY_COLORS.get(f.severity.lower(), "white")
        table.add_row(
            str(i),
            f"[{color}]{f.severity.upper()}[/{color}]",
            f.title[:40],
            f.target[:35],
            f.tool,
        )

    console.print(table)
    console.print()


def status_dashboard(
    console: Console,
    hosts: int,
    endpoints: int,
    findings: int,
    endpoints_with_params: int = 0,
) -> None:
    """
    Display a compact dashboard row showing DB state counts.
    Rendered after each agent completes its task.
    """
    metrics = [
        Panel(f"[bold cyan]{hosts}[/bold cyan]\n[dim]Hosts[/dim]", border_style="cyan"),
        Panel(f"[bold blue]{endpoints}[/bold blue]\n[dim]Endpoints[/dim]", border_style="blue"),
        Panel(
            f"[bold yellow]{endpoints_with_params}[/bold yellow]\n[dim]With Params[/dim]",
            border_style="yellow",
        ),
        Panel(f"[bold red]{findings}[/bold red]\n[dim]Findings[/dim]", border_style="red"),
    ]
    console.print(Columns(metrics, equal=True, expand=True))
    console.print()
