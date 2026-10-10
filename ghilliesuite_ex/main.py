"""
ghilliesuite_ex/main.py
─────────────────────
Typer CLI entrypoint for GhillieSuite-EX.sec.

Install:   pip install -e .
Run:       GhillieSuite-EX.sec hunt --target example.com --scope scope.txt

AI Provider is AUTO-DETECTED from .env — no --ai-provider flag needed:
  OPENAI_API_KEY=sk-...   → OpenAI (gpt-4o-mini)
  GEMINI_API_KEY=AIza...  → Google Gemini (gemini-2.5-pro)

Authentication flags (optional, injected into all active tools):
  --cookie "session=abc123"              → adds -H "Cookie: session=abc123"
  --header "Authorization: Bearer xyz"  → adds -H "Authorization: Bearer xyz"

Available commands:
  hunt          — Start a full AI-driven bug bounty hunt.
  check-tools   — Show which tool binaries are installed.
  check-config  — Validate .env / environment variables.
"""

from __future__ import annotations

import asyncio
import io
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.rule import Rule

from ghilliesuite_ex import __app_name__, __version__
from ghilliesuite_ex.arsenal import check_binaries, collect_tooling_status
from ghilliesuite_ex.config import normalize_execution_profile, validate_config
from ghilliesuite_ex.safety import get_execution_safety_policy
from ghilliesuite_ex.state.db import StateDB
from ghilliesuite_ex.utils.run_metadata import (
    build_run_manifest,
    safe_run_slug,
    write_run_manifest,
)
from ghilliesuite_ex.utils.scope import load_scope, validate_target_scope
from ghilliesuite_ex.utils.ui import print_banner

def _ensure_utf8_stdio() -> None:
    """
    Force UTF-8 stdout/stderr so rich/print never crash on non-ASCII output.
    This prevents crashes on Linux shells using C/ASCII locales.
    """
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is None:
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
            continue
        except Exception:
            pass
        try:
            buffer = stream.buffer
        except Exception:
            continue
        try:
            setattr(
                sys,
                name,
                io.TextIOWrapper(buffer, encoding="utf-8", errors="replace"),
            )
        except Exception:
            pass


_ensure_utf8_stdio()


app = typer.Typer(
    name=__app_name__,
    help="[bold cyan]GhillieSuite-EX.sec[/bold cyan] — AI Bug Bounty Orchestrator for HackerOne.",
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
)

console = Console()


# ──────────────────────────────────────────────────────────────────────────────
# hunt
# ──────────────────────────────────────────────────────────────────────────────

@app.command()
def hunt(
    target: str = typer.Option(
        ...,
        "--target", "-t",
        help="Primary domain to hunt (e.g. example.com).",
        show_default=False,
    ),
    scope: str = typer.Option(
        ...,
        "--scope", "-s",
        help="In-scope domains — comma-separated string OR path to a scope file.",
        show_default=False,
    ),
    output: str = typer.Option(
        "reports",
        "--output", "-o",
        help="Directory where JSON + Markdown + HTML reports are saved.",
    ),
    evidence_dir: str = typer.Option(
        "evidence",
        "--evidence-dir",
        help="Directory where request/response evidence files are saved.",
    ),
    max_loops: int = typer.Option(
        15,
        "--max-loops",
        help="Maximum number of agent decision loops.",
    ),
    timeout: int = typer.Option(
        180,
        "--timeout",
        help="Per-tool execution timeout in seconds.",
    ),
    nuclei_timeout: Optional[int] = typer.Option(
        None,
        "--nuclei-timeout",
        help="Nuclei-only execution timeout in seconds.",
        show_default=False,
    ),
    fast_nuclei: Optional[bool] = typer.Option(
        None,
        "--fast-nuclei/--no-fast-nuclei",
        help="Enable aggressive Nuclei speed + severity filtering flags.",
        show_default=False,
    ),
    nuclei_rate_limit: Optional[int] = typer.Option(
        None,
        "--rate-limit",
        "--nuclei-rate-limit",
        help="Nuclei rate limit (requests per second).",
        show_default=False,
    ),
    nuclei_concurrency: Optional[int] = typer.Option(
        None,
        "--concurrency",
        "--nuclei-concurrency",
        help="Nuclei concurrency (parallel template checks).",
        show_default=False,
    ),
    nuclei_http_timeout: Optional[int] = typer.Option(
        None,
        "--nuclei-http-timeout",
        help="Nuclei per-request timeout in seconds (maps to -timeout).",
        show_default=False,
    ),
    profile: str = typer.Option(
        "balanced",
        "--profile",
        help="Execution profile: vdp-safe, balanced, or aggressive.",
        show_default=True,
    ),
    safe_mode: bool = typer.Option(
        False,
        "--safe-mode",
        help="Force Human-in-the-Loop for EVERY tool, not just exploitation ones.",
        is_flag=True,
    ),
    update_templates: bool = typer.Option(
        True,
        "--update-templates/--no-update-templates",
        help="Run 'nuclei -ut' on startup to fetch the latest CVE templates.",
    ),
    stealth: bool = typer.Option(
        False,
        "--stealth",
        help="Enable stealth rate-limiting to reduce WAF 429s (nuclei/sqlmap/ffuf).",
        is_flag=True,
    ),
    allow_redirects: bool = typer.Option(
        False,
        "--allow-redirects",
        help="Compatibility flag; automatic redirects stay disabled so recon remains in scope.",
        is_flag=True,
    ),
    disable_stealth: bool = typer.Option(
        False,
        "--disable-stealth",
        help="Disable sniper protocol and ignore WAF/Commander stealth signals (full-speed execution).",
        is_flag=True,
    ),
    cookie: Optional[str] = typer.Option(
        None,
        "--cookie", "--cookies", "-c",
        help=(
            "Session cookie string injected into all active tools as -H 'Cookie: ...'.\n"
            "Example: --cookie 'session=abc123; csrf_token=xyz'\n"
            "Enables authenticated scanning to discover post-login vulnerabilities."
        ),
        show_default=False,
    ),
    header: Optional[str] = typer.Option(
        None,
        "--header",
        help=(
            "Custom HTTP header injected into all active tools as -H '...'.\n"
            "Example: --header 'Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...'\n"
            "Can be combined with --cookie for full authenticated session support."
        ),
        show_default=False,
    ),
    screenshots: bool = typer.Option(
        False,
        "--screenshots",
        help="Enable gowitness screenshots during recon (optional).",
        is_flag=True,
    ),
    recon_dnsx: Optional[bool] = typer.Option(
        None,
        "--recon-dnsx/--no-recon-dnsx",
        help="Enable/disable optional dnsx recon add-on (default follows RECON_ENABLE_DNSX).",
        show_default=False,
    ),
    recon_naabu: Optional[bool] = typer.Option(
        None,
        "--recon-naabu/--no-recon-naabu",
        help="Enable/disable optional naabu recon add-on (default follows RECON_ENABLE_NAABU).",
        show_default=False,
    ),
    recon_subzy: Optional[bool] = typer.Option(
        None,
        "--recon-subzy/--no-recon-subzy",
        help="Enable/disable optional subzy recon add-on (default follows RECON_ENABLE_SUBZY).",
        show_default=False,
    ),
    proxy: Optional[str] = typer.Option(
        None,
        "--proxy", "-p",
        help="Global HTTP/SOCKS5 proxy for all tools (e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:9050).",
        show_default=False,
    ),
    ai_planner: bool = typer.Option(
        False,
        "--ai-planner",
        help="Enable LLM advisory targeting in Supervisor (rules-first by default).",
        is_flag=True,
    ),
    force_auto: bool = typer.Option(
        False,
        "--force-auto",
        help=(
            "Bypass ALL Human-in-the-Loop prompts and run fully automatically. "
            "\n[bold red]WARNING:[/bold red] Only use on targets you are explicitly authorised to test. "
            "\nIdeal for CI/CD pipelines and scheduled automated scans."
        ),
        is_flag=True,
        rich_help_panel="Automation",
    ),
    force_exploit: bool = typer.Option(
        False,
        "--force-exploit",
        "--dumb-exploit",
        help=(
            "Brute-force mode for ExploitAgent. Bypasses AI Commander filtering and "
            "feeds all discovered parameterized URLs to dalfox/sqlmap and all hosts to nuclei."
        ),
        is_flag=True,
        rich_help_panel="Automation",
    ),
    waf_evasion: bool = typer.Option(
        False,
        "--waf-evasion",
        help=(
            "Enable WAF-evasion runtime hardening for spoofed requests and "
            "FFUF stealth controls (jitter + randomized User-Agent)."
        ),
        is_flag=True,
        rich_help_panel="Automation",
    ),
    js_workers: Optional[int] = typer.Option(
        None,
        "--js-workers",
        help="JS Deep Inspection: max concurrent JS downloads/workers.",
        show_default=False,
    ),
    js_max_files: Optional[int] = typer.Option(
        None,
        "--js-max-files",
        help="JS Deep Inspection: max JS files to analyze.",
        show_default=False,
    ),
    llm_concurrency: Optional[int] = typer.Option(
        None,
        "--llm-concurrency",
        help="JS Deep Inspection: max concurrent LLM verification calls.",
        show_default=False,
    ),
    js_snippet_len: Optional[int] = typer.Option(
        None,
        "--js-snippet-len",
        help="JS Deep Inspection: max snippet length sent to LLM.",
        show_default=False,
    ),
    js_http_timeout: Optional[float] = typer.Option(
        None,
        "--js-http-timeout",
        help="JS Deep Inspection: per-file download timeout (seconds).",
        show_default=False,
    ),
    js_llm_timeout: Optional[float] = typer.Option(
        None,
        "--js-llm-timeout",
        help="JS Deep Inspection: LLM verification timeout (seconds).",
        show_default=False,
    ),
    turbo: bool = typer.Option(
        False,
        "--turbo",
        help="Enable High-Speed mode (Bypass Safe-by-Default limits for VPS/Data Center).",
        is_flag=True,
        rich_help_panel="Automation",
    ),
) -> None:
    """
    Launch a full AI-driven bug bounty hunt against TARGET.

    AI provider is auto-detected from your .env:
      OPENAI_API_KEY=sk-...   → OpenAI (gpt-4o-mini)
      GEMINI_API_KEY=AIza...  → Google Gemini (gemini-2.5-pro)

    AUTHENTICATED SCANNING: Use --cookie and/or --header to inject session
    credentials into httpx, katana, nuclei, dalfox, and sqlmap. This enables
    discovery of post-authentication vulnerabilities commonly missed by
    unauthenticated scans.

    The Supervisor AI will orchestrate Recon, Exploit, and Reporter agents
    in an intelligent loop, storing all state in a local SQLite database.
    A JSON + Markdown report is saved to the OUTPUT directory on completion.
    """
    coro = _async_hunt(
        target=target,
        scope_input=scope,
        output_dir=output,
        evidence_dir=evidence_dir,
        max_loops=max_loops,
        timeout=timeout,
        nuclei_timeout=nuclei_timeout,
        fast_nuclei=fast_nuclei,
        nuclei_rate_limit=nuclei_rate_limit,
        nuclei_concurrency=nuclei_concurrency,
        nuclei_http_timeout=nuclei_http_timeout,
        profile=profile,
        safe_mode=safe_mode,
        update_templates=update_templates,
        stealth=stealth,
        allow_redirects=allow_redirects,
        disable_stealth=disable_stealth,
        cookie=cookie,
        header=header,
        proxy=proxy,
        screenshots=screenshots,
        recon_dnsx=recon_dnsx,
        recon_naabu=recon_naabu,
        recon_subzy=recon_subzy,
        ai_planner=ai_planner,
        force_auto=force_auto,
        force_exploit=force_exploit,
        waf_evasion=waf_evasion,
        js_workers=js_workers,
        js_max_files=js_max_files,
        llm_concurrency=llm_concurrency,
        js_snippet_len=js_snippet_len,
        js_http_timeout=js_http_timeout,
        js_llm_timeout=js_llm_timeout,
        turbo=turbo,
    )

    # B-01/B-02 fix: asyncio.run() is the only correct synchronous entry-point
    # for a Typer command launching an async pipeline.  It always creates a
    # fresh event loop, runs the coroutine to completion, and propagates
    # exceptions cleanly.  The old get_event_loop()/create_task() path was
    # fire-and-forget — all errors were silently swallowed.
    try:
        success = asyncio.run(coro)
    except KeyboardInterrupt:
        console.print("\n[yellow]Hunt interrupted by user (Ctrl+C).[/yellow]")
        raise typer.Exit(code=130)
    if not success:
        raise typer.Exit(code=1)


async def _async_hunt(
    target: str,
    scope_input: str,
    output_dir: str,
    evidence_dir: str,
    max_loops: int,
    timeout: int,
    nuclei_timeout: int | None,
    fast_nuclei: bool | None,
    nuclei_rate_limit: int | None,
    nuclei_concurrency: int | None,
    nuclei_http_timeout: int | None,
    profile: str,
    safe_mode: bool,
    update_templates: bool,
    stealth: bool,
    allow_redirects: bool,
    disable_stealth: bool,
    cookie: str | None,
    header: str | None,
    proxy: str | None = None,
    screenshots: bool = False,
    recon_dnsx: bool | None = None,
    recon_naabu: bool | None = None,
    recon_subzy: bool | None = None,
    ai_planner: bool = False,
    force_auto: bool = False,
    force_exploit: bool = False,
    waf_evasion: bool = False,
    js_workers: int | None = None,
    js_max_files: int | None = None,
    llm_concurrency: int | None = None,
    js_snippet_len: int | None = None,
    js_http_timeout: float | None = None,
    js_llm_timeout: float | None = None,
    turbo: bool = False,
) -> bool:
    """Async implementation of the hunt command.  Returns True on success, False on fatal preflight failure."""
    from ghilliesuite_ex.config import RuntimeConfigOverrides, cfg, validate_config
    from ghilliesuite_ex.agents.supervisor import SupervisorAgent
    from ghilliesuite_ex.agents.base import AgentTask
    from ghilliesuite_ex.utils.nuclei import update_nuclei_templates

    started_at = datetime.now(timezone.utc)
    run_slug = safe_run_slug(target, started_at)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    failure_stage = ""
    counts: dict[str, int] = {}
    tooling_manifest: dict[str, object] = {}
    target_session_manifest: dict[str, object] = {}
    scope_domains: list[str] = []

    def _runtime_flags_snapshot() -> dict[str, object]:
        return {
            "safe_mode": bool(safe_mode),
            "stealth": bool(stealth),
            "disable_stealth": bool(disable_stealth),
            "allow_redirects": bool(allow_redirects),
            "screenshots": bool(screenshots),
            "ai_planner": bool(ai_planner),
            "force_auto": bool(force_auto),
            "force_exploit": bool(force_exploit),
            "waf_evasion": bool(waf_evasion),
            "turbo": bool(turbo),
            "update_templates": bool(update_templates),
            "generate_bounty_draft": bool(getattr(cfg, "generate_bounty_draft", False)),
            "max_loops": max_loops,
            "timeout": timeout,
            "nuclei_timeout": nuclei_timeout,
            "nuclei_rate_limit": nuclei_rate_limit,
            "nuclei_concurrency": nuclei_concurrency,
            "nuclei_http_timeout": nuclei_http_timeout,
            "js_workers": js_workers,
            "js_max_files": js_max_files,
            "llm_concurrency": llm_concurrency,
            "js_snippet_len": js_snippet_len,
            "js_http_timeout": js_http_timeout,
            "js_llm_timeout": js_llm_timeout,
            "recon_dnsx": recon_dnsx,
            "recon_naabu": recon_naabu,
            "recon_subzy": recon_subzy,
        }

    def _write_manifest(status: str, summary: str) -> None:
        finished_at = datetime.now(timezone.utc)
        manifest = build_run_manifest(
            target=target,
            scope=scope_domains,
            started_at=started_at,
            finished_at=finished_at,
            status=status,
            summary=summary,
            execution_profile=getattr(cfg, "execution_profile", str(profile)),
            ai_enabled=bool(getattr(cfg, "ai_enabled", False)),
            ai_provider=getattr(cfg, "ai_provider", "none"),
            ai_status_message=getattr(cfg, "ai_status_message", "AI triage disabled"),
            ai_disabled_reason=getattr(cfg, "ai_disabled_reason", ""),
            output_dir=str(output_path.resolve()),
            evidence_dir=str(Path(evidence_dir).resolve()),
            db_path=getattr(cfg, "db_path", ""),
            runtime_flags=_runtime_flags_snapshot(),
            tooling=tooling_manifest,
            counts=counts,
            failure_stage=failure_stage or None,
            target_session=target_session_manifest,
        )
        manifest_path = write_run_manifest(output_path, run_slug, manifest)
        console.print(f"[dim]Run manifest: {manifest_path.resolve()}[/dim]")

    # ── Banner ─────────────────────────────────────────────────────────────
    print_banner(console)
    if allow_redirects:
        console.print("[yellow]Automatic redirects are disabled to keep requests within scope.[/yellow]")

    # ── Auto-detect AI provider + validate ────────────────────────────────
    ai_status_logged = False
    if cfg.ai_provider != "none" and cfg.active_api_key:
        try:
            resolved_provider = validate_config()
        except RuntimeError as exc:
            cfg.disable_ai(str(exc).splitlines()[0])
            _print_ai_disabled_log(cfg.ai_disabled_reason)
            ai_status_logged = True
        else:
            cfg.enable_ai()
            _print_provider_log(resolved_provider)
    else:
        cfg.disable_ai("No API key configured.")
        _print_ai_disabled_log(cfg.ai_disabled_reason)
        ai_status_logged = True

    # ── Store auth credentials in global config ────────────────────────────
    # These are set here (not in Config.__init__) because they are per-session
    # CLI values, not environment variables.
    try:
        normalized_profile = normalize_execution_profile(profile)
    except ValueError as exc:
        console.print(f"[bold red]Profile error:[/bold red] {exc}")
        failure_stage = "profile_validation"
        _write_manifest("preflight_failed", str(exc))
        return False  # B-03: propagate failure via return value, not typer.Exit inside a coroutine

    cfg.apply_runtime_overrides(
        RuntimeConfigOverrides(
            execution_profile=normalized_profile,
            auth_cookie=cookie if cookie is not None else "",
            auth_header=header if header is not None else "",
            proxy=proxy if proxy is not None else cfg.proxy,
            enable_screenshots=bool(screenshots),
            ai_planner=bool(ai_planner),
            force_exploit=bool(force_exploit),
            waf_evasion=bool(waf_evasion),
            output_dir=output_dir,
            evidence_dir=evidence_dir,
            allow_redirects=bool(allow_redirects),
            stealth_mode=bool(stealth),
            disable_stealth=bool(disable_stealth),
            nuclei_timeout=nuclei_timeout,
            fast_nuclei=bool(fast_nuclei) if fast_nuclei is not None else None,
            nuclei_rate_limit=nuclei_rate_limit,
            nuclei_concurrency=nuclei_concurrency,
            nuclei_http_timeout=nuclei_http_timeout,
            js_max_workers=js_workers,
            js_max_files=js_max_files,
            js_llm_concurrency=llm_concurrency,
            js_snippet_max_len=js_snippet_len,
            js_http_timeout=js_http_timeout,
            js_llm_timeout=js_llm_timeout,
            recon_enable_dnsx=bool(recon_dnsx) if recon_dnsx is not None else None,
            recon_enable_naabu=bool(recon_naabu) if recon_naabu is not None else None,
            recon_enable_subzy=bool(recon_subzy) if recon_subzy is not None else None,
            turbo_mode=bool(turbo),
            force_auto=bool(force_auto),
            max_agent_loops=max_loops,
            default_timeout=timeout,
        )
    )
    safety_policy = get_execution_safety_policy(cfg.execution_profile)

    console.print(
        "[bold cyan]Execution profile:[/bold cyan] "
        f"[bold]{safety_policy.profile}[/bold]"
    )
    console.print(f"[dim]  {safety_policy.description}[/dim]")
    console.print()

    if force_exploit:
        console.print(
            "[bold red]FORCE-EXPLOIT MODE ACTIVE[/bold red]  "
            "[dim]- AI Commander filtering bypassed for ExploitAgent.[/dim]"
        )
        console.print("[dim]  dalfox/sqlmap: all URLs with params; nuclei: all hosts.[/dim]")
        console.print()

    if waf_evasion:
        console.print(
            "[bold bright_yellow]WAF EVASION HARDENING ACTIVE[/bold bright_yellow]  "
            "[dim]— request spoofing + FFUF jitter/UA hardening enabled[/dim]"
        )
        console.print()

    if force_exploit and not safety_policy.force_exploit_allowed:
        console.print(
            "[yellow]  force-exploit requested, but the active profile will still block broad exploit-only paths until aggressive mode is selected.[/yellow]"
        )
    if cfg.execution_profile != "aggressive" and waf_evasion:
        console.print(
            "[dim]  waf-evasion hardening remains active across profiles (mutation probes removed).[/dim]"
        )

    if stealth:
        console.print("[bold yellow]Stealth mode enabled[/bold yellow]  [dim]— lower request rate & concurrency[/dim]")

    if disable_stealth:
        if cfg.stealth_mode:
            console.print(
                "[bold yellow]Stealth override disabled[/bold yellow]  "
                "[dim]— --disable-stealth overrides --stealth[/dim]"
            )
        console.print(
            "[bold yellow]Sniper protocol disabled[/bold yellow]  "
            "[dim]— WAF signals will not reduce execution[/dim]"
        )


    if turbo:
        console.print("[bold red]TURBO MODE ACTIVE[/bold red] [dim]— bypassing safe limits for high-speed scanning[/dim]")

    console.print(
        "[bold cyan]JS Deep Inspection config:[/bold cyan] "
        f"workers={cfg.js_max_workers}, "
        f"max_files={cfg.js_max_files}, "
        f"llm_concurrency={cfg.js_llm_concurrency}, "
        f"snippet_max_len={cfg.js_snippet_max_len}, "
        f"http_timeout={cfg.js_http_timeout}s, "
        f"llm_timeout={cfg.js_llm_timeout}s"
    )
    console.print(
        "[bold cyan]Recon add-ons:[/bold cyan] "
        f"dnsx={'on' if cfg.recon_enable_dnsx else 'off'}, "
        f"naabu={'on' if cfg.recon_enable_naabu else 'off'}, "
        f"subzy={'on' if cfg.recon_enable_subzy else 'off'} "
        "[dim](gau/arjun remain enabled by default)[/dim]"
    )

    if cfg.is_authenticated:
        console.print(
            "[bold bright_yellow][+] Authenticated mode active[/bold bright_yellow]  "
            "[dim]— auth credentials will be injected into httpx, katana, nuclei, dalfox, sqlmap[/dim]"
        )
        if cfg.auth_cookie:
            console.print("    [dim]Cookie configured[/dim]")
        if cfg.auth_header:
            console.print("    [dim]Authorization header configured[/dim]")
        console.print()

    # ── Force-auto mode ────────────────────────────────────────────────────
    if force_auto:
        console.print(
            "[bold red]⚠️  FORCE-AUTO MODE ACTIVE — All HitL prompts bypassed.[/bold red]\n"
            "[dim]   Active scanners may run without confirmation.\n"
            "   Only use on targets you are explicitly, legally authorised to test.[/dim]"
        )
        console.print()

    # ── Scope loading ──────────────────────────────────────────────────────
    try:
        scope_domains = load_scope(scope_input)
    except (ValueError, FileNotFoundError) as exc:
        console.print(f"[bold red]Scope error:[/bold red] {exc}")
        failure_stage = "scope_load"
        _write_manifest("preflight_failed", str(exc))
        return False  # B-03

    console.print(f"[green]✔[/green] Scope loaded: {', '.join(scope_domains)}")

    # Validate target is in scope before any scan starts
    try:
        validate_target_scope(target, scope_domains)
    except ValueError as exc:
        console.print(
            f"[bold red]❌ Target rejected by scope preflight.[/bold red]\n"
            f"   Reason: {exc}\n"
            f"   Scope: {', '.join(scope_domains)}\n"
            "   Adjust the target or scope rules and retry."
        )
        failure_stage = "scope_preflight"
        _write_manifest("preflight_failed", str(exc))
        return False  # B-03

    # ── Binary availability check ──────────────────────────────────────────
    console.print()
    results = check_binaries(console, profile=cfg.execution_profile)
    tooling_status = collect_tooling_status(profile=cfg.execution_profile)
    missing = [name for name in tooling_status.required_tools if not results.get(name)]
    tooling_manifest = {
        "required_missing": missing,
        "optional_missing": [
            name for name in tooling_status.optional_tools if not results.get(name)
        ],
        "optional_dependencies_missing": [
            dep.name for dep in tooling_status.optional_dependencies if not dep.installed
        ],
        "disabled_by_profile": list(tooling_status.disabled_by_profile),
    }
    if missing:
        console.print(
            f"\n[bold red]Missing required recon tools:[/bold red] {', '.join(missing)}\n"
            "Install them and ensure they are on your PATH, then re-run the hunt."
        )
        failure_stage = "tool_preflight"
        _write_manifest("preflight_failed", f"Missing required recon tools: {', '.join(missing)}")
        return False  # B-03

    # ── Nuclei template update (runs before hunting starts) ──────────────
    if update_templates:
        console.print("\n[cyan]Updating nuclei templates (nuclei -ut)…[/cyan]")
        nuclei_update = await asyncio.to_thread(update_nuclei_templates, 120)
        if nuclei_update.ok:
            console.print("[green]✔ Nuclei templates updated.[/green]")
        else:
            console.print(
                f"[yellow]⚠ nuclei -ut failed (continuing anyway): {nuclei_update.error[:80]}[/yellow]"
            )

    # ── Initialise AI client ───────────────────────────────────────────────
    ai_client = _build_ai_client(cfg)
    if ai_client is None and not ai_status_logged:
        _print_ai_disabled_log(cfg.ai_disabled_reason or "AI client unavailable.")

    # ── Environment sanity checks ──────────────────────────────────────────
    # Target isolation is handled centrally inside StateDB.

    # ── Initialise DB and run supervisor ──────────────────────────────────
    console.print()
    console.print(Rule("[bold]Starting agent swarm[/bold]", style="bright_magenta"))


    # Ensure the DB directory exists (for the hardcoded ~/GhillieSuite-EX/ path)
    import os as _os
    _db_dir = _os.path.dirname(_os.path.abspath(cfg.db_path))
    if _db_dir:
        _os.makedirs(_db_dir, exist_ok=True)

    result_summary = "Pipeline terminated early — see error log above."
    async with StateDB(cfg.db_path, target=target) as db:
        target_session = db.target_session
        target_session_manifest = {
            "requested_target": target_session.requested_target,
            "stored_target_before": target_session.stored_target_before,
            "active_target": target_session.active_target,
            "data_reset": target_session.data_reset,
        }
        supervisor = SupervisorAgent(
            db=db,
            ai_client=ai_client,
            scope=scope_domains,
            console=console,
            config=cfg,
            safe_mode=safe_mode,
            max_loops=max_loops,
        )
        from ghilliesuite_ex.agents.base import AgentTask
        task = AgentTask(target=target, safe_mode=safe_mode)

        try:
            result = await supervisor.run(task)
            result_summary = result.summary
            if result.status == "error":
                failure_stage = "agent_runtime"
        except Exception as _agent_exc:
            failure_stage = "agent_runtime"
            console.print(
                f"\n[bold red]⚠ Agent swarm encountered an unhandled error:[/bold red]\n"
                f"  [red]{_agent_exc}[/red]\n"
                f"[dim]Partial database results were preserved.[/dim]"
            )
            result_summary = (
                f"Agent swarm encountered an unhandled error but preserved partial results: {_agent_exc}"
            )

        from ghilliesuite_ex.utils.scope import is_in_scope
        counts = {
            "hosts": len(await db.get_hosts(scope_domains=scope_domains)),
            "endpoints": sum(is_in_scope(ep.url, scope_domains) for ep in await db.get_endpoints()),
            "findings": sum(is_in_scope(f.target, scope_domains) for f in await db.get_findings()),
            "screenshots": sum(is_in_scope(s.url, scope_domains) for s in await db.get_screenshots()),
        }

    if failure_stage:
        console.print(f"\n[bold red]Hunt finished with errors. {result_summary}[/bold red]")
    else:
        console.print(f"\n[bold bright_green]Hunt complete! {result_summary}[/bold bright_green]")
    final_status = "completed_with_errors" if failure_stage else "completed"
    _write_manifest(final_status, result_summary)
    return not failure_stage
def _build_ai_client(config):
    """
    Construct the AI client using the auto-detected provider stored in cfg.
    Returns None when AI is disabled or client initialisation fails.
    """
    if not getattr(config, "ai_enabled", False):
        return None

    provider = config.ai_provider

    try:
        if provider == "openai":
            from openai import AsyncOpenAI
            return AsyncOpenAI(api_key=config.openai_api_key)

        if provider == "gemini":
            import google.generativeai as genai
            genai.configure(api_key=config.gemini_api_key)
            return genai.GenerativeModel(
                model_name=config.gemini_model,
                generation_config={"temperature": 0.2, "max_output_tokens": 1024},
            )

    # Should never reach here — validate_config() already caught this
    except Exception as exc:
        config.disable_ai(f"{provider} client init failed: {exc}")
        return None

    config.disable_ai(f"Unsupported AI provider '{provider}'.")
    return None


def _print_provider_log(provider: str) -> None:
    """
    Print the styled '[+] Auto-detected AI Provider: ...' startup message.
    """
    from ghilliesuite_ex.config import cfg
    provider_styles = {
        "openai": ("bright_green", "🤖 OpenAI", cfg.openai_model),
        "gemini": ("bright_cyan",  "✨ Google Gemini", cfg.gemini_model),
    }
    color, label, model = provider_styles.get(
        provider, ("yellow", f"Unknown ({provider})", "?")
    )
    console.print(
        f"  [bold {color}][+] Auto-detected AI Provider: {label}[/bold {color}]  "
        f"[dim]model: {model}[/dim]"
    )
    console.print()


def _print_ai_disabled_log(reason: str) -> None:
    detail = reason or "No AI provider available."
    console.print(
        "  [bold yellow][+] AI triage disabled[/bold yellow]  "
        f"[dim]{detail}[/dim]"
    )
    console.print(
        "[dim]  Falling back to standard recon, scope enforcement, and rate-limited exploit scans.[/dim]"
    )
    console.print()


# ──────────────────────────────────────────────────────────────────────────────
# check-tools
# ──────────────────────────────────────────────────────────────────────────────

@app.command(name="check-tools")
def check_tools(
    profile: str = typer.Option(
        "balanced",
        "--profile",
        help="Execution profile: vdp-safe, balanced, or aggressive.",
        show_default=True,
    ),
) -> None:
    """Show required tools, optional tooling, and profile-disabled binaries."""
    print_banner(console)
    try:
        normalized_profile = normalize_execution_profile(profile)
    except ValueError as exc:
        console.print(f"[bold red]Profile error:[/bold red] {exc}\n")
        raise typer.Exit(code=1)

    results = check_binaries(console, profile=normalized_profile)
    tooling_status = collect_tooling_status(profile=normalized_profile)
    missing_required = [
        name for name in tooling_status.required_tools if not results.get(name)
    ]
    missing_optional = [
        name for name in tooling_status.optional_tools if not results.get(name)
    ]
    missing_deps = [
        dep.name for dep in tooling_status.optional_dependencies if not dep.installed
    ]
    if missing_required:
        console.print(
            f"\n[red]Missing required tools:[/red] {', '.join(missing_required)}"
        )
        console.print("[dim]Install them before running a full hunt.[/dim]")
    else:
        console.print("\n[green]Required tools ready for this profile.[/green]")

    if missing_optional:
        console.print(
            f"[yellow]Optional binaries not installed:[/yellow] {', '.join(missing_optional)}"
        )
    if missing_deps:
        console.print(
            f"[yellow]Optional dependencies not installed:[/yellow] {', '.join(missing_deps)}"
        )
    if tooling_status.disabled_by_profile:
        console.print(
            f"[cyan]Disabled by profile '{normalized_profile}':[/cyan] "
            f"{', '.join(tooling_status.disabled_by_profile)}"
        )
    console.print()


# ──────────────────────────────────────────────────────────────────────────────
# check-config
# ──────────────────────────────────────────────────────────────────────────────

@app.command(name="check-config")
def check_config() -> None:
    """Validate the .env configuration and show which AI provider was auto-detected."""
    print_banner(console)
    try:
        resolved = validate_config()   # auto-detect
        from ghilliesuite_ex.config import cfg
        _print_provider_log(resolved)
        console.print(f"[green]✔ Configuration valid.[/green]  Provider: [bold]{cfg.provider_display}[/bold]\n")
    except RuntimeError as exc:
        console.print(f"[bold red]Configuration error:[/bold red]\n{exc}\n")
        raise typer.Exit(code=1)


# ──────────────────────────────────────────────────────────────────────────────
# version
# ──────────────────────────────────────────────────────────────────────────────

@app.command()
def version() -> None:
    """Show the GhillieSuite-EX version."""
    console.print(f"[cyan]{__app_name__}[/cyan] v[bold]{__version__}[/bold]")


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
