"""
ghilliesuite_ex/agents/supervisor.py
─────────────────────────
SupervisorAgent — the orchestration brain of GhillieSuite-EX.

Responsibilities:
  1. Read a compact DB summary (never raw tool output).
  2. Ask the AI: "What should the next agent + tool be?"
  3. Dispatch to ReconAgent, ExploitAgent, or ReporterAgent.
  4. Iterate up to MAX_AGENT_LOOPS; stop when AI returns phase="done".

The Supervisor never touches files or runs tools directly.
All state changes happen inside the specialised agents.
"""

from __future__ import annotations

import json
import re

from rich.console import Console
from rich.rule import Rule

from ghilliesuite_ex.config import Config, cfg
from ghilliesuite_ex.arsenal import TOOL_REGISTRY
from ghilliesuite_ex.state.db import StateDB
from ghilliesuite_ex.utils.scope import is_in_scope
from ghilliesuite_ex.utils.ui import agent_panel, status_dashboard

from .base import AgentResult, AgentTask, BaseAgent
from .exploit import ExploitAgent
from .recon import ReconAgent
from .reporter import ReporterAgent

# ── System prompt injected into every Supervisor AI call ──────────────────────
SUPERVISOR_SYSTEM_PROMPT = """\
You are an automated Bug Bounty Hunter operating on an AUTHORISED HackerOne target.
Your job is to orchestrate a team of specialised agents to find vulnerabilities.

Available agents:
  • recon    — Runs passive/active reconnaissance (subfinder, httpx, katana, gau).
               Use this first and any time you want more data about the target.
  • exploit  — Runs vulnerability scanners and exploitation tools (nuclei, dalfox, sqlmap).
               Only use after recon has found live hosts and endpoints.
  • reporter — Compiles all findings from the database into a final report.
               Use this when no more useful discoveries are expected.

Focus on: IDOR, SSRF, XSS, SQL Injection, Open Redirect, and latest CVEs.

You will receive a JSON snapshot of the current database state.
Based on that, respond with ONLY a JSON object (no markdown fences, no prose):
{
  "phase": "recon" | "exploit" | "reporter" | "fetch_cve" | "done",
  "agent": "ReconAgent" | "ExploitAgent" | "ReporterAgent",
  "tool": "<tool_name from registry, or null>",
  "target": "<specific domain or URL to test>",
  "reason": "<one sentence explaining your decision>",
  "cve_keyword": "<keyword if phase=fetch_cve, else null>"
}

Rules:
  - NEVER suggest a tool that is not in the registry.
  - NEVER suggest targeting an out-of-scope domain.
  - If hosts_count == 0, always start with recon.
  - If findings already cover the majority of endpoints, move to reporter.
  - Prefer high-impact vulnerabilities (critical/high severity).
  - When in doubt, do more recon.
"""


def _extract_json_block(text: str) -> str:
    """Return the first JSON object found in text, or the original text."""
    cleaned = (text or "").strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        return cleaned[start:end + 1]
    return cleaned


class SupervisorAgent(BaseAgent):
    """
    Hierarchical supervisor that delegates tasks to specialised sub-agents
    and drives the main hunt loop.
    """

    def __init__(
        self,
        db: StateDB,
        ai_client,
        scope: list[str],
        console: Console,
        config: Config | None = None,
        safe_mode: bool = False,
        max_loops: int | None = None,
    ) -> None:
        super().__init__(db, ai_client, scope, console, config)
        self.safe_mode = safe_mode
        self.max_loops = max_loops or self.cfg.max_agent_loops

        # Instantiate sub-agents (all share the same DB + AI client)
        self.recon_agent = ReconAgent(db, ai_client, scope, console, config)
        self.exploit_agent = ExploitAgent(db, ai_client, scope, console, config)
        self.reporter_agent = ReporterAgent(db, ai_client, scope, console, config)

    async def run(self, task: AgentTask) -> AgentResult:
        """Rules-first orchestration loop with optional AI advisory."""
        target = task.target
        self.console.print(
            Rule(f"[bold bright_magenta]Hunt started (Rules-First) - target: {target}[/bold bright_magenta]",
                 style="bright_magenta")
        )

        def in_scope_findings(findings):
            return [finding for finding in findings if is_in_scope(finding.target, self.scope)]

        initial_findings = len(in_scope_findings(await self.db.get_findings()))
        failures: list[str] = []
        last_snapshot: tuple[int, int, int, int] | None = None
        # RC7: require 2 consecutive stable iterations before early exit.
        # Previously the loop stopped after 1 stable recon run, which often meant
        # exploit had not yet had a full pass. stable_streak ensures exploit
        # completes at least once before the session terminates.
        stable_streak = 0
        exploit_ran = False

        for loop_idx in range(1, self.max_loops + 1):
            agent_panel(self.console, "ReconAgent", "subfinder, dnsx, naabu, httpx, katana, gau, arjun", target, loop_idx, self.max_loops)
            try:
                res_recon = await self.recon_agent.run(AgentTask(target=target, safe_mode=self.safe_mode))
            except Exception as exc:
                res_recon = AgentResult("ReconAgent", "error", f"Recon failed: {exc}", error=str(exc))
            if res_recon.status == "error":
                failures.append(f"recon: {res_recon.error or res_recon.summary}")
            self.console.print(f"[dim]  -> ReconAgent: {res_recon.summary}[/dim]")

            hosts = await self.db.get_hosts(self.scope)
            endpoints = [ep for ep in await self.db.get_endpoints() if is_in_scope(ep.url, self.scope)]
            endpoints_with_params = sum(1 for e in endpoints if e.params)
            finding_count = len(in_scope_findings(await self.db.get_findings()))
            status_dashboard(self.console, len(hosts), len(endpoints), finding_count, endpoints_with_params)

            if endpoints:
                tool_override = None
                reason = ""
                if self.cfg.ai_planner:
                    tool_override, reason = await self._ai_advisory_tool_choice()
                agent_panel(
                    self.console,
                    "ExploitAgent",
                    "nuclei, dalfox, sqlmap, ffuf, js_secret, proto, rsc, trufflehog",
                    target,
                    loop_idx,
                    self.max_loops,
                )
                try:
                    res_exploit = await self.exploit_agent.run(
                        AgentTask(target=target, safe_mode=self.safe_mode, tool_name=tool_override, reason=reason)
                    )
                except Exception as exc:
                    res_exploit = AgentResult("ExploitAgent", "error", f"Exploit failed: {exc}", error=str(exc))
                if res_exploit.status == "error":
                    failures.append(f"exploit: {res_exploit.error or res_exploit.summary}")
                self.console.print(f"[dim]  -> ExploitAgent: {res_exploit.summary}[/dim]")
                exploit_ran = res_exploit.status in {"ok", "skipped"}

            finding_count = len(in_scope_findings(await self.db.get_findings()))
            snapshot = (len(hosts), len(endpoints), endpoints_with_params, finding_count)
            stable_now = snapshot == last_snapshot and res_recon.status != "error"
            if stable_now and (not endpoints or exploit_ran):
                stable_streak += 1
            else:
                stable_streak = 0
            last_snapshot = snapshot

            # Exit only after 2 consecutive stable iterations AND exploit has run at least once.
            if stable_streak >= 2 and exploit_ran and not failures:
                self.console.print("[dim]Recon stable for 2 iterations and exploit complete. Exiting loop.[/dim]")
                break
            elif stable_now and not exploit_ran:
                self.console.print("[dim]Recon stable but exploit has not run yet -- continuing.[/dim]")

        self.console.print(Rule("[bold bright_green]Compiling Report[/bold bright_green]", style="bright_green"))
        try:
            report_result = await self.reporter_agent.run(AgentTask(target=target))
        except Exception as exc:
            report_result = AgentResult("ReporterAgent", "error", f"Report failed: {exc}", error=str(exc))
        if report_result.status == "error":
            failures.append(f"reporter: {report_result.error or report_result.summary}")

        finding_count = len(in_scope_findings(await self.db.get_findings()))
        unique_failures = list(dict.fromkeys(failures))
        failure_note = f" Failed stages: {'; '.join(unique_failures)}." if unique_failures else ""
        close_exploit = getattr(self.exploit_agent, "close", None)
        if callable(close_exploit):
            close_exploit()

        return AgentResult(
            agent=self.name,
            status="error" if unique_failures else "ok",
            summary=f"Rules-first pipeline complete. {finding_count} finding(s) stored.{failure_note}",
            items_added=max(0, finding_count - initial_findings),
            error="; ".join(unique_failures),
        )

    async def _ai_advisory_tool_choice(self) -> tuple[str | None, str]:
        """Optional LLM advisory: suggest a tool override within the registry."""
        try:
            summary = await self.db.get_summary_for_ai()
        except Exception:
            summary = "{}"

        allowed_tools = list(TOOL_REGISTRY.keys())
        prompt = (
            "You are an advisory assistant. Suggest a single tool to run next, or null.\n"
            "Return ONLY JSON: {\"tool\": <tool|NULL>, \"target\": <url|domain|NULL>, \"reason\": <short>}\n\n"
            f"Allowed tools: {', '.join(allowed_tools)}\n"
            f"Scope: {', '.join(self.scope)}\n\n"
            f"DB summary:\n{summary}\n"
        )

        raw = await self._ask_ai(prompt)
        json_text = _extract_json_block(raw)
        try:
            data = json.loads(json_text)
        except Exception:
            return (None, "")

        tool = (data.get("tool") or "").strip().lower()
        target = (data.get("target") or "").strip()
        reason = (data.get("reason") or "").strip()

        if not tool or tool == "null":
            return (None, reason)
        if tool not in TOOL_REGISTRY:
            return (None, reason)
        if target and not is_in_scope(target, self.scope):
            return (None, reason)

        return (tool, reason)

    # ── Internal helpers ───────────────────────────────────────────────────────

    # Helper properties deleted to reduce bloat

    async def _dispatch(self, phase: str, task: AgentTask) -> AgentResult:
        """Route a phase string to the correct sub-agent."""
        route: dict[str, BaseAgent] = {
            "recon": self.recon_agent,
            "exploit": self.exploit_agent,
            "reporter": self.reporter_agent,
        }
        agent = route.get(phase, self.reporter_agent)
        try:
            return await agent.run(task)
        except Exception as exc:
            return AgentResult(
                agent=agent.name,
                status="error",
                summary=f"Unhandled exception in {agent.name}",
                error=str(exc),
            )

    async def _handle_fetch_cve(self, keyword: str) -> None:
        """Fetch a CVE and cache the result in the DB."""
        from ghilliesuite_ex.utils.cve_fetcher import fetch_latest_cve
        self.console.print(f"[cyan]  Fetching CVE for: {keyword}[/cyan]")
        result = await fetch_latest_cve(keyword, db=self.db)
        self.console.print(
            f"  [bold]{result.cve_id}[/bold]  CVSS {result.cvss_score}  "
            f"{result.description[:120]}..."
        )
        if result.poc_url:
            self.console.print(f"  [dim]PoC: {result.poc_url}[/dim]")
