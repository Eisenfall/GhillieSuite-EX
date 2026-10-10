"""
ReporterAgent queries the state DB and writes structured report artifacts.

The agent owns orchestration and output paths; report shaping/rendering lives in
ghilliesuite_ex.utils.reporter so JSON/Markdown/HTML stay aligned.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from rich.rule import Rule

from ghilliesuite_ex.utils.reporter import (
    HtmlReporter,
    build_report_data,
    filter_report_records,
    render_markdown_report,
)
from ghilliesuite_ex.utils.run_metadata import safe_run_slug
from ghilliesuite_ex.utils.ui import findings_table

from .base import AgentResult, AgentTask, BaseAgent


class ReporterAgent(BaseAgent):
    """Compile DB findings into JSON, Markdown, and HTML reports."""

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        findings = await self.db.get_findings()
        hosts = await self.db.get_hosts()
        endpoints = await self.db.get_endpoints()
        screenshots = await self.db.get_screenshots()
        findings, hosts, endpoints, screenshots = filter_report_records(
            self.scope, findings, hosts, endpoints, screenshots,
        )

        if not findings:
            findings_table(self.console, findings)
        else:
            stealth_findings = [finding for finding in findings if finding.tool == "stealth_payload"]
            standard_findings = [finding for finding in findings if finding.tool != "stealth_payload"]
            if standard_findings:
                findings_table(self.console, standard_findings, title="Findings Summary")
            if stealth_findings:
                findings_table(
                    self.console,
                    stealth_findings,
                    title="AI Stealth Probes & WAF Bypasses",
                )

        output_dir = Path(getattr(self.cfg, "output_dir", "reports") or "reports")
        output_dir.mkdir(parents=True, exist_ok=True)

        now_utc = datetime.now(timezone.utc)
        base_name = safe_run_slug(target, now_utc)

        json_path = output_dir / f"{base_name}.json"
        report_data = build_report_data(
            target=target,
            generated_at=now_utc.isoformat(),
            scope=self.scope,
            findings=findings,
            hosts=hosts,
            endpoints=endpoints,
            screenshots=screenshots,
            config=self.cfg,
            ai_available=bool(getattr(self.cfg, "ai_enabled", False) and self.ai is not None),
        )
        json_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")

        md_path = output_dir / f"{base_name}.md"
        md_path.write_text(
            render_markdown_report(
                target=target,
                generated_at=now_utc,
                scope=self.scope,
                findings=findings,
                hosts=hosts,
                endpoints=endpoints,
                screenshots=screenshots,
                config=self.cfg,
            ),
            encoding="utf-8",
        )

        self.console.print()
        self.console.print(Rule("[bold bright_green]Report saved[/bold bright_green]", style="bright_green"))
        self.console.print(f"  JSON: [underline]{json_path.resolve()}[/underline]")
        self.console.print(f"  MD:   [underline]{md_path.resolve()}[/underline]")
        self.console.print(
            f"[dim]  JS Deep Inspection config: workers={self.cfg.js_max_workers}, "
            f"llm_concurrency={self.cfg.js_llm_concurrency}, "
            f"snippet_max_len={self.cfg.js_snippet_max_len}, "
            f"http_timeout={self.cfg.js_http_timeout}s, "
            f"llm_timeout={self.cfg.js_llm_timeout}s[/dim]"
        )

        try:
            html_reporter = HtmlReporter(
                db=self.db,
                ai_client=self.ai,
                console=self.console,
                config=self.cfg,
            )
            html_path = await html_reporter.generate(
                target=target,
                scope=self.scope,
                output_dir=output_dir,
                base_name=base_name,
            )
            self.console.print(f"  HTML: [underline]{html_path.resolve()}[/underline]")
        except Exception as exc:
            self.console.print(f"[yellow]  HTML report failed (continuing): {exc}[/yellow]")

        self.console.print()
        return AgentResult(
            agent=self.name,
            status="ok",
            summary=f"Report written - {len(findings)} finding(s) across {len(hosts)} host(s).",
            items_added=0,
        )
