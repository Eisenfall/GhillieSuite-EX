"""
ghilliesuite_ex/utils/reporter.py
─────────────────────────────────
HTML Report Generator for GhillieSuite-EX.

Produces a single self-contained .html file with:
  • Executive summary dashboard (counts, severity donut)
  • Per-finding cards with AI-generated plain-English explanations
  • Collapsible technical evidence / reproducible steps sections
  • Dedicated BOLA/IDOR and AI Advisory sections
  • Appendix: discovered hosts and high-value endpoints

The AI generates three plain-English fields per finding:
  • "What is it?"  — simplified explanation for non-technical stakeholders
  • "Impact"       — why it matters / business risk
  • "Remediation"  — concise fix guidance

Usage:
    from ghilliesuite_ex.utils.reporter import HtmlReporter
    reporter = HtmlReporter(db=db, ai_client=ai, console=console, config=cfg)
    html_path = await reporter.generate(target, scope, output_dir)
"""

from __future__ import annotations

import asyncio
import base64
import html as _html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console

from ghilliesuite_ex.config import Config, cfg as global_cfg
from ghilliesuite_ex.state.db import StateDB
from ghilliesuite_ex.state.models import Finding, Host, Endpoint, Screenshot
from ghilliesuite_ex.utils.redaction import redact_text
from ghilliesuite_ex.utils.run_metadata import safe_run_slug
from ghilliesuite_ex.utils.scope import is_in_scope


# ── Severity metadata ─────────────────────────────────────────────────────────────────────
_SEV_META: dict[str, dict[str, str]] = {
    "critical": {"color": "red",    "badge": "bg-red-600",    "border": "border-red-500",  "ring": "ring-red-500",  "emoji": "🔴"},
    "high":     {"color": "orange", "badge": "bg-orange-500", "border": "border-orange-400","ring": "ring-orange-400","emoji": "🟠"},
    "medium":   {"color": "yellow", "badge": "bg-yellow-500", "border": "border-yellow-400","ring": "ring-yellow-400","emoji": "🟡"},
    "low":      {"color": "blue",   "badge": "bg-blue-500",   "border": "border-blue-400", "ring": "ring-blue-400", "emoji": "🔵"},
    "info":     {"color": "gray",   "badge": "bg-gray-500",   "border": "border-gray-400", "ring": "ring-gray-400", "emoji": "⚪"},
}
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Severities shown by default in the main section ("hot" findings)
_HOT_SEVERITIES = frozenset({"critical", "high", "medium"})

# ── Advisory tool names (passive, rendered in separate section) ─────────────────
_ADVISORY_TOOLS = frozenset({"bola_check", "ai_advisory"})

_MAX_SCREENSHOT_BYTES = 2 * 1024 * 1024  # 2 MB cap for inline HTML embedding
_MAX_EVIDENCE_CHARS = 8000


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        try:
            value.encode("utf-8")
            return value
        except UnicodeEncodeError:
            return value.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    try:
        text = str(value)
    except Exception:
        return ""
    try:
        text.encode("utf-8")
        return text
    except UnicodeEncodeError:
        return text.encode("utf-8", errors="replace").decode("utf-8", errors="replace")


def _report_safe_text(value: Any) -> str:
    return redact_text(_safe_text(value))


def _extract_evidence_paths(text: str) -> tuple[str, str]:
    """Extract evidence request/response file paths from a finding's evidence."""
    text = _safe_text(text)
    req_path = ""
    res_path = ""
    for line in (text or "").splitlines():
        if "Request:" in line:
            req_path = line.split("Request:", 1)[-1].strip()
        if "Response:" in line:
            res_path = line.split("Response:", 1)[-1].strip()
    return req_path, res_path


def _read_text_safe(path: str, max_chars: int = _MAX_EVIDENCE_CHARS) -> str:
    p = Path(path)
    if not p.exists():
        return ""
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return redact_text(text)[:max_chars]


def _image_data_uri(path: str) -> str:
    p = Path(path)
    if not p.exists():
        return ""
    try:
        if p.stat().st_size > _MAX_SCREENSHOT_BYTES:
            return ""
        data = p.read_bytes()
    except OSError:
        return ""
    ext = p.suffix.lower()
    mime = "image/png"
    if ext in (".jpg", ".jpeg"):
        mime = "image/jpeg"
    elif ext in (".webp",):
        mime = "image/webp"
    encoded = base64.b64encode(data).decode("ascii")
    return f"data:{mime};base64,{encoded}"


def serialize_scope(scope: Any) -> dict[str, Any] | list[str] | str:
    def redact_value(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: redact_value(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [redact_value(item) for item in value]
        if isinstance(value, str):
            return redact_text(value)
        return value

    if hasattr(scope, "to_dict"):
        return redact_value(scope.to_dict())
    if isinstance(scope, (list, tuple)):
        return [_report_safe_text(item) for item in scope]
    return _report_safe_text(scope)


def filter_report_records(
    scope: Any,
    findings: list[Finding],
    hosts: list[Host],
    endpoints: list[Endpoint],
    screenshots: list[Screenshot],
) -> tuple[list[Finding], list[Host], list[Endpoint], list[Screenshot]]:
    """Limit reused DB records to the scope of this report run."""
    return (
        [f for f in findings if is_in_scope(f.target, scope)],
        [h for h in hosts if is_in_scope(h.domain, scope)],
        [e for e in endpoints if is_in_scope(e.url, scope)],
        [s for s in screenshots if is_in_scope(s.url, scope)],
    )


def build_report_data(
    *,
    target: str,
    generated_at: str,
    scope: Any,
    findings: list[Finding],
    hosts: list[Host],
    endpoints: list[Endpoint],
    screenshots: list[Screenshot],
    config: Config,
    ai_available: bool,
) -> dict[str, Any]:
    ai_status = getattr(config, "ai_status_message", "AI triage disabled")
    ai_reason = getattr(config, "ai_disabled_reason", "")
    return {
        "target": _report_safe_text(target),
        "generated_at": generated_at,
        "scope": serialize_scope(scope),
        "scan_config": {
            "ai_triage": {
                "enabled": ai_available,
                "status": _report_safe_text(ai_status),
                "reason": _report_safe_text(ai_reason),
            },
            "js_deep_inspection": {
                "js_max_workers": config.js_max_workers,
                "js_max_files": config.js_max_files,
                "js_llm_concurrency": config.js_llm_concurrency,
                "js_snippet_max_len": config.js_snippet_max_len,
                "js_http_timeout": config.js_http_timeout,
                "js_llm_timeout": config.js_llm_timeout,
            },
            "force_exploit": bool(getattr(config, "force_exploit", False)),
            "generate_bounty_draft": bool(getattr(config, "generate_bounty_draft", False)),
        },
        "stats": {
            "hosts": len(hosts),
            "endpoints": len(endpoints),
            "findings": len(findings),
        },
        "findings": [
            {
                "id": finding.id,
                "tool": _report_safe_text(finding.tool),
                "target": _report_safe_text(finding.target),
                "severity": _report_safe_text(finding.severity),
                "title": _report_safe_text(finding.title),
                "evidence": _report_safe_text(finding.evidence),
                "reproducible_steps": _report_safe_text(finding.reproducible_steps),
                "raw_output_excerpt": _report_safe_text(finding.raw_output)[:500],
                "timestamp": _report_safe_text(finding.timestamp),
                "evidence_request_path": _report_safe_text(_extract_evidence_paths(finding.evidence)[0]),
                "evidence_response_path": _report_safe_text(_extract_evidence_paths(finding.evidence)[1]),
            }
            for finding in findings
        ],
        "hosts": [
            {"domain": _report_safe_text(host.domain), "status_code": host.status_code, "tech_stack": _report_safe_text(host.tech_stack)}
            for host in hosts
        ],
        "screenshots": [
            {"url": _report_safe_text(shot.url), "path": _report_safe_text(shot.path), "title": _report_safe_text(shot.title), "status": shot.status}
            for shot in screenshots
        ],
    }


def render_markdown_report(
    *,
    target: str,
    generated_at: datetime,
    scope: Any,
    findings: list[Finding],
    hosts: list[Host],
    endpoints: list[Endpoint],
    screenshots: list[Screenshot],
    config: Config,
) -> str:
    ai_status = getattr(config, "ai_status_message", "AI triage disabled")
    ai_reason = getattr(config, "ai_disabled_reason", "")
    scope_display = ", ".join(_report_safe_text(item) for item in scope) if isinstance(scope, (list, tuple)) else _report_safe_text(scope)
    md_lines = [
        "# GhillieSuite-EX Bug Bounty Report",
        "",
        f"**Target:** `{_report_safe_text(target)}`  ",
        f"**Generated:** {generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Scope:** {scope_display}  ",
        f"**AI Triage:** {_report_safe_text(ai_status)}" + (f" ({_report_safe_text(ai_reason)})" if ai_reason else "") + "  ",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "|--------|-------|",
        f"| Hosts discovered | {len(hosts)} |",
        f"| Endpoints mapped | {len(endpoints)} |",
        f"| Total findings   | {len(findings)} |",
        "",
        "## Execution Flags",
        "",
        "| Flag | Value |",
        "|------|-------|",
        f"| `force_exploit` | {bool(getattr(config, 'force_exploit', False))} |",
        f"| `generate_bounty_draft` | {bool(getattr(config, 'generate_bounty_draft', False))} |",
        "",
        "## JS Deep Inspection Config",
        "",
        "| Setting | Value |",
        "|---------|-------|",
        f"| `js_max_workers` | {config.js_max_workers} |",
        f"| `js_max_files` | {config.js_max_files} |",
        f"| `js_llm_concurrency` | {config.js_llm_concurrency} |",
        f"| `js_snippet_max_len` | {config.js_snippet_max_len} |",
        f"| `js_http_timeout` | {config.js_http_timeout} |",
        f"| `js_llm_timeout` | {config.js_llm_timeout} |",
        "",
    ]

    stealth_findings = [finding for finding in findings if finding.tool == "stealth_payload"]
    standard_findings = [finding for finding in findings if finding.tool != "stealth_payload"]
    by_severity: dict[str, list[Finding]] = {severity: [] for severity in _SEVERITY_ORDER}
    for finding in standard_findings:
        by_severity.setdefault(finding.severity.lower(), []).append(finding)

    for severity in _SEVERITY_ORDER:
        bucket = by_severity.get(severity, [])
        if not bucket:
            continue
        emoji = {
            "critical": "CRIT",
            "high": "HIGH",
            "medium": "MED",
            "low": "LOW",
            "info": "INFO",
        }.get(severity, "INFO")
        md_lines += [
            f"## {emoji} {severity.capitalize()} Findings ({len(bucket)})",
            "",
        ]
        for index, finding in enumerate(bucket, start=1):
            req_path, res_path = _extract_evidence_paths(finding.evidence)
            md_lines += [
                f"### {index}. {_report_safe_text(finding.title)}",
                "",
                "| Field | Value |",
                "|-------|-------|",
                f"| **Tool** | `{_report_safe_text(finding.tool)}` |",
                f"| **Target** | `{_report_safe_text(finding.target)}` |",
                f"| **Severity** | **{_report_safe_text(finding.severity).upper()}** |",
                f"| **Timestamp** | {_report_safe_text(finding.timestamp)} |",
                "",
                "**Evidence:**",
                "```",
                _report_safe_text(finding.evidence or "N/A"),
                "```",
                f"Evidence Request: `{_report_safe_text(req_path)}`" if req_path else "",
                f"Evidence Response: `{_report_safe_text(res_path)}`" if res_path else "",
                "",
                "**Reproducible Steps:**",
                "",
                _report_safe_text(finding.reproducible_steps or "N/A"),
                "",
                "**Raw Output (excerpt):**",
                "```",
                _report_safe_text(finding.raw_output)[:500] if finding.raw_output else "N/A",
                "```",
                "",
                "---",
                "",
            ]

    if stealth_findings:
        md_lines += [
            f"## AI Stealth Probes & WAF Bypasses ({len(stealth_findings)})",
            "",
            "Targeted low-noise probes executed via Python requests. Includes WAF bypass attempts and response evidence.",
            "",
        ]
        for index, finding in enumerate(stealth_findings, start=1):
            req_path, res_path = _extract_evidence_paths(finding.evidence)
            md_lines += [
                f"### {index}. {_report_safe_text(finding.title)}",
                "",
                "| Field | Value |",
                "|-------|-------|",
                f"| **Tool** | `{_report_safe_text(finding.tool)}` |",
                f"| **Target** | `{_report_safe_text(finding.target)}` |",
                f"| **Severity** | **{_report_safe_text(finding.severity).upper()}** |",
                f"| **Timestamp** | {_report_safe_text(finding.timestamp)} |",
                "",
                "**Evidence:**",
                "```",
                _report_safe_text(finding.evidence or "N/A"),
                "```",
                f"Evidence Request: `{_report_safe_text(req_path)}`" if req_path else "",
                f"Evidence Response: `{_report_safe_text(res_path)}`" if res_path else "",
                "",
                "**Reproducible Steps:**",
                "",
                _report_safe_text(finding.reproducible_steps or "N/A"),
                "",
                "**Raw Output (excerpt):**",
                "```",
                _report_safe_text(finding.raw_output[:500] if finding.raw_output else "N/A"),
                "```",
                "",
                "---",
                "",
            ]

    if hosts:
        md_lines += [
            "## Appendix - Discovered Hosts",
            "",
            "| Domain | Status | Tech Stack |",
            "|--------|--------|------------|",
        ]
        for host in hosts:
            md_lines.append(f"| `{_report_safe_text(host.domain)}` | {host.status_code} | {_report_safe_text(host.tech_stack)} |")
        md_lines.append("")

    if screenshots:
        md_lines += [
            "## Appendix - Screenshots",
            "",
            "| URL | Screenshot Path | Status |",
            "|-----|------------------|--------|",
        ]
        for shot in screenshots:
            md_lines.append(f"| `{_report_safe_text(shot.url)}` | `{_report_safe_text(shot.path)}` | {shot.status} |")
        md_lines.append("")

    return "\n".join(line for line in md_lines if line is not None)


class HtmlReporter:
    """
    Generates a polished, self-contained HTML security report.
    Calls the AI once per unique finding title to generate stakeholder summaries.
    """

    def __init__(
        self,
        db: StateDB,
        ai_client: Any,
        console: Console,
        config: Config | None = None,
    ) -> None:
        self.db = db
        self.ai = ai_client
        self.console = console
        self.cfg = config or global_cfg

    async def generate(
        self,
        target: str,
        scope: list[str],
        output_dir: str | Path = "reports",
        base_name: str | None = None,
    ) -> Path:
        """
        Query the DB, enrich findings with AI summaries, render HTML, write to disk.
        Returns the absolute path to the generated .html file.
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        safe_target = (
            re.sub(r"[^A-Za-z0-9_-]+", "_", base_name).strip("_")[:160]
            if base_name else safe_run_slug(target, datetime.now(timezone.utc))
        ) or "report"
        html_path = output_path / f"{safe_target}.html"

        try:
            findings: list[Finding] = await self.db.get_findings()
        except Exception as exc:
            self.console.print(f"[yellow]  ⚠ Failed to load findings: {exc}[/yellow]")
            findings = []

        try:
            hosts: list[Host] = await self.db.get_hosts()
        except Exception as exc:
            self.console.print(f"[yellow]  ⚠ Failed to load hosts: {exc}[/yellow]")
            hosts = []

        try:
            endpoints: list[Endpoint] = await self.db.get_endpoints()
        except Exception as exc:
            self.console.print(f"[yellow]  ⚠ Failed to load endpoints: {exc}[/yellow]")
            endpoints = []

        try:
            screenshots: list[Screenshot] = await self.db.get_screenshots()
        except Exception as exc:
            self.console.print(f"[yellow]  ⚠ Failed to load screenshots: {exc}[/yellow]")
            screenshots = []

        findings, hosts, endpoints, screenshots = filter_report_records(
            scope, findings, hosts, endpoints, screenshots,
        )

        if getattr(self.cfg, "ai_enabled", False) and self.ai is not None:
            self.console.print(f"[cyan]  Generating AI summaries for {len(findings)} finding(s)…[/cyan]")
        else:
            self.console.print("[yellow]  AI triage disabled — using fallback summaries.[/yellow]")
        enriched = await self._enrich_findings(findings, hosts)

        js_config = {
            "js_max_workers": self.cfg.js_max_workers,
            "js_max_files": self.cfg.js_max_files,
            "js_llm_concurrency": self.cfg.js_llm_concurrency,
            "js_snippet_max_len": self.cfg.js_snippet_max_len,
            "js_http_timeout": self.cfg.js_http_timeout,
            "js_llm_timeout": self.cfg.js_llm_timeout,
        }
        execution_flags = {
            "execution_profile": getattr(self.cfg, "execution_profile", "balanced"),
            "force_exploit": bool(getattr(self.cfg, "force_exploit", False)),
            "generate_bounty_draft": bool(getattr(self.cfg, "generate_bounty_draft", False)),
            "ai_triage_status": _report_safe_text(getattr(self.cfg, "ai_status_message", "AI triage disabled")),
            "ai_triage_reason": _report_safe_text(getattr(self.cfg, "ai_disabled_reason", "")),
        }

        screenshots_render = [
            {
                "url": _report_safe_text(s.url),
                "path": _report_safe_text(s.path),
                "title": _report_safe_text(s.title),
                "status": s.status,
                "data_uri": _image_data_uri(s.path),
            }
            for s in screenshots
        ]

        html_content = _render_html(
            target=target,
            scope=scope,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            findings=enriched,
            hosts=hosts,
            endpoints=endpoints,
            screenshots=screenshots_render,
            js_config=js_config,
            execution_flags=execution_flags,
        )

        html_content = _safe_text(html_content)

        try:
            html_path.write_text(html_content, encoding="utf-8")
        except Exception as exc:
            self.console.print(f"[yellow]  ⚠ HTML write failed: {exc}[/yellow]")
            raise
        self.console.print(f"  HTML: [underline]{html_path.resolve()}[/underline]")
        
        if bool(getattr(self.cfg, "generate_bounty_draft", False)):
            self._generate_bounty_draft(target, safe_target, enriched, output_path)

        return html_path

    def _generate_bounty_draft(
        self,
        target: str,
        safe_target: str,
        enriched: list[dict[str, Any]],
        output_path: Path,
    ) -> None:
        """
        Generates a plain text Responsible Disclosure draft for high/critical findings.
        Consolidates all findings into a single email to prevent noise.
        """
        high_critical = [f for f in enriched if f.get("severity", "").lower() in ("high", "critical")]
        if not high_critical:
            return

        draft_path = output_path / f"{safe_target}_bounty_draft.txt"
        
        # Count Severities
        crit_count = sum(1 for f in high_critical if f.get("severity", "").lower() == "critical")
        high_count = sum(1 for f in high_critical if f.get("severity", "").lower() == "high")

        email_draft = [
            f"Subject: Multiple Security Vulnerabilities Report - {_report_safe_text(target)}\n",
            "Hello Security Team,\n",
            "My name is [Your Name/Handle], an independent security researcher. During a routine security assessment on your infrastructure, I discovered multiple security vulnerabilities that require your attention. I am practicing Responsible Disclosure and keeping this confidential.\n",
            "--- FINDINGS SUMMARY ---",
            f"Total Critical Findings: {crit_count}",
            f"Total High Findings: {high_count}\n",
            "--- DETAILED FINDINGS ---\n"
        ]

        for i, f in enumerate(high_critical, start=1):
            sev = str(f.get("severity", "")).upper().strip()
            title = str(f.get("title", "")).strip()
            
            # Use multiple fallbacks to guarantee the URL is caught
            target_url = str(f.get("target", "") or f.get("url", "") or f.get("matched_at", "") or f.get("host", "")).strip()
            impact = str(f.get("impact", "")).strip()
            remediation = str(f.get("remediation", "")).strip()
            
            # Prioritize human-readable steps, then evidence, lastly raw json
            raw_out = str(f.get("raw_output", "")).strip()
            evid_str = str(f.get("evidence", "")).strip()
            steps_str = str(f.get("reproducible_steps", "")).strip()

            evidence = steps_str or evid_str or raw_out
            
            # Attempt to parse json array if that's all that exists
            if evidence.startswith("[") and evidence.endswith("]"):
                import json
                try:
                    parsed_ev = json.loads(evidence)
                    if isinstance(parsed_ev, list) and len(parsed_ev) > 0 and isinstance(parsed_ev[0], dict):
                        first = parsed_ev[0]
                        evidence = str(first.get("payload", "") or first.get("evidence", "") or first.get("request", "")).strip()
                except Exception:
                    pass

            evidence = evidence.strip()
            # If the json rescue gave us empty brackets or it's still missing
            if not evidence or evidence in ("{}", "[{}]", "[]"):
                evidence = "Evidence unavailable; validate this finding manually before submission."

            if len(evidence) > 300:
                evidence = evidence[:300].strip() + "\n... [TRUNCATED]"

            finding_block = (
                f"[{i}] Severity: {sev} - {title}\n"
                f"- Vulnerable URL: {target_url}\n"
                "- Evidence / Snippet:\n"
                f"{evidence}\n"
                f"- Impact: {impact}\n"
                f"- Remediation: {remediation}\n"
            )
            email_draft.append(finding_block)

        email_draft.append(
            "Please let me know if you require further details, full request/response logs, or assistance in validating these issues.\n\n"
            "Best regards,\n"
            "[Your Handle]"
        )

        try:
            draft_content = redact_text("\n".join(email_draft))
            draft_path.write_text(draft_content.strip(), encoding="utf-8")
            self.console.print(f"  Draft: [underline]{draft_path.resolve()}[/underline]")
        except Exception as e:
            self.console.print(f"[yellow]  ⚠ Failed to write bounty draft: {e}[/yellow]")


    # ── AI enrichment ─────────────────────────────────────────────────────────

    async def _enrich_findings(
        self,
        findings: list[Finding],
        hosts: list[Host],
    ) -> list[dict[str, Any]]:
        """
        For each finding, ask the AI for plain-English explanation, impact, and remediation.
        De-duplicates by title so we don't burn tokens on repeated advisories.
        Falls back gracefully if the AI is unavailable.
        """
        title_cache: dict[str, dict[str, str]] = {}
        enriched: list[dict[str, Any]] = []

        for f in findings:
            safe_title = _report_safe_text(f.title)
            if safe_title not in title_cache:
                summary = await self._ai_summary(f)
                title_cache[safe_title] = summary

            # Match host for status code info
            safe_target_for_domain = _report_safe_text(f.target)
            domain = safe_target_for_domain.split("//")[-1].split("/")[0].split(":")[0]
            matched_host = next((h for h in hosts if h.domain == domain), None)
            host_status = matched_host.status_code if matched_host else ""
            host_tech = matched_host.tech_stack if matched_host else ""

            # Dynamic Severity Promotion
            sev_str = f.severity.lower()
            if "BOLA/IDOR Detected" in f.title:
                sev_str = "critical"

            req_path, res_path = _extract_evidence_paths(f.evidence)
            req_text = _read_text_safe(req_path) if req_path else ""
            res_text = _read_text_safe(res_path) if res_path else ""

            safe_target = _report_safe_text(f.target)
            safe_tool = _report_safe_text(f.tool)
            safe_evidence = _report_safe_text(f.evidence)
            safe_steps = _report_safe_text(f.reproducible_steps)
            safe_raw = _report_safe_text(f.raw_output)
            safe_timestamp = _report_safe_text(f.timestamp)

            enriched.append({
                "id":                 f.id,
                "tool":               safe_tool,
                "target":             safe_target,
                "severity":           sev_str,
                "title":              safe_title,
                "evidence":           safe_evidence,
                "reproducible_steps": safe_steps,
                "raw_output":         safe_raw,
                "timestamp":          safe_timestamp,
                "what_is_it":         _report_safe_text(title_cache[safe_title].get("what_is_it", "")),
                "impact":             _report_safe_text(title_cache[safe_title].get("impact", "")),
                "remediation":        _report_safe_text(title_cache[safe_title].get("remediation", "")),
                "host_status":        host_status,
                "host_tech":          _report_safe_text(host_tech),
                "evidence_request_path": _report_safe_text(req_path),
                "evidence_response_path": _report_safe_text(res_path),
                "evidence_request": req_text,
                "evidence_response": res_text,
            })

        return enriched

    async def _ai_summary(self, f: Finding) -> dict[str, str]:
        """
        Ask the AI to explain a finding in plain English.
        Returns dict with keys: what_is_it, impact, remediation.
        """
        _SYSTEM = (
            "You are a professional web security report writer. "
            "Your audience is non-technical stakeholders (product managers, executives). "
            "Be concise — 1-3 sentences max per field. No jargon, no CVE numbers. "
            "Under 'impact', if the vulnerability is BOLA/IDOR, explicitly explain which specific ID (e.g., user_id=123) should be tested for manipulation based on the evidence."
        )
        title = _report_safe_text(f.title)
        tool = _report_safe_text(f.tool)
        severity = _report_safe_text(f.severity)
        evidence = _report_safe_text(f.evidence)

        prompt = f"""
Finding title: {title}
Tool: {tool}
Severity: {severity}
Evidence: {evidence[:400] if evidence else 'N/A'}

Reply with a JSON object containing exactly these three keys:
{{
  "what_is_it": "...",
  "impact": "...",
  "remediation": "..."
}}
"""
        if not getattr(self.cfg, "ai_enabled", False) or self.ai is None:
            return {
                "what_is_it": f"A {severity}-severity vulnerability detected by {tool}.",
                "impact": "AI triage disabled. Review the technical evidence for impact assessment.",
                "remediation": "Review the evidence and reproducible steps below and apply appropriate fixes.",
            }
        try:
            if hasattr(self.ai, "generate_content"):
                # Gemini
                from ghilliesuite_ex.agents.base import _run_in_thread
                resp = await _run_in_thread(self.ai.generate_content, f"{_SYSTEM}\n\n{prompt}")
                raw = resp.text or ""
            elif hasattr(self.ai, "chat"):
                # OpenAI
                resp = await self.ai.chat.completions.create(
                    model=self.cfg.openai_model,
                    messages=[
                        {"role": "system", "content": _SYSTEM},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.3,
                    max_tokens=300,
                )
                raw = resp.choices[0].message.content or ""
            else:
                raw = ""

            # Parse JSON from response (may have surrounding text)
            start = raw.find("{")
            end   = raw.rfind("}") + 1
            if start >= 0 and end > start:
                parsed = json.loads(raw[start:end])
                if isinstance(parsed, dict):
                    return {key: _report_safe_text(parsed.get(key, ""))
                            for key in ("what_is_it", "impact", "remediation")}
        except Exception as exc:
            if getattr(self.cfg, "ai_enabled", False):
                self.cfg.disable_ai(f"{type(exc).__name__}: {exc}")
            pass

        # Graceful fallback
        return {
            "what_is_it": f"A {severity}-severity vulnerability detected by {tool}.",
            "impact":      "AI triage disabled. Review the technical evidence to confirm business impact.",
            "remediation": "Review the evidence and reproducible steps below and apply appropriate fixes.",
        }


# ── HTML Rendering ─────────────────────────────────────────────────────────────

def _e(s: Any) -> str:
    """HTML-escape a value for safe inclusion in the template."""
    return _html.escape(_report_safe_text(s), quote=True)



def _render_html(
    target: str,
    scope: list[str],
    generated_at: str,
    findings: list[dict[str, Any]],
    hosts: list[Host],
    endpoints: list[Endpoint],
    screenshots: list[dict[str, Any]] | None = None,
    js_config: dict[str, Any] | None = None,
    execution_flags: dict[str, Any] | None = None,
) -> str:
    """Render a standalone HTML report with inline CSS/JS only."""
    active_hosts = [h for h in hosts if 200 <= getattr(h, "status_code", 0) < 400]
    active_domains = {h.domain for h in active_hosts}
    screenshots = screenshots or []

    active_endpoints = []
    for ep in endpoints:
        domain = ep.url.split("//")[-1].split("/")[0].split(":")[0]
        if domain in active_domains:
            active_endpoints.append(ep)

    endpoints = active_endpoints
    hosts = active_hosts

    total = len(findings)
    counts_all = {s: sum(1 for f in findings if f["severity"] == s) for s in _SEVERITY_ORDER}

    stealth_findings = [f for f in findings if f.get("tool") == "stealth_payload"]
    non_stealth = [f for f in findings if f.get("tool") != "stealth_payload"]
    hot_findings = [f for f in non_stealth if f["severity"] in _HOT_SEVERITIES and f["tool"] not in _ADVISORY_TOOLS]
    advisories = [f for f in non_stealth if f["tool"] in _ADVISORY_TOOLS]
    cold_findings = [f for f in non_stealth if f["severity"] not in _HOT_SEVERITIES and f["tool"] not in _ADVISORY_TOOLS]
    counts_hot = {s: sum(1 for f in hot_findings if f["severity"] == s) for s in _SEVERITY_ORDER}

    js_config = js_config or {}
    execution_flags = execution_flags or {}
    scope_display = ", ".join(_report_safe_text(item) for item in scope)

    screenshot_section = (
        f"""
      <section class="panel">
        <div class="section-heading">
          <h2>Visual Evidence ({len(screenshots)})</h2>
          <p>Embedded inline when the file size allows a standalone report.</p>
        </div>
        <div class="screenshots-grid">
          {"".join(_screenshot_card(s) for s in screenshots[:24])}
        </div>
        {"" if len(screenshots) <= 24 else f'<p class="section-note">Showing 24 of {len(screenshots)} screenshots.</p>'}
      </section>"""
        if screenshots
        else ""
    )
    hosts_section = (
        f"""
      <section class="panel">
        <div class="section-heading">
          <h2>Discovered Hosts ({len(hosts)})</h2>
          <p>Only active hosts are listed here to keep the appendix focused.</p>
        </div>
        <div class="table-shell">
          <table>
            <thead>
              <tr>
                <th>Domain</th>
                <th>Status</th>
                <th>Tech Stack</th>
              </tr>
            </thead>
            <tbody>
              {"".join(_host_row(h) for h in hosts)}
            </tbody>
          </table>
        </div>
      </section>"""
        if hosts
        else ""
    )
    endpoints_section = (
        f"""
      <section class="panel">
        <div class="section-heading">
          <h2>High-Value Endpoints ({len(endpoints)})</h2>
          <p>Prioritized recon paths that remained associated with active hosts.</p>
        </div>
        <div class="endpoint-shell">
          <ul class="endpoint-list">
            {"".join(f'<li>{_e(_report_safe_text(ep.url))}</li>' for ep in endpoints[:100])}
            {"" if len(endpoints) <= 100 else f'<li class="muted">... and {len(endpoints) - 100} more</li>'}
          </ul>
        </div>
      </section>"""
        if endpoints
        else ""
    )
    advisories_section = (
        f"""
      <section class="panel">
        <div class="section-heading">
          <h2>Automated Advisories ({len(advisories)})</h2>
          <p>Passive checks only. Confirm these manually before acting on them.</p>
        </div>
        <div class="stack">
          {"".join(_finding_card(f) for f in advisories)}
        </div>
      </section>"""
        if advisories
        else ""
    )
    stealth_section = (
        f"""
      <section class="panel">
        <div class="section-heading">
          <h2>AI Stealth Probes ({len(stealth_findings)})</h2>
          <p>Low-noise validation traffic with captured response evidence.</p>
        </div>
        <div class="stack">
          {"".join(_finding_card(f) for f in stealth_findings)}
        </div>
      </section>"""
        if stealth_findings
        else ""
    )
    cold_section = (
        f"""
      <section class="panel">
        <details class="disclosure">
          <summary>Low / Info Findings ({len(cold_findings)})</summary>
          <div class="stack">
            {"".join(_finding_card(f) for f in cold_findings)}
          </div>
        </details>
      </section>"""
        if cold_findings
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>GhillieSuite-EX Report - {_e(target)}</title>
  <style>
    :root {{
      --bg: #081017;
      --bg-soft: #101a24;
      --panel: rgba(9, 18, 28, 0.88);
      --panel-strong: #0f1b28;
      --line: rgba(173, 194, 217, 0.16);
      --line-strong: rgba(173, 194, 217, 0.26);
      --text: #e8f0f7;
      --muted: #98adbf;
      --accent: #3dd6b5;
      --accent-soft: rgba(61, 214, 181, 0.18);
      --critical: #ff5f6d;
      --high: #ff9950;
      --medium: #ffd166;
      --low: #69b7ff;
      --info: #97a6b5;
      --shadow: 0 20px 55px rgba(0, 0, 0, 0.28);
      --radius-lg: 24px;
      --radius-md: 16px;
      --radius-sm: 12px;
      --font: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
      --font-mono: "Cascadia Code", "Consolas", "Courier New", monospace;
    }}
    * {{
      box-sizing: border-box;
    }}
    html {{
      background:
        radial-gradient(circle at top right, rgba(61, 214, 181, 0.18), transparent 34%),
        radial-gradient(circle at bottom left, rgba(105, 183, 255, 0.16), transparent 30%),
        var(--bg);
    }}
    body {{
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      font-family: var(--font);
      line-height: 1.55;
      background: transparent;
    }}
    a {{
      color: inherit;
    }}
    pre {{
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      font-family: var(--font-mono);
    }}
    code {{
      font-family: var(--font-mono);
    }}
    .shell {{
      max-width: 1220px;
      margin: 0 auto;
      padding: 28px 20px 60px;
    }}
    .hero {{
      position: relative;
      overflow: hidden;
      padding: 28px;
      border: 1px solid var(--line);
      border-radius: 32px;
      background:
        linear-gradient(135deg, rgba(61, 214, 181, 0.08), rgba(61, 214, 181, 0.01)),
        linear-gradient(180deg, rgba(255, 255, 255, 0.03), rgba(255, 255, 255, 0.01)),
        var(--panel);
      box-shadow: var(--shadow);
    }}
    .hero::after {{
      content: "";
      position: absolute;
      inset: -120px -60px auto auto;
      width: 260px;
      height: 260px;
      background: radial-gradient(circle, rgba(105, 183, 255, 0.12), transparent 70%);
      pointer-events: none;
    }}
    .hero-top {{
      display: flex;
      justify-content: space-between;
      gap: 20px;
      align-items: flex-start;
      flex-wrap: wrap;
    }}
    .eyebrow {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 10px;
      border-radius: 999px;
      background: var(--accent-soft);
      color: #bff9ea;
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      font-weight: 700;
    }}
    h1 {{
      margin: 14px 0 6px;
      font-size: clamp(28px, 4vw, 42px);
      line-height: 1.05;
      letter-spacing: -0.03em;
    }}
    .hero-subtitle,
    .hero-meta,
    .section-heading p,
    .section-note,
    .muted {{
      color: var(--muted);
    }}
    .hero-meta {{
      display: grid;
      gap: 8px;
      min-width: 260px;
      font-size: 13px;
    }}
    .hero-meta strong,
    .target-chip strong {{
      color: var(--text);
    }}
    .hero-scope {{
      margin-top: 22px;
      display: inline-flex;
      gap: 10px;
      align-items: center;
      padding: 12px 14px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.02);
      font-size: 13px;
      color: var(--muted);
      flex-wrap: wrap;
    }}
    .target-chip {{
      margin-top: 12px;
      display: inline-flex;
      padding: 10px 14px;
      border-radius: 999px;
      border: 1px solid rgba(61, 214, 181, 0.24);
      color: #d7fff5;
      background: rgba(61, 214, 181, 0.08);
      font-family: var(--font-mono);
      font-size: 13px;
    }}
    .main-stack {{
      display: grid;
      gap: 20px;
      margin-top: 24px;
    }}
    .panel {{
      border: 1px solid var(--line);
      border-radius: var(--radius-lg);
      background: var(--panel);
      padding: 22px;
      box-shadow: var(--shadow);
    }}
    .stats-grid,
    .meta-grid,
    .screenshots-grid {{
      display: grid;
      gap: 14px;
    }}
    .stats-grid {{
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    }}
    .meta-grid {{
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    }}
    .screenshots-grid {{
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    }}
    .stat-card,
    .meta-card,
    .shot-card {{
      border-radius: var(--radius-md);
      border: 1px solid var(--line);
      background: var(--panel-strong);
    }}
    .stat-card {{
      padding: 16px;
      min-height: 116px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }}
    .stat-label {{
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
    }}
    .stat-value {{
      margin-top: 10px;
      font-size: 36px;
      font-weight: 800;
      line-height: 1;
      letter-spacing: -0.04em;
    }}
    .tone-critical .stat-value {{ color: var(--critical); }}
    .tone-high .stat-value {{ color: var(--high); }}
    .tone-medium .stat-value {{ color: var(--medium); }}
    .tone-low .stat-value {{ color: var(--low); }}
    .tone-neutral .stat-value {{ color: var(--accent); }}
    .meta-card {{
      padding: 14px;
    }}
    .meta-card .label {{
      display: block;
      margin-bottom: 6px;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
    }}
    .meta-card .value {{
      font-family: var(--font-mono);
      color: #d8fbf2;
      font-size: 13px;
      word-break: break-word;
    }}
    .section-heading {{
      display: flex;
      align-items: end;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 16px;
      flex-wrap: wrap;
    }}
    .section-heading h2 {{
      margin: 0;
      font-size: 18px;
      letter-spacing: -0.02em;
    }}
    .section-heading p {{
      margin: 0;
      font-size: 13px;
      max-width: 640px;
    }}
    .filter-bar {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 16px;
    }}
    .filter-btn {{
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.02);
      color: var(--text);
      border-radius: 999px;
      padding: 10px 14px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.04em;
      cursor: pointer;
      transition: transform 0.15s ease, border-color 0.15s ease, background 0.15s ease;
    }}
    .filter-btn:hover {{
      transform: translateY(-1px);
      border-color: var(--line-strong);
    }}
    .filter-btn.active {{
      background: var(--accent-soft);
      border-color: rgba(61, 214, 181, 0.38);
      color: #d7fff5;
    }}
    .stack {{
      display: grid;
      gap: 16px;
    }}
    .finding-card {{
      border: 1px solid var(--line);
      border-left: 5px solid var(--info);
      border-radius: var(--radius-md);
      background: linear-gradient(180deg, rgba(255, 255, 255, 0.025), rgba(255, 255, 255, 0.015)), var(--panel-strong);
      overflow: hidden;
      transition: transform 0.16s ease, border-color 0.16s ease;
    }}
    .finding-card:hover {{
      transform: translateY(-2px);
      border-color: var(--line-strong);
    }}
    .finding-card.hidden {{
      display: none;
    }}
    .finding-card.sev-critical {{ border-left-color: var(--critical); }}
    .finding-card.sev-high {{ border-left-color: var(--high); }}
    .finding-card.sev-medium {{ border-left-color: var(--medium); }}
    .finding-card.sev-low {{ border-left-color: var(--low); }}
    .finding-card.sev-info {{ border-left-color: var(--info); }}
    .finding-body {{
      padding: 18px;
    }}
    .finding-top {{
      display: flex;
      justify-content: space-between;
      gap: 14px;
      align-items: flex-start;
      margin-bottom: 14px;
      flex-wrap: wrap;
    }}
    .finding-top h3 {{
      margin: 10px 0 0;
      font-size: 19px;
      letter-spacing: -0.02em;
    }}
    .chip-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }}
    .chip {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      border: 1px solid transparent;
    }}
    .chip.sev-critical {{ background: rgba(255, 95, 109, 0.18); color: #ffd5da; border-color: rgba(255, 95, 109, 0.32); }}
    .chip.sev-high {{ background: rgba(255, 153, 80, 0.18); color: #ffe4cf; border-color: rgba(255, 153, 80, 0.32); }}
    .chip.sev-medium {{ background: rgba(255, 209, 102, 0.18); color: #fff0c7; border-color: rgba(255, 209, 102, 0.32); }}
    .chip.sev-low {{ background: rgba(105, 183, 255, 0.18); color: #d9eeff; border-color: rgba(105, 183, 255, 0.32); }}
    .chip.sev-info {{ background: rgba(151, 166, 181, 0.18); color: #d7e0e9; border-color: rgba(151, 166, 181, 0.32); }}
    .chip.tool {{
      background: rgba(255, 255, 255, 0.04);
      color: #c8d7e5;
      border-color: var(--line);
      font-family: var(--font-mono);
      text-transform: none;
      letter-spacing: 0;
      font-weight: 600;
    }}
    .chip.passive {{
      background: rgba(155, 113, 255, 0.18);
      border-color: rgba(155, 113, 255, 0.34);
      color: #eadbff;
    }}
    .chip.verified {{
      background: rgba(255, 95, 109, 0.22);
      border-color: rgba(255, 95, 109, 0.36);
      color: #ffe0e4;
    }}
    .timestamp {{
      color: var(--muted);
      font-family: var(--font-mono);
      font-size: 12px;
    }}
    .summary-grid,
    .evidence-grid {{
      display: grid;
      gap: 12px;
    }}
    .summary-grid {{
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      margin-bottom: 14px;
    }}
    .evidence-grid {{
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      padding-top: 14px;
      border-top: 1px solid var(--line);
    }}
    .summary-card,
    .evidence-card {{
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
      background: rgba(255, 255, 255, 0.02);
      padding: 14px;
    }}
    .summary-card h4,
    .evidence-card h4 {{
      margin: 0 0 10px;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
    }}
    .summary-card p {{
      margin: 0;
      font-size: 14px;
      color: var(--text);
    }}
    .evidence-meta {{
      display: grid;
      gap: 6px;
      margin-bottom: 10px;
      font-size: 12px;
      color: var(--muted);
      font-family: var(--font-mono);
      word-break: break-word;
    }}
    .evidence-block {{
      border-radius: 12px;
      background: rgba(4, 11, 18, 0.86);
      border: 1px solid rgba(61, 214, 181, 0.14);
      padding: 12px;
      color: #a7f5e4;
      font-size: 12px;
      max-height: 260px;
      overflow: auto;
    }}
    .steps-block {{
      border-radius: 12px;
      background: rgba(6, 12, 21, 0.92);
      border: 1px solid rgba(105, 183, 255, 0.16);
      padding: 12px;
      color: #d8ebff;
      font-size: 12px;
      max-height: 320px;
      overflow: auto;
    }}
    details {{
      border: 1px solid var(--line);
      border-radius: 14px;
      background: rgba(255, 255, 255, 0.015);
    }}
    details summary {{
      list-style: none;
      cursor: pointer;
      user-select: none;
    }}
    details summary::-webkit-details-marker {{
      display: none;
    }}
    .disclosure {{
      padding: 14px;
    }}
    .disclosure summary {{
      font-size: 13px;
      color: var(--text);
      font-weight: 700;
      margin-bottom: 12px;
    }}
    .evidence-disclosure {{
      margin-top: 12px;
      padding: 12px;
    }}
    .evidence-disclosure summary {{
      font-size: 12px;
      color: var(--muted);
      font-weight: 700;
    }}
    .evidence-disclosure .disclosure-grid {{
      display: grid;
      gap: 10px;
      margin-top: 10px;
    }}
    .evidence-file {{
      font-size: 11px;
      color: var(--muted);
      word-break: break-word;
      font-family: var(--font-mono);
    }}
    .table-shell,
    .endpoint-shell {{
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: var(--radius-md);
      background: rgba(255, 255, 255, 0.02);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
    }}
    th,
    td {{
      padding: 14px 16px;
      text-align: left;
      border-bottom: 1px solid var(--line);
    }}
    th {{
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
      background: rgba(255, 255, 255, 0.02);
    }}
    td {{
      font-size: 13px;
      color: var(--text);
    }}
    tr:last-child td {{
      border-bottom: none;
    }}
    .mono {{
      font-family: var(--font-mono);
      word-break: break-word;
    }}
    .status-good {{ color: #8af0d5; }}
    .status-warn {{ color: #ffd68c; }}
    .status-bad {{ color: #ffb0b7; }}
    .shot-card {{
      padding: 14px;
      display: grid;
      gap: 10px;
    }}
    .shot-card img {{
      width: 100%;
      height: auto;
      display: block;
      border-radius: 12px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.03);
    }}
    .shot-title {{
      font-size: 13px;
      color: var(--text);
      font-weight: 700;
    }}
    .shot-meta,
    .shot-path {{
      font-size: 11px;
      color: var(--muted);
      word-break: break-word;
      font-family: var(--font-mono);
    }}
    .endpoint-list {{
      list-style: none;
      margin: 0;
      padding: 14px;
      display: grid;
      gap: 8px;
      font-size: 12px;
      color: #d8fbf2;
      font-family: var(--font-mono);
    }}
    .endpoint-list li {{
      padding: 8px 10px;
      border-radius: 10px;
      border: 1px solid rgba(61, 214, 181, 0.12);
      background: rgba(61, 214, 181, 0.04);
      word-break: break-word;
    }}
    .footer {{
      margin-top: 18px;
      text-align: center;
      color: var(--muted);
      font-size: 12px;
    }}
    @media (max-width: 720px) {{
      .shell {{
        padding: 18px 14px 48px;
      }}
      .hero,
      .panel {{
        padding: 18px;
        border-radius: 22px;
      }}
      .hero-scope,
      .target-chip {{
        border-radius: 16px;
      }}
      .finding-body {{
        padding: 14px;
      }}
      th,
      td {{
        padding: 12px;
      }}
    }}
  </style>
</head>
<body>
  <div class="shell">
    <header class="hero">
      <div class="hero-top">
        <div>
          <div class="eyebrow">Authorized Security Report</div>
          <h1>GhillieSuite-EX</h1>
          <p class="hero-subtitle">Standalone assessment output for authorized pentest and bug bounty workflows.</p>
          <div class="target-chip"><strong>Target:</strong>&nbsp;{_e(target)}</div>
        </div>
        <div class="hero-meta">
          <div><strong>Generated:</strong> {_e(generated_at)}</div>
          <div><strong>Execution profile:</strong> {_e(str(execution_flags.get("execution_profile", "balanced")))}</div>
          <div><strong>AI triage:</strong> {_e(str(execution_flags.get("ai_triage_status", "AI triage disabled")))}</div>
          <div><strong>AI detail:</strong> {_e(str(execution_flags.get("ai_triage_reason", "") or "None"))}</div>
        </div>
      </div>
      <div class="hero-scope"><strong>Scope:</strong> {_e(scope_display or "Not provided")}</div>
    </header>

    <main class="main-stack">
      <section class="panel">
        <div class="section-heading">
          <h2>Executive Summary</h2>
          <p>Counts reflect findings after report-time redaction and host/activity filtering.</p>
        </div>
        <div class="stats-grid">
          {_stat_card("Total Findings", str(total), "neutral")}
          {_stat_card("Critical", str(counts_all["critical"]), "critical")}
          {_stat_card("High", str(counts_all["high"]), "high")}
          {_stat_card("Medium", str(counts_all["medium"]), "medium")}
          {_stat_card("Hosts Found", str(len(hosts)), "neutral")}
          {_stat_card("Endpoints", str(len(endpoints)), "low")}
        </div>
      </section>

      <section class="panel">
        <div class="section-heading">
          <h2>Execution Flags</h2>
          <p>Operator-selected controls and AI availability captured with the report.</p>
        </div>
        <div class="meta-grid">
          {_meta_card("Execution Profile", str(execution_flags.get("execution_profile", "balanced")))}
          {_meta_card("Force Exploit", str(execution_flags.get("force_exploit", False)))}
          {_meta_card("Generate Bounty Draft", str(execution_flags.get("generate_bounty_draft", False)))}
          {_meta_card("AI Triage Status", str(execution_flags.get("ai_triage_status", "AI triage disabled")))}
        </div>
      </section>

      <section class="panel">
        <div class="section-heading">
          <h2>JS Deep Inspection Config</h2>
          <p>Snapshot of the runtime inspection settings that shaped JavaScript review depth.</p>
        </div>
        <div class="meta-grid">
          {_meta_card("Workers", js_config.get("js_max_workers", ""))}
          {_meta_card("Max Files", js_config.get("js_max_files", ""))}
          {_meta_card("LLM Concurrency", js_config.get("js_llm_concurrency", ""))}
          {_meta_card("Snippet Max Len", js_config.get("js_snippet_max_len", ""))}
          {_meta_card("HTTP Timeout (s)", js_config.get("js_http_timeout", ""))}
          {_meta_card("LLM Timeout (s)", js_config.get("js_llm_timeout", ""))}
        </div>
      </section>

      <section class="panel" id="hot-findings">
        <div class="section-heading">
          <h2>Active Vulnerability Findings ({len(hot_findings)})</h2>
          <p>Critical, high, and medium findings prioritized for immediate review.</p>
        </div>
        <div class="filter-bar" id="filter-bar">
          <button class="filter-btn active" data-filter="all" onclick="filterFindings('all', this)">All ({len(hot_findings)})</button>
          <button class="filter-btn" data-filter="critical" onclick="filterFindings('critical', this)">Critical ({counts_hot["critical"]})</button>
          <button class="filter-btn" data-filter="high" onclick="filterFindings('high', this)">High ({counts_hot["high"]})</button>
          <button class="filter-btn" data-filter="medium" onclick="filterFindings('medium', this)">Medium ({counts_hot["medium"]})</button>
        </div>
        <div id="findings-container" class="stack">
          {"".join(_finding_card(f) for f in hot_findings) if hot_findings else _empty_state("No critical, high, or medium findings were produced in this run.")}
        </div>
      </section>

      {advisories_section}
      {stealth_section}
      {cold_section}
      {screenshot_section}
      {hosts_section}
      {endpoints_section}
    </main>

    <footer class="footer">
      GhillieSuite-EX - For authorized security testing only. Operator remains responsible for program compliance.
    </footer>
  </div>

  <script>
    function filterFindings(severity, btn) {{
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('#findings-container .finding-card').forEach(card => {{
        if (severity === 'all' || card.dataset.severity === severity) {{
          card.classList.remove('hidden');
        }} else {{
          card.classList.add('hidden');
        }}
      }});
    }}
  </script>
</body>
</html>"""


def _stat_card(label: str, value: str, tone: str) -> str:
    return f"""
    <div class="stat-card tone-{_e(tone)}">
      <div class="stat-label">{_e(label)}</div>
      <div class="stat-value">{_e(value)}</div>
    </div>"""


def _meta_card(label: str, value: Any) -> str:
    return f"""
    <div class="meta-card">
      <span class="label">{_e(label)}</span>
      <div class="value">{_e(value)}</div>
    </div>"""


def _finding_card(f: dict[str, Any]) -> str:
    sev = _safe_text(f.get("severity", "info")).lower()
    if sev not in _SEVERITY_ORDER:
        sev = "info"

    what_is_it = _e(f.get("what_is_it", ""))
    impact = _e(f.get("impact", ""))
    remediation = _e(f.get("remediation", ""))
    evidence = _e(f.get("evidence", "") or "N/A")
    steps = _e(f.get("reproducible_steps", "") or "No steps provided.")
    raw_out = _safe_text(f.get("raw_output", "") or "")
    raw_display = _e(raw_out[:800]) if raw_out.strip() else ""
    req_path = _e(f.get("evidence_request_path", "") or "")
    res_path = _e(f.get("evidence_response_path", "") or "")
    req_text = _e(f.get("evidence_request", "") or "")
    res_text = _e(f.get("evidence_response", "") or "")
    tool_name = _safe_text(f.get("tool", ""))
    target_url = _e(f.get("target", ""))
    h_status = f.get("host_status", "")
    h_tech = f.get("host_tech", "")
    is_advisory = tool_name in _ADVISORY_TOOLS

    advisory_badge = '<span class="chip passive">Passive Advisory</span>' if is_advisory else ""
    verified_badge = (
        '<span class="chip verified">Verified</span>'
        if tool_name in ("dalfox", "sqlmap")
        or "BOLA/IDOR Detected" in _safe_text(f.get("title", ""))
        or "GraphQL Introspection" in _safe_text(f.get("title", ""))
        else ""
    )
    status_str = _e(f"HTTP {h_status}") if h_status else _e("Status Unknown")
    tech_str = _e(f" - Tech: {h_tech}") if h_tech else ""

    proof_block = (
        f"""
            <div>
              <h4>Raw Tool Output</h4>
              <pre class="evidence-block">{raw_display}</pre>
            </div>"""
        if raw_display
        else ""
    )

    evidence_files_block = ""
    if req_text or res_text or req_path or res_path:
        evidence_files_block = f"""
            <details class="evidence-disclosure">
              <summary>Captured HTTP Evidence</summary>
              <div class="disclosure-grid">
                {f'<div class="evidence-file">Request File: {req_path}</div>' if req_path else ''}
                {f'<pre class="evidence-block">{req_text}</pre>' if req_text else ''}
                {f'<div class="evidence-file">Response File: {res_path}</div>' if res_path else ''}
                {f'<pre class="evidence-block">{res_text}</pre>' if res_text else ''}
              </div>
            </details>"""

    return f"""
    <article class="finding-card sev-{_e(sev)}" data-severity="{_e(sev)}">
      <div class="finding-body">
        <div class="finding-top">
          <div class="flex-1">
            <div class="chip-row">
              <span class="chip sev-{_e(sev)}">{_e(sev)}</span>
              {advisory_badge}
              {verified_badge}
              <span class="chip tool">{_e(tool_name)}</span>
            </div>
            <h3>{_e(f.get("title", ""))}</h3>
          </div>
          <div class="timestamp">{_e(str(f.get("timestamp", ""))[:19])}</div>
        </div>

        <div class="summary-grid">
          <div class="summary-card">
            <h4>What Is It?</h4>
            <p>{what_is_it}</p>
          </div>
          <div class="summary-card">
            <h4>Impact</h4>
            <p>{impact}</p>
          </div>
          <div class="summary-card">
            <h4>Remediation</h4>
            <p>{remediation}</p>
          </div>
        </div>

        <div class="evidence-grid">
          <div class="evidence-card">
            <h4>Technical Evidence</h4>
            <div class="evidence-meta">
              <div>URL: {target_url}</div>
              <div>Response: {status_str}{tech_str}</div>
            </div>
            <pre class="evidence-block">{evidence}</pre>
            {proof_block}
            {evidence_files_block}
          </div>
          <div class="evidence-card">
            <h4>Steps to Reproduce</h4>
            <pre class="steps-block">{steps}</pre>
          </div>
        </div>
      </div>
    </article>"""


def _screenshot_card(s: dict[str, Any]) -> str:
    url = _e(s.get("url", ""))
    title = _e(s.get("title", "")) or "Screenshot"
    status = _e(s.get("status", "")) if s.get("status") else ""
    path = _e(s.get("path", ""))
    data_uri = s.get("data_uri") or ""
    img_block = (
        f'<img src="{data_uri}" alt="{title}" />'
        if data_uri
        else '<div class="muted">Screenshot file not embedded.</div>'
    )
    return f"""
    <div class="shot-card">
      <div class="shot-meta">{url}</div>
      <div>
        <div class="shot-title">{title}</div>
        <div class="shot-meta">{f'HTTP {status}' if status else 'Status unknown'}</div>
      </div>
      {img_block}
      <div class="shot-path">{path}</div>
    </div>"""


def _host_row(h: Host) -> str:
    status_code = h.status_code or 0
    status_class = (
        "status-good" if 200 <= status_code < 300 else
        "status-warn" if 300 <= status_code < 400 else
        "status-bad" if status_code >= 400 else
        ""
    )
    return f"""
    <tr>
      <td class="mono">{_e(h.domain)}</td>
      <td class="{status_class}">{_e(h.status_code or "-")}</td>
      <td>{_e(h.tech_stack or "-")}</td>
    </tr>"""


def _empty_state(msg: str) -> str:
    return f'<div class="muted">{_e(msg)}</div>'


