import io
import json
import shutil
import unittest
import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import httpx
from rich.console import Console

from ghilliesuite_ex.agents.base import AgentResult, AgentTask, BaseAgent
from ghilliesuite_ex.agents.exploit import ExploitAgent
from ghilliesuite_ex.agents.reporter import ReporterAgent
from ghilliesuite_ex.config import Config
from ghilliesuite_ex.state.db import StateDB
from ghilliesuite_ex.state.models import Endpoint, Finding, Host
from ghilliesuite_ex.utils.redaction import redact_text
from ghilliesuite_ex.utils.scope import load_scope


class _DummyAgent(BaseAgent):
    async def run(self, task: AgentTask) -> AgentResult:
        return AgentResult(agent=self.name, status="ok", summary="noop")


class _FailingAI:
    def generate_content(self, prompt: str):
        raise TimeoutError("simulated timeout")


class _AuthAwareExploitAgent(ExploitAgent):
    async def _ai_triage(self, finding, status_code, content_type, response_body):
        return {
            "is_vulnerable": True,
            "is_lead": False,
            "confidence": 95,
            "technical_reasoning": "Replay validation preserved the original authenticated context.",
        }

    async def _generate_poc(self, finding, triage_reason):
        return ""


class _RecordingAsyncClient:
    last_init_kwargs = None
    last_request_method = None
    last_request_url = None
    last_request_kwargs = None

    def __init__(self, **kwargs):
        type(self).last_init_kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def request(self, method, url, **kwargs):
        type(self).last_request_method = method
        type(self).last_request_url = url
        type(self).last_request_kwargs = kwargs
        return SimpleNamespace(
            url=url,
            status_code=200,
            headers={"Content-Type": "text/html; charset=utf-8"},
            text="<html>ok</html>",
            elapsed=SimpleNamespace(total_seconds=lambda: 0.12),
        )

    async def get(self, url, **kwargs):
        return await self.request("GET", url, **kwargs)


class _WafBlockingAsyncClient(_RecordingAsyncClient):
    async def request(self, method, url, **kwargs):
        type(self).last_request_method = method
        type(self).last_request_url = url
        type(self).last_request_kwargs = kwargs
        return SimpleNamespace(
            url=url,
            status_code=429,
            headers={"Content-Type": "text/html; charset=utf-8", "Server": "cloudflare"},
            text="<html><title>Attention Required</title> Just a moment...</html>",
            elapsed=SimpleNamespace(total_seconds=lambda: 0.08),
        )


class _AuthFailureAsyncClient(_RecordingAsyncClient):
    async def request(self, method, url, **kwargs):
        type(self).last_request_method = method
        type(self).last_request_url = url
        type(self).last_request_kwargs = kwargs
        return SimpleNamespace(
            url=url,
            status_code=401,
            headers={"Content-Type": "text/html; charset=utf-8"},
            text="<html>login required</html>",
            elapsed=SimpleNamespace(total_seconds=lambda: 0.05),
        )


class _TimeoutAsyncClient(_RecordingAsyncClient):
    async def request(self, method, url, **kwargs):
        type(self).last_request_method = method
        type(self).last_request_url = url
        type(self).last_request_kwargs = kwargs
        raise httpx.TimeoutException("validation timed out")


class _ForbiddenAsyncClient:
    def __init__(self, **kwargs):
        raise AssertionError("HTTP replay should not be used for this tool policy")


class TestRedaction(unittest.TestCase):
    def test_redact_sensitive_headers_and_tokens(self) -> None:
        raw = (
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret.signature\n"
            "Cookie: sessionid=supersecret; csrftoken=anothersecret\n"
            "X-API-Key: topsecretapikey1234567890\n"
            "GET /api?api_key=querysecret123456&token=othertoken999 HTTP/1.1\n"
            "openai_key=sk-abcdefghijklmnopQRSTUV1234567890\n"
            "github=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n"
        )
        redacted = redact_text(raw)

        self.assertIn("Authorization: [REDACTED]", redacted)
        self.assertIn("Cookie: [REDACTED]", redacted)
        self.assertIn("X-API-Key: [REDACTED]", redacted)
        self.assertIn("[REDACTED_SECRET]", redacted)

        self.assertNotIn("sessionid=supersecret", redacted)
        self.assertNotIn("querysecret123456", redacted)
        self.assertNotIn("sk-abcdefghijklmnopQRSTUV1234567890", redacted)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz1234567890", redacted)


class TestAIFallback(unittest.IsolatedAsyncioTestCase):
    async def test_base_agent_disables_ai_after_timeout(self) -> None:
        config = Config()
        config.enable_ai()
        config.ai_retries = 1
        console = Console(file=io.StringIO(), force_terminal=False, color_system=None)

        async with StateDB(":memory:", target="example.com") as db:
            agent = _DummyAgent(
                db=db,
                ai_client=_FailingAI(),
                scope=["example.com"],
                console=console,
                config=config,
            )
            result = await agent._ask_ai("hello")

        self.assertEqual(result, "")
        self.assertFalse(config.ai_enabled)
        self.assertIn("simulated timeout", config.ai_disabled_reason.lower())


class TestExploitValidationAuthAware(unittest.IsolatedAsyncioTestCase):
    async def test_validate_and_insert_finding_reuses_auth_headers_cookie_and_proxy(self) -> None:
        config = Config()
        config.disable_ai("No API key configured.")
        config.auth_cookie = "sessionid=abc123; csrftoken=xyz"
        config.auth_header = "Authorization: Bearer token123"
        config.proxy = "http://127.0.0.1:8080"
        console = Console(file=io.StringIO(), force_terminal=False, color_system=None)

        finding = Finding(
            tool="nuclei",
            target="https://example.com/dashboard",
            severity="medium",
            title="Sensitive Dashboard Exposure",
            evidence="Dashboard returned to the scanner.",
            reproducible_steps="1. Request the dashboard path.",
            raw_output="",
        )

        async with StateDB(":memory:", target="example.com") as db:
            agent = _AuthAwareExploitAgent(
                db=db,
                ai_client=None,
                scope=["example.com"],
                console=console,
                config=config,
            )

            with patch("httpx.AsyncClient", _RecordingAsyncClient):
                stored = await agent._validate_and_insert_finding(finding)

            self.assertTrue(stored)
            self.assertEqual(_RecordingAsyncClient.last_request_method, "GET")
            self.assertEqual(_RecordingAsyncClient.last_request_url, finding.target)
            self.assertEqual(_RecordingAsyncClient.last_request_kwargs, {})

            init_kwargs = dict(_RecordingAsyncClient.last_init_kwargs or {})
            self.assertEqual(init_kwargs.get("proxy"), "http://127.0.0.1:8080")
            self.assertEqual(init_kwargs.get("timeout"), 5.0)
            self.assertFalse(init_kwargs.get("follow_redirects"))

            headers = dict(init_kwargs.get("headers") or {})
            self.assertEqual(headers.get("Authorization"), "Bearer token123")
            self.assertEqual(headers.get("Cookie"), "sessionid=abc123; csrftoken=xyz")
            self.assertIn("Mozilla/5.0", headers.get("User-Agent", ""))

            findings = await db.get_findings()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].target, finding.target)

    async def test_validate_and_insert_finding_replays_post_json_request_context(self) -> None:
        config = Config()
        config.disable_ai("No API key configured.")
        config.auth_header = "Authorization: Bearer token123"
        console = Console(file=io.StringIO(), force_terminal=False, color_system=None)

        request_body = "{\"email\":\"alice@example.com\",\"role\":\"user\"}"
        evidence_request = (
            "POST https://example.com/api/users HTTP/1.1\r\n"
            "Content-Type: application/json\r\n"
            "X-Trace-Id: abc-123\r\n"
            "\r\n"
            f"{request_body}"
        )
        finding = Finding(
            tool="nuclei",
            target="https://example.com/api/users",
            severity="medium",
            title="User Creation Endpoint Exposed",
            evidence="Scanner reached the JSON API.",
            reproducible_steps="1. Replay the original POST request.",
            raw_output="",
        )

        async with StateDB(":memory:", target="example.com") as db:
            agent = _AuthAwareExploitAgent(
                db=db,
                ai_client=None,
                scope=["example.com"],
                console=console,
                config=config,
            )

            with patch("httpx.AsyncClient", _RecordingAsyncClient):
                stored = await agent._validate_and_insert_finding(
                    finding,
                    evidence_request=evidence_request,
                )

            self.assertTrue(stored)
            self.assertEqual(_RecordingAsyncClient.last_request_method, "POST")
            self.assertEqual(_RecordingAsyncClient.last_request_url, finding.target)
            self.assertEqual(
                dict(_RecordingAsyncClient.last_request_kwargs or {}).get("content"),
                request_body,
            )

            init_kwargs = dict(_RecordingAsyncClient.last_init_kwargs or {})
            headers = dict(init_kwargs.get("headers") or {})
            self.assertEqual(headers.get("Content-Type"), "application/json")
            self.assertEqual(headers.get("X-Trace-Id"), "abc-123")
            self.assertEqual(headers.get("Authorization"), "Bearer token123")

    async def test_validate_and_insert_finding_preserves_waf_response_as_lead(self) -> None:
        config = Config()
        config.disable_ai("No API key configured.")
        console = Console(file=io.StringIO(), force_terminal=False, color_system=None)

        finding = Finding(
            tool="dalfox",
            target="https://example.com/search?q=test",
            severity="medium",
            title="Reflected XSS Candidate",
            evidence="Payload reflected during scanning.",
            reproducible_steps="1. Replay the reflected payload.",
            raw_output="",
        )

        async with StateDB(":memory:", target="example.com") as db:
            agent = _AuthAwareExploitAgent(
                db=db,
                ai_client=None,
                scope=["example.com"],
                console=console,
                config=config,
            )

            with patch("httpx.AsyncClient", _WafBlockingAsyncClient):
                stored = await agent._validate_and_insert_finding(finding)

            self.assertTrue(stored)
            findings = await db.get_findings()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "low")
            self.assertTrue(findings[0].title.startswith("[LEAD] "))
            self.assertIn("denial/WAF response", findings[0].evidence)

    async def test_validate_and_insert_finding_preserves_auth_failure_as_lead(self) -> None:
        config = Config()
        config.disable_ai("No API key configured.")
        config.auth_cookie = "sessionid=abc123"
        console = Console(file=io.StringIO(), force_terminal=False, color_system=None)

        finding = Finding(
            tool="nuclei",
            target="https://example.com/account",
            severity="medium",
            title="Sensitive Account Page Exposed",
            evidence="Scanner reached the account page.",
            reproducible_steps="1. Request the account page.",
            raw_output="",
        )

        async with StateDB(":memory:", target="example.com") as db:
            agent = _AuthAwareExploitAgent(
                db=db,
                ai_client=None,
                scope=["example.com"],
                console=console,
                config=config,
            )

            with patch("httpx.AsyncClient", _AuthFailureAsyncClient):
                stored = await agent._validate_and_insert_finding(finding)

            self.assertTrue(stored)
            findings = await db.get_findings()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "low")
            self.assertTrue(findings[0].title.startswith("[LEAD] "))
            self.assertIn("HTTP 401", findings[0].evidence)

    async def test_validate_and_insert_finding_preserves_timeout_as_informational(self) -> None:
        config = Config()
        config.disable_ai("No API key configured.")
        console = Console(file=io.StringIO(), force_terminal=False, color_system=None)

        finding = Finding(
            tool="nuclei",
            target="https://example.com/admin",
            severity="medium",
            title="Admin Surface Requires Review",
            evidence="Probe returned a meaningful signal during validation.",
            reproducible_steps="1. Replay the original request.",
            raw_output="",
        )

        async with StateDB(":memory:", target="example.com") as db:
            agent = _AuthAwareExploitAgent(
                db=db,
                ai_client=None,
                scope=["example.com"],
                console=console,
                config=config,
            )

            with patch("httpx.AsyncClient", _TimeoutAsyncClient):
                stored = await agent._validate_and_insert_finding(finding)

            self.assertTrue(stored)
            findings = await db.get_findings()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "info")
            self.assertTrue(findings[0].title.startswith("[INFO] "))
            self.assertIn("timed out", findings[0].evidence.lower())

    async def test_validate_and_insert_finding_bypasses_http_for_trufflehog(self) -> None:
        config = Config()
        config.disable_ai("No API key configured.")
        console = Console(file=io.StringIO(), force_terminal=False, color_system=None)

        finding = Finding(
            tool="trufflehog",
            target="example.com",
            severity="high",
            title="Leaked Secret in GitHub Source - AWS Access Key",
            evidence=(
                "Organization: example\n"
                "Source: example/repo\n"
                "URL: https://github.com/example/repo/security\n"
                "Verified: true\n"
                "Value (redacted): AKIA[…REDACTED…]1234"
            ),
            reproducible_steps="1. Re-run trufflehog against the same org.",
            raw_output="",
        )

        async with StateDB(":memory:", target="example.com") as db:
            agent = _AuthAwareExploitAgent(
                db=db,
                ai_client=None,
                scope=["example.com"],
                console=console,
                config=config,
            )

            with patch("httpx.AsyncClient", _ForbiddenAsyncClient):
                stored = await agent._validate_and_insert_finding(finding)

            self.assertTrue(stored)
            findings = await db.get_findings()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "high")
            self.assertFalse(findings[0].title.startswith("[LEAD] "))
            self.assertIn("Trufflehog marked the secret as verified", findings[0].evidence)

    async def test_validate_and_insert_finding_maps_ffuf_200_to_lead_without_http_replay(self) -> None:
        config = Config()
        config.disable_ai("No API key configured.")
        console = Console(file=io.StringIO(), force_terminal=False, color_system=None)

        finding = Finding(
            tool="ffuf",
            target="https://example.com/admin",
            severity="medium",
            title="Hidden Resource Found — HTTP 200",
            evidence="URL: https://example.com/admin\nStatus: 200, Length: 512 bytes",
            reproducible_steps="1. Visit: https://example.com/admin",
            raw_output="",
        )

        async with StateDB(":memory:", target="example.com") as db:
            agent = _AuthAwareExploitAgent(
                db=db,
                ai_client=None,
                scope=["example.com"],
                console=console,
                config=config,
            )

            with patch("httpx.AsyncClient", _ForbiddenAsyncClient):
                stored = await agent._validate_and_insert_finding(finding)

            self.assertTrue(stored)
            findings = await db.get_findings()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "low")
            self.assertTrue(findings[0].title.startswith("[LEAD] "))
            self.assertIn("FFUF surface discovery preserved as a lead", findings[0].evidence)

    async def test_validate_and_insert_finding_maps_ffuf_403_to_informational_without_http_replay(self) -> None:
        config = Config()
        config.disable_ai("No API key configured.")
        console = Console(file=io.StringIO(), force_terminal=False, color_system=None)

        finding = Finding(
            tool="ffuf",
            target="https://example.com/internal",
            severity="medium",
            title="Hidden Resource Found — HTTP 403",
            evidence="URL: https://example.com/internal\nStatus: 403, Length: 120 bytes",
            reproducible_steps="1. Visit: https://example.com/internal",
            raw_output="",
        )

        async with StateDB(":memory:", target="example.com") as db:
            agent = _AuthAwareExploitAgent(
                db=db,
                ai_client=None,
                scope=["example.com"],
                console=console,
                config=config,
            )

            with patch("httpx.AsyncClient", _ForbiddenAsyncClient):
                stored = await agent._validate_and_insert_finding(finding)

            self.assertTrue(stored)
            findings = await db.get_findings()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "info")
            self.assertTrue(findings[0].title.startswith("[INFO] "))
            self.assertIn("HTTP 403", findings[0].evidence)

    async def test_validate_and_insert_finding_maps_graphql_recon_public_schema_to_informational_without_http_replay(self) -> None:
        config = Config()
        config.disable_ai("No API key configured.")
        console = Console(file=io.StringIO(), force_terminal=False, color_system=None)

        finding = Finding(
            tool="graphql_recon",
            target="https://example.com/graphql",
            severity="info",
            title="[Public GraphQL API] Introspection Enabled — Read-Only/Public Schema",
            evidence=(
                "Endpoint: https://example.com/graphql\n"
                "HTTP Status: 200\n"
                "Exposed types: Query, Product, Healthcheck"
            ),
            reproducible_steps="1. POST the introspection query to the GraphQL endpoint.",
            raw_output="{\"data\":{\"__schema\":{\"types\":[{\"name\":\"Query\"}]}}}",
        )

        async with StateDB(":memory:", target="example.com") as db:
            agent = _AuthAwareExploitAgent(
                db=db,
                ai_client=None,
                scope=["example.com"],
                console=console,
                config=config,
            )

            with patch("httpx.AsyncClient", _ForbiddenAsyncClient):
                stored = await agent._validate_and_insert_finding(finding)

            self.assertTrue(stored)
            findings = await db.get_findings()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "info")
            self.assertTrue(findings[0].title.startswith("[INFO] "))
            self.assertIn("[Tool-Specific Policy: Advisory]", findings[0].evidence)
            self.assertIn("GraphQL introspection exposure preserved as advisory informational context", findings[0].evidence)

    async def test_validate_and_insert_finding_maps_cloud_ssrf_surface_to_lead_without_http_replay(self) -> None:
        config = Config()
        config.disable_ai("No API key configured.")
        console = Console(file=io.StringIO(), force_terminal=False, color_system=None)

        finding = Finding(
            tool="cloud_ssrf",
            target="https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/",
            severity="high",
            title="Cloud SSRF Surface — Metadata Endpoint Not Blocked",
            evidence=(
                "SSRF-prone endpoint: https://example.com/fetch\n"
                "Injected param 'url' with: http://169.254.169.254/latest/meta-data/\n"
                "HTTP response: 200 (512 bytes)\n"
                "Content snippet: upstream returned a generic success page"
            ),
            reproducible_steps="1. Replay the metadata probe and confirm with OOB telemetry.",
            raw_output="upstream returned a generic success page",
        )

        async with StateDB(":memory:", target="example.com") as db:
            agent = _AuthAwareExploitAgent(
                db=db,
                ai_client=None,
                scope=["example.com"],
                console=console,
                config=config,
            )

            with patch("httpx.AsyncClient", _ForbiddenAsyncClient):
                stored = await agent._validate_and_insert_finding(finding)

            self.assertTrue(stored)
            findings = await db.get_findings()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "low")
            self.assertTrue(findings[0].title.startswith("[LEAD] "))
            self.assertIn("[Tool-Specific Policy: Advisory]", findings[0].evidence)
            self.assertIn("Cloud SSRF surface signal preserved as a lead", findings[0].evidence)

    async def test_commander_logs_raw_and_status_on_json_decode_and_recovers_with_fallback(self) -> None:
        config = Config()
        config.disable_ai("No API key configured.")
        config.ai_fallback_provider = "ollama"
        console_buffer = io.StringIO()
        console = Console(file=console_buffer, force_terminal=False, color_system=None)

        async with StateDB(":memory:", target="example.com") as db:
            agent = _AuthAwareExploitAgent(
                db=db,
                ai_client=None,
                scope=["example.com"],
                console=console,
                config=config,
            )

            async def _fake_primary_ask(_self, _prompt, system=""):
                return "<html>503 Service Unavailable</html>"

            fallback_mock = AsyncMock(
                return_value=(
                    '{"stealth_mode": false, "targets": [], "global_notes": "fallback-plan-ok"}',
                    200,
                    "ollama",
                )
            )

            with patch.object(BaseAgent, "_ask_ai", _fake_primary_ask), patch.object(
                agent, "_ask_fallback_provider_with_meta", fallback_mock
            ):
                plan = await agent._build_execution_plan(
                    ["https://example.com/search?q=1"],
                    "example.com",
                )

            self.assertIn("fallback-plan-ok", plan.get("global_notes", ""))
            self.assertEqual(plan.get("targets", []), [])
            self.assertGreaterEqual(fallback_mock.await_count, 1)

            log_text = console_buffer.getvalue()
            self.assertIn("Commander parse failure", log_text)
            self.assertIn("HTTP Status: unknown", log_text)
            self.assertIn("Raw Response: <html>503 Service Unavailable</html>", log_text)
            self.assertIn("fallback provider 'ollama'", log_text)

    async def test_commander_logs_fallback_status_and_raw_when_fallback_returns_non_json(self) -> None:
        config = Config()
        config.disable_ai("No API key configured.")
        config.ai_fallback_provider = "ollama"
        console_buffer = io.StringIO()
        console = Console(file=console_buffer, force_terminal=False, color_system=None)

        async with StateDB(":memory:", target="example.com") as db:
            agent = _AuthAwareExploitAgent(
                db=db,
                ai_client=None,
                scope=["example.com"],
                console=console,
                config=config,
            )

            async def _fake_primary_ask(_self, _prompt, system=""):
                return ""

            fallback_mock = AsyncMock(
                return_value=(
                    "<html><title>503 Service Unavailable</title></html>",
                    503,
                    "ollama",
                )
            )

            sleep_mock = AsyncMock(return_value=None)
            with patch.object(BaseAgent, "_ask_ai", _fake_primary_ask), patch.object(
                agent, "_ask_fallback_provider_with_meta", fallback_mock
            ), patch("ghilliesuite_ex.agents.exploit.asyncio.sleep", sleep_mock):
                plan = await agent._build_execution_plan(
                    ["https://example.com/search?q=1"],
                    "example.com",
                )

            self.assertEqual(plan.get("targets", []), [])
            self.assertIn("Parse failure for chunk 1.", plan.get("global_notes", ""))
            self.assertGreaterEqual(fallback_mock.await_count, 1)

            log_text = console_buffer.getvalue()
            self.assertIn("Commander parse failure", log_text)
            self.assertIn("HTTP Status: 503", log_text)
            self.assertIn("Raw Response: <html><title>503 Service Unavailable</title></html>", log_text)


class TestReporterSafety(unittest.IsolatedAsyncioTestCase):
    async def test_reports_redact_secrets_and_mark_ai_disabled(self) -> None:
        console = Console(file=io.StringIO(), force_terminal=False, color_system=None)
        tmp_path = Path("tmp") / f"reporter_safety_{uuid4().hex}"
        tmp_path.mkdir(parents=True, exist_ok=True)
        try:
            evidence_dir = tmp_path / "evidence"
            output_dir = tmp_path / "reports"
            evidence_dir.mkdir(parents=True, exist_ok=True)
            output_dir.mkdir(parents=True, exist_ok=True)

            req_path = evidence_dir / "captured.request.txt"
            res_path = evidence_dir / "captured.response.txt"
            req_path.write_text(
                "GET /api?api_key=querysecret123456 HTTP/1.1\n"
                "Authorization: Bearer bearersecret123456789\n"
                "Cookie: sessionid=supersecret\n",
                encoding="utf-8",
            )
            res_path.write_text(
                "HTTP/1.1 200 OK\n"
                "Set-Cookie: sessionid=serversecret\n\n"
                "{\"token\":\"ghp_abcdefghijklmnopqrstuvwxyz1234567890\"}",
                encoding="utf-8",
            )

            config = Config()
            config.disable_ai("No API key configured.")
            config.output_dir = str(output_dir)
            config.evidence_dir = str(evidence_dir)

            async with StateDB(":memory:", target="example.com") as db:
                await db.insert_host(Host(domain="example.com", status_code=200, tech_stack="nginx"))
                await db.insert_endpoint(Endpoint(url="https://example.com/api?api_key=querysecret123456"))
                await db.insert_finding(
                    Finding(
                        tool="sqlmap",
                        target="https://example.com/api",
                        severity="high",
                        title="SQL Injection",
                        evidence=(
                            f"Evidence Request: {req_path}\n"
                            f"Evidence Response: {res_path}\n"
                            "Authorization: Bearer bearersecret123456789"
                        ),
                        reproducible_steps="Use Cookie: sessionid=supersecret",
                        raw_output="openai=sk-abcdefghijklmnopQRSTUV1234567890",
                    )
                )

                reporter = ReporterAgent(
                    db=db,
                    ai_client=None,
                    scope=["example.com"],
                    console=console,
                    config=config,
                )
                await reporter.run(AgentTask(target="example.com"))

            report_files = list(output_dir.glob("*.*"))
            self.assertTrue(any(path.suffix == ".json" for path in report_files))
            self.assertTrue(any(path.suffix == ".md" for path in report_files))
            self.assertTrue(any(path.suffix == ".html" for path in report_files))
            self.assertFalse(any(path.name.endswith("_bounty_draft.txt") for path in report_files))

            for path in report_files:
                content = path.read_text(encoding="utf-8", errors="replace")
                self.assertIn("AI triage disabled", content)
                self.assertNotIn("sessionid=supersecret", content)
                self.assertNotIn("querysecret123456", content)
                self.assertNotIn("bearersecret123456789", content)
                self.assertNotIn("sk-abcdefghijklmnopQRSTUV1234567890", content)
                self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz1234567890", content)
                if path.suffix == ".html":
                    self.assertNotIn("cdn.tailwindcss.com", content)
                    self.assertNotIn("fonts.googleapis.com", content)
        finally:
            shutil.rmtree(tmp_path, ignore_errors=True)

    async def test_reports_serialize_scope_spec_in_json(self) -> None:
        console = Console(file=io.StringIO(), force_terminal=False, color_system=None)
        tmp_path = Path("tmp") / f"reporter_scope_{uuid4().hex}"
        tmp_path.mkdir(parents=True, exist_ok=True)
        try:
            config = Config()
            config.disable_ai("No API key configured.")
            config.output_dir = str(tmp_path)
            scope = load_scope("example.com,exclude:admin.example.com")

            async with StateDB(":memory:", target="example.com") as db:
                await db.insert_host(Host(domain="example.com", status_code=200, tech_stack="nginx"))
                reporter = ReporterAgent(
                    db=db,
                    ai_client=None,
                    scope=scope,
                    console=console,
                    config=config,
                )
                await reporter.run(AgentTask(target="example.com"))

            json_report = next(tmp_path.glob("*.json"))
            report_data = json.loads(json_report.read_text(encoding="utf-8"))
            self.assertEqual(report_data["scope"]["entries"], ["example.com", "exclude:admin.example.com"])
            self.assertEqual(report_data["scope"]["rules"][0]["kind"], "host_exact")
            self.assertEqual(report_data["scope"]["rules"][1]["include"], False)
        finally:
            shutil.rmtree(tmp_path, ignore_errors=True)

    async def test_bounty_draft_is_generated_only_when_enabled(self) -> None:
        console = Console(file=io.StringIO(), force_terminal=False, color_system=None)
        tmp_path = Path("tmp") / f"reporter_draft_{uuid4().hex}"
        tmp_path.mkdir(parents=True, exist_ok=True)
        try:
            config = Config()
            config.disable_ai("No API key configured.")
            config.output_dir = str(tmp_path)
            config.generate_bounty_draft = True

            async with StateDB(":memory:", target="example.com") as db:
                await db.insert_host(Host(domain="example.com", status_code=200, tech_stack="nginx"))
                await db.insert_finding(
                    Finding(
                        tool="sqlmap",
                        target="https://example.com/api/users?id=1",
                        severity="high",
                        title="SQL Injection",
                        evidence="Authorization: Bearer hiddensecret123",
                        reproducible_steps="Replay the request against the vulnerable parameter.",
                        raw_output="token=ghp_secretshouldberedacted",
                    )
                )

                reporter = ReporterAgent(
                    db=db,
                    ai_client=None,
                    scope=["example.com"],
                    console=console,
                    config=config,
                )
                await reporter.run(AgentTask(target="example.com"))

            draft_files = list(tmp_path.glob("*_bounty_draft.txt"))
            self.assertEqual(len(draft_files), 1)
            draft_content = draft_files[0].read_text(encoding="utf-8")
            self.assertIn("SQL Injection", draft_content)
            self.assertNotIn("hiddensecret123", draft_content)
            self.assertNotIn("ghp_secretshouldberedacted", draft_content)
        finally:
            shutil.rmtree(tmp_path, ignore_errors=True)
