import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from rich.console import Console

from ghilliesuite_ex.agents.base import AgentTask
from ghilliesuite_ex.agents.reporter import ReporterAgent
from ghilliesuite_ex.config import Config
from ghilliesuite_ex.state.db import StateDB
from ghilliesuite_ex.state.models import Endpoint, Finding, Host, Screenshot
from ghilliesuite_ex.utils.executor import _build_tool_env
from ghilliesuite_ex.utils.redaction import redact_command, redact_text
from ghilliesuite_ex.utils.run_metadata import safe_run_slug, write_run_manifest
from ghilliesuite_ex.utils.ui import hitl_prompt, tool_result_panel


class TestStateAndOutputHardening(unittest.IsolatedAsyncioTestCase):
    async def test_ignored_host_insert_returns_existing_host_id(self):
        async with StateDB(":memory:", target="example.com") as db:
            first_id = await db.insert_host(Host(domain="first.example.com"))
            await db.insert_host(Host(domain="second.example.com"))
            duplicate_id = await db.insert_host(Host(domain="first.example.com"))
            self.assertEqual(duplicate_id, first_id)

    async def test_narrower_report_scope_excludes_stale_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            async with StateDB(":memory:", target="example.com") as db:
                for name in ("allowed.example.com", "excluded.example.com"):
                    await db.insert_host(Host(domain=name, status_code=200))
                    await db.insert_endpoint(Endpoint(url=f"https://{name}/api"))
                    await db.insert_screenshot(Screenshot(url=f"https://{name}/", path="missing.png"))
                    await db.insert_finding(Finding(tool="nuclei", target=f"https://{name}/api", severity="high", title=f"Finding {name}", evidence="evidence", reproducible_steps="steps", raw_output=""))

                cfg = Config()
                cfg.output_dir = tmp
                cfg.ai_enabled = False
                output = io.StringIO()
                agent = ReporterAgent(db, None, ["allowed.example.com"], Console(file=output, force_terminal=False), cfg)
                await agent.run(AgentTask(target="example.com"))

            for path in Path(tmp).glob("*.*"):
                if path.suffix in (".json", ".md", ".html"):
                    content = path.read_text(encoding="utf-8")
                    self.assertIn("allowed.example.com", content)
                    self.assertNotIn("excluded.example.com", content, str(path))


class TestRedactionAndArtifacts(unittest.TestCase):
    def test_redacts_query_token_and_json_cookie_values(self):
        text = 'https://example.com/api?token=session-secret-123&ok=yes {"Cookie": "session=session-secret-123"}'
        result = redact_text(text)
        self.assertNotIn("session-secret-123", result)
        self.assertIn("ok=yes", result)

    def test_tool_panels_hide_credentials_in_commands_and_summaries(self):
        output = io.StringIO()
        console = Console(file=output, force_terminal=False)
        cmd = ["curl", "-H", "Authorization: Bearer secret-token-123", "https://example.com/?token=secret-token-123"]
        tool_result_panel(console, "curl", cmd, True, "Cookie: session=secret-token-123")
        with patch("ghilliesuite_ex.utils.ui.Confirm.ask", return_value=False):
            hitl_prompt(console, "curl", cmd, "Test token=secret-token-123")
        self.assertNotIn("secret-token-123", output.getvalue())
        self.assertIn("curl", output.getvalue())

    def test_command_redaction_keeps_scan_target_visible(self):
        command = redact_command([
            "nuclei", "-u", "https://example.com/api?token=secret-token-123",
            "-H", "Authorization: Bearer secret-token-123",
        ])
        self.assertIn("https://example.com/api", command)
        self.assertNotIn("secret-token-123", command)
        self.assertNotIn("alice:secret", redact_command(["curl", "-u", "alice:secret"]))

    def test_slug_is_filename_safe_and_unique_for_same_start_time(self):
        started = datetime(2026, 10, 10, 1, 2, 3, tzinfo=timezone.utc)
        first = safe_run_slug("https://example.com/a?token=secret/../../bad", started)
        second = safe_run_slug("https://example.com/a?token=secret/../../bad", started)
        self.assertNotEqual(first, second)
        self.assertNotIn("secret", first)
        self.assertTrue(all(c.isalnum() or c in "_-" for c in first))

    def test_manifest_write_preserves_prior_artifact_on_collision(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = write_run_manifest(tmp, "same", {"status": "first"})
            second = write_run_manifest(tmp, "same", {"status": "second"})
            self.assertNotEqual(first, second)
            self.assertEqual(json.loads(first.read_text())["status"], "first")
            self.assertEqual(json.loads(second.read_text())["status"], "second")

    def test_tool_path_uses_platform_separator(self):
        home_bin = Path.home() / "go" / "bin"
        with patch("ghilliesuite_ex.utils.executor.Path.is_dir", lambda p: p == home_bin), patch.dict(os.environ, {"PATH": "C:\\Windows"}):
            env = _build_tool_env()
        self.assertTrue(env["PATH"].startswith(str(home_bin) + os.pathsep))


if __name__ == "__main__":
    unittest.main()
