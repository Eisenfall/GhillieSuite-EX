import io
import unittest
from collections import Counter
from unittest.mock import AsyncMock, patch

from rich.console import Console

from ghilliesuite_ex.agents.base import AgentTask
from ghilliesuite_ex.agents.recon import ReconAgent
from ghilliesuite_ex.config import Config
from ghilliesuite_ex.state.db import StateDB
from ghilliesuite_ex.utils.executor import ToolResult


class TestReconFlow(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.db = StateDB(":memory:", target="example.com")
        await self.db.__aenter__()
        self.cfg = Config()
        self.cfg.enable_screenshots = False
        self.cfg.recon_enable_dnsx = False
        self.cfg.recon_enable_naabu = False
        self.cfg.recon_enable_subzy = False
        self.console = Console(file=io.StringIO(), force_terminal=False)
        self.agent = ReconAgent(self.db, None, ["example.com"], self.console, self.cfg)

    async def asyncTearDown(self) -> None:
        await self.db.__aexit__(None, None, None)

    async def test_failed_subfinder_and_httpx_are_retried(self) -> None:
        attempts = Counter()

        async def fake_file(cmd, output_path, timeout):
            tool = cmd[0]
            attempts[tool] += 1
            if tool in {"subfinder", "httpx"} and attempts[tool] == 1:
                return ToolResult(returncode=1, error="failed")
            if tool == "subfinder":
                output_path.write_text("api.example.com\n", encoding="utf-8")
            elif tool == "httpx":
                output_path.write_text('{"url":"https://example.com/api/users","status-code":200}\n', encoding="utf-8")
            else:
                output_path.write_text("", encoding="utf-8")
            return ToolResult(output_file=output_path)

        with patch("ghilliesuite_ex.agents.recon.build_command", side_effect=lambda tool, *a, **k: [tool]), \
             patch("ghilliesuite_ex.agents.recon.run_tool_to_file", side_effect=fake_file), \
             patch("ghilliesuite_ex.agents.recon.run_tool", new_callable=AsyncMock, return_value=ToolResult()):
            first = await self.agent.run(AgentTask(target="example.com"))
            await self.agent.run(AgentTask(target="example.com"))

        self.assertEqual(first.status, "error")
        self.assertEqual(attempts["subfinder"], 2)
        self.assertEqual(attempts["httpx"], 2)

    async def test_pending_katana_and_arjun_survive_next_run(self) -> None:
        attempts = Counter()

        async def fake_file(cmd, output_path, timeout):
            tool = cmd[0]
            attempts[tool] += 1
            if tool in {"katana", "arjun"} and attempts[tool] == 1:
                return ToolResult(returncode=1, error="failed")
            contents = {
                "subfinder": "example.com\n",
                "httpx": '{"url":"https://example.com/api/users","status-code":200}\n',
                "katana": "",
                "arjun": '{"https://example.com/api/users":["id"]}',
            }
            output_path.write_text(contents.get(tool, ""), encoding="utf-8")
            return ToolResult(output_file=output_path)

        with patch("ghilliesuite_ex.agents.recon.build_command", side_effect=lambda tool, *a, **k: [tool]), \
             patch("ghilliesuite_ex.agents.recon.run_tool_to_file", side_effect=fake_file), \
             patch("ghilliesuite_ex.agents.recon.run_tool", new_callable=AsyncMock, return_value=ToolResult()):
            await self.agent.run(AgentTask(target="example.com"))
            await self.agent.run(AgentTask(target="example.com"))

        self.assertEqual(attempts["httpx"], 1)
        self.assertEqual(attempts["katana"], 2)
        self.assertGreaterEqual(attempts["arjun"], 2)

    async def test_safe_mode_requires_approval_before_scanner_execution(self) -> None:
        with patch("ghilliesuite_ex.agents.recon.build_command", side_effect=lambda tool, *a, **k: [tool]), \
             patch("ghilliesuite_ex.agents.recon.auto_approve", return_value=False) as approve, \
             patch("ghilliesuite_ex.agents.recon.run_tool_to_file", new_callable=AsyncMock) as file_run, \
             patch("ghilliesuite_ex.agents.recon.run_tool", new_callable=AsyncMock) as raw_run:
            result = await self.agent.run(AgentTask(target="example.com", safe_mode=True))

        self.assertGreaterEqual(approve.call_count, 1)
        file_run.assert_not_awaited()
        raw_run.assert_not_awaited()
        self.assertEqual(result.status, "skipped")

    async def test_httpx_never_auto_follows_redirects_outside_scope(self) -> None:
        self.cfg.allow_redirects = True
        command_options = []

        def fake_command(tool, *args, **kwargs):
            command_options.append((tool, kwargs))
            return [tool]

        with patch("ghilliesuite_ex.agents.recon.build_command", side_effect=fake_command), patch(
            "ghilliesuite_ex.agents.recon.run_tool_to_file",
            new_callable=AsyncMock,
            return_value=ToolResult(returncode=1, error="mock failure"),
        ), patch("ghilliesuite_ex.agents.recon.run_tool", new_callable=AsyncMock, return_value=ToolResult()):
            await self.agent.run(AgentTask(target="example.com"))

        httpx_options = next(kwargs for tool, kwargs in command_options if tool == "httpx")
        self.assertIs(httpx_options.get("allow_redirects"), False)

    async def test_path_scoped_recon_does_not_launch_katana(self) -> None:
        self.agent.scope = ["url:https://example.com/api/"]
        self.cfg.enable_screenshots = True
        self.cfg.recon_enable_dnsx = True
        self.cfg.recon_enable_naabu = True
        self.cfg.recon_enable_subzy = True
        launched = []

        async def fake_file(cmd, output_path, timeout):
            launched.append(cmd[0])
            if cmd[0] == "httpx":
                output_path.write_text(
                    '{"url":"https://example.com/api/users","status-code":200}\n', encoding="utf-8"
                )
            else:
                output_path.write_text("", encoding="utf-8")
            return ToolResult(output_file=output_path)

        with patch("ghilliesuite_ex.agents.recon.build_command", side_effect=lambda tool, *a, **k: [tool]), patch(
            "ghilliesuite_ex.agents.recon.run_tool_to_file", side_effect=fake_file
        ), patch("ghilliesuite_ex.agents.recon.run_tool", new_callable=AsyncMock, return_value=ToolResult()):
            await self.agent.run(AgentTask(target="https://example.com/api/"))
        self.assertIn("httpx", launched)
        self.assertFalse(set(launched) & {"katana", "arjun", "dnsx", "naabu", "subzy", "gowitness"})
