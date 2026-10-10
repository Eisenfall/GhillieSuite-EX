import unittest
import tempfile
import json
from pathlib import Path
from unittest.mock import AsyncMock
from unittest.mock import patch

from typer.testing import CliRunner

from ghilliesuite_ex import __version__
from ghilliesuite_ex.main import app
from ghilliesuite_ex.config import cfg
from ghilliesuite_ex.agents.base import AgentResult
from ghilliesuite_ex.arsenal import collect_tooling_status


class TestCliSmoke(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_help_renders(self) -> None:
        result = self.runner.invoke(app, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("GhillieSuite-EX.sec", result.stdout)
        self.assertIn("check-tools", result.stdout)

    def test_version_renders(self) -> None:
        result = self.runner.invoke(app, ["version"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn(__version__, result.stdout)

    def test_check_tools_runs(self) -> None:
        result = self.runner.invoke(app, ["check-tools"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Required Tools", result.stdout)

    def test_check_config_reports_missing_key(self) -> None:
        result = self.runner.invoke(app, ["check-config"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Configuration error:", result.stdout)

    def test_check_config_accepts_mocked_provider(self) -> None:
        with patch("ghilliesuite_ex.main.validate_config", return_value="openai"):
            result = self.runner.invoke(app, ["check-config"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Configuration valid.", result.stdout)

    def test_hunt_startup_never_prints_auth_values(self) -> None:
        with tempfile.TemporaryDirectory() as output_dir, patch(
            "ghilliesuite_ex.main.check_binaries", return_value={}
        ):
            result = self.runner.invoke(app, [
                "hunt", "--target", "example.com", "--scope", "example.com",
                "--cookie", "session=secret-session-123",
                "--header", "Authorization: Bearer secret-token-123",
                "--output", output_dir, "--no-update-templates",
            ])
        self.assertEqual(result.exit_code, 1)
        self.assertNotIn("secret-session-123", result.stdout)
        self.assertNotIn("secret-token-123", result.stdout)

    def test_failed_agent_sets_nonzero_exit_and_error_manifest(self) -> None:
        installed = {name: True for name in collect_tooling_status(profile="balanced").required_tools}
        with tempfile.TemporaryDirectory() as output_dir, patch.object(
            cfg, "db_path", str(Path(output_dir) / "state.db")
        ), patch(
            "ghilliesuite_ex.main.check_binaries", return_value=installed
        ), patch(
            "ghilliesuite_ex.agents.supervisor.SupervisorAgent.run",
            new_callable=AsyncMock,
            return_value=AgentResult("SupervisorAgent", "error", "recon failed", error="httpx"),
        ):
            result = self.runner.invoke(app, [
                "hunt", "--target", "example.com", "--scope", "example.com",
                "--output", output_dir, "--no-update-templates",
            ])
            manifests = list(Path(output_dir).glob("*_run.json"))
            self.assertEqual(result.exit_code, 1, result.stdout)
            self.assertEqual(len(manifests), 1)
            self.assertEqual(json.loads(manifests[0].read_text())["status"], "completed_with_errors")
