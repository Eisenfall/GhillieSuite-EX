import io
import unittest
from types import SimpleNamespace

from rich.console import Console

from ghilliesuite_ex.agents.base import AgentResult, AgentTask
from ghilliesuite_ex.agents.supervisor import SupervisorAgent
from ghilliesuite_ex.config import Config


class _FakeDB:
    def __init__(self, findings=None):
        self.findings = findings or []

    async def get_hosts(self, scope_domains=None):
        return []

    async def get_endpoints(self):
        return []

    async def get_findings(self):
        return list(self.findings)


class _Stage:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    async def run(self, task):
        self.calls += 1
        return self.result


class TestSupervisorStatus(unittest.IsolatedAsyncioTestCase):
    async def test_recon_failure_is_reported_after_partial_report(self):
        db = _FakeDB()
        supervisor = SupervisorAgent(
            db, None, ["example.com"], Console(file=io.StringIO()), Config(), max_loops=1
        )
        supervisor.recon_agent = _Stage(
            AgentResult("ReconAgent", "error", "httpx failed", items_added=3, error="httpx")
        )
        supervisor.reporter_agent = _Stage(AgentResult("ReporterAgent", "ok", "report saved"))

        result = await supervisor.run(AgentTask(target="example.com"))

        self.assertEqual(result.status, "error")
        self.assertIn("httpx", result.summary)
        self.assertEqual(supervisor.reporter_agent.calls, 1)

    async def test_summary_counts_findings_in_scope_not_recon_records(self):
        db = _FakeDB([
            SimpleNamespace(target="https://example.com/api", severity="high"),
            SimpleNamespace(target="https://outside.example/api", severity="high"),
        ])
        supervisor = SupervisorAgent(
            db, None, ["example.com"], Console(file=io.StringIO()), Config(), max_loops=1
        )
        supervisor.recon_agent = _Stage(
            AgentResult("ReconAgent", "ok", "recon done", items_added=50)
        )
        supervisor.reporter_agent = _Stage(AgentResult("ReporterAgent", "ok", "report saved"))

        result = await supervisor.run(AgentTask(target="example.com"))

        self.assertEqual(result.status, "ok")
        self.assertIn("1 finding(s)", result.summary)
        self.assertEqual(result.items_added, 0)


if __name__ == "__main__":
    unittest.main()
