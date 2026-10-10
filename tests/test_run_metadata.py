import json
import shutil
import unittest
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from ghilliesuite_ex.utils.run_metadata import (
    build_run_manifest,
    safe_run_slug,
    write_run_manifest,
)


class TestRunMetadata(unittest.TestCase):
    def test_safe_run_slug_normalizes_target(self) -> None:
        started_at = datetime(2026, 5, 14, 12, 30, 45, tzinfo=timezone.utc)
        slug = safe_run_slug("https://app.example.com:8443", started_at)
        self.assertTrue(slug.startswith("https__app_example_com8443_20260514_123045_000000_"))

    def test_safe_run_slug_handles_invalid_port_without_leaking_query(self) -> None:
        started_at = datetime(2026, 5, 14, 12, 30, 45, tzinfo=timezone.utc)
        slug = safe_run_slug("https://example.com:bad/?token=secret123", started_at)
        self.assertTrue(slug.startswith("target_"))
        self.assertNotIn("secret123", slug)

    def test_build_run_manifest_excludes_sensitive_runtime_fields(self) -> None:
        started_at = datetime(2026, 5, 14, 12, 0, 0, tzinfo=timezone.utc)
        finished_at = datetime(2026, 5, 14, 12, 0, 3, 500000, tzinfo=timezone.utc)
        manifest = build_run_manifest(
            target="example.com",
            scope=["example.com"],
            started_at=started_at,
            finished_at=finished_at,
            status="completed",
            summary="Hunt complete.",
            execution_profile="balanced",
            ai_enabled=False,
            ai_provider="none",
            ai_status_message="AI triage disabled",
            ai_disabled_reason="No API key configured.",
            output_dir="reports",
            evidence_dir="evidence",
            db_path="C:/tmp/test.db",
            runtime_flags={
                "safe_mode": True,
                "force_auto": False,
                "generate_bounty_draft": False,
            },
            tooling={"required_missing": [], "optional_missing": ["gowitness"]},
            counts={"hosts": 2, "endpoints": 5, "findings": 1},
            failure_stage="",
            target_session={"target": "example.com"},
        )

        self.assertEqual(manifest["status"], "completed")
        self.assertEqual(manifest["duration_seconds"], 3.5)
        self.assertNotIn("auth_cookie", json.dumps(manifest))
        self.assertNotIn("auth_header", json.dumps(manifest))
        self.assertEqual(manifest["tooling"]["optional_missing"], ["gowitness"])

    def test_write_run_manifest_persists_json(self) -> None:
        tmp_path = Path("tmp") / f"run_manifest_{uuid4().hex}"
        tmp_path.mkdir(parents=True, exist_ok=True)
        try:
            manifest_path = write_run_manifest(
                tmp_path,
                "example_20260514_123045",
                {"status": "preflight_failed", "summary": "Missing required tools."},
            )
            self.assertTrue(manifest_path.exists())
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "preflight_failed")
        finally:
            shutil.rmtree(tmp_path, ignore_errors=True)
