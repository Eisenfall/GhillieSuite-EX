import unittest
from pathlib import Path

from ghilliesuite_ex.arsenal import build_command

from ghilliesuite_ex.agents.recon_pipeline import (
    build_httpx_targets,
    build_katana_candidates,
    katana_crawl_safe_for_scope,
    select_arjun_targets,
    select_katana_targets,
)


class TestReconPipelineHelpers(unittest.TestCase):
    def test_build_httpx_targets_filters_scope_and_deduplicates(self) -> None:
        targets = build_httpx_targets(
            ["example.com", "example.com", "outside.com"],
            ["example.com"],
        )
        self.assertEqual(targets, ["http://example.com", "https://example.com"])

    def test_url_only_scope_probes_exact_target(self) -> None:
        scope = ["url:https://example.com/api/"]
        self.assertEqual(
            build_httpx_targets(["example.com"], scope, root_target="https://example.com/api/"),
            ["https://example.com/api/"],
        )

    def test_explicit_target_port_is_probed(self) -> None:
        self.assertEqual(
            build_httpx_targets(["example.com"], ["example.com"], root_target="example.com:8443"),
            [
                "http://example.com:8443", "https://example.com:8443",
                "http://example.com", "https://example.com",
            ],
        )

    def test_katana_keeps_path_scoped_seed(self) -> None:
        scope = ["url:https://example.com/api/"]
        self.assertEqual(
            build_katana_candidates(["https://example.com/api/users"], scope=scope),
            ["https://example.com/api/users"],
        )

    def test_katana_is_disabled_for_path_restricted_scope(self) -> None:
        self.assertFalse(katana_crawl_safe_for_scope(["url:https://example.com/api/"]))
        self.assertFalse(katana_crawl_safe_for_scope([
            "example.com", "exclude-url:https://example.com/private/",
        ]))
        self.assertTrue(katana_crawl_safe_for_scope(["example.com"]))

    def test_katana_command_stays_on_exact_host_and_stops_at_redirect(self) -> None:
        command = build_command(
            "katana", "https://example.com", output_file=Path("tmp/katana.jsonl")
        )
        self.assertEqual(command[command.index("-fs") + 1], "fqdn")
        self.assertIn("-dr", command)

    def test_build_katana_candidates_normalizes_to_origin(self) -> None:
        candidates = build_katana_candidates(
            [
                "https://example.com/path?a=1",
                "https://example.com/other",
                "http://api.example.com/v1/users",
                "not-a-url",
            ]
        )

        self.assertEqual(
            candidates,
            ["https://example.com", "http://api.example.com"],
        )

    def test_select_katana_targets_respects_recrawl_interval(self) -> None:
        selected = select_katana_targets(
            ["https://example.com", "https://api.example.com", "https://stale.example.com"],
            history={"https://api.example.com", "https://stale.example.com"},
            last_crawl_run={
                "https://api.example.com": 4,
                "https://stale.example.com": 1,
            },
            recon_run_count=5,
            recrawl_interval=3,
            max_targets=10,
        )

        self.assertEqual(
            selected,
            ["https://example.com", "https://stale.example.com"],
        )

    def test_select_arjun_targets_prioritizes_api_and_deduplicates_base_paths(self) -> None:
        selected = select_arjun_targets(
            [
                "https://example.com/blog/",
                "https://example.com/api/users",
                "https://example.com/api/users/1234567890123456789012345",
                "https://example.com/profile.php",
                "https://example.com/assets/app.js",
                "https://outside.com/api/users",
            ],
            history=set(),
            scope=["example.com"],
            limit=10,
        )

        self.assertEqual(
            selected,
            ["https://example.com/api/users", "https://example.com/profile.php"],
        )
