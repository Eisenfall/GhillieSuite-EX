import unittest
from pathlib import Path
from uuid import uuid4

from ghilliesuite_ex.utils.scope import (
    explain_scope_decision,
    filter_in_scope,
    is_in_scope,
    load_scope,
    scope_filter_domains,
    scope_filter_urls,
    validate_target_scope,
)


class TestScopeRules(unittest.TestCase):
    def test_exact_host_matches_only_apex(self) -> None:
        scope = load_scope("example.com")
        self.assertTrue(is_in_scope("example.com", scope))
        self.assertFalse(is_in_scope("api.example.com", scope))

    def test_wildcard_matches_subdomains_not_apex(self) -> None:
        scope = load_scope("*.example.com")
        self.assertFalse(is_in_scope("example.com", scope))
        self.assertTrue(is_in_scope("api.example.com", scope))

    def test_exclude_overrides_include(self) -> None:
        scope = load_scope("*.example.com,exclude:admin.example.com")
        self.assertTrue(is_in_scope("api.example.com", scope))
        self.assertFalse(is_in_scope("admin.example.com", scope))

    def test_url_prefix_rules(self) -> None:
        scope = load_scope("url:https://app.example.com/api/")
        self.assertTrue(is_in_scope("https://app.example.com/api/v1/users", scope))
        self.assertFalse(is_in_scope("https://app.example.com/admin", scope))
        self.assertFalse(is_in_scope("app.example.com", scope))

    def test_exclude_url_prefix_blocks_matching_path(self) -> None:
        scope = load_scope("example.com,exclude-url:https://example.com/private/")
        self.assertTrue(is_in_scope("https://example.com/public/info", scope))
        self.assertFalse(is_in_scope("https://example.com/private/report", scope))

    def test_url_rules_normalize_default_ports_and_path_segments(self) -> None:
        scope = load_scope("url:https://example.com/api/,exclude-url:https://example.com/api/private/")
        self.assertTrue(is_in_scope("https://EXAMPLE.com:443/api/users", scope))
        self.assertFalse(is_in_scope("https://example.com:443/api/../admin", scope))
        self.assertFalse(is_in_scope("https://example.com/api/%2e%2e/admin", scope))
        self.assertFalse(is_in_scope("https://example.com/api/private/../private/secret", scope))
        self.assertFalse(is_in_scope("https://example.com/apix/users", scope))
        self.assertFalse(is_in_scope("https://example.com:444/api/users", scope))
        self.assertFalse(is_in_scope("https://example.com/api/%252525252e%252525252e/admin", scope))

    def test_url_rule_matches_base_path_without_trailing_slash(self) -> None:
        scope = load_scope("url:https://example.com/api/")
        self.assertTrue(is_in_scope("https://example.com/api", scope))
        self.assertTrue(is_in_scope("https://example.com/api/", scope))

    def test_cidr_rules(self) -> None:
        scope = load_scope("cidr:10.10.10.0/24,exclude-cidr:10.10.10.128/25")
        self.assertTrue(is_in_scope("10.10.10.42", scope))
        self.assertFalse(is_in_scope("10.10.10.200", scope))

    def test_validate_target_scope_raises_with_reason(self) -> None:
        scope = load_scope("example.com,exclude:example.com")
        with self.assertRaisesRegex(ValueError, "explicitly excluded"):
            validate_target_scope("example.com", scope)

    def test_scope_filters_respect_strict_rules(self) -> None:
        scope = load_scope("example.com,*.example.com,exclude:admin.example.com")
        self.assertEqual(
            scope_filter_domains(["example.com", "api.example.com", "admin.example.com"], scope),
            ["example.com", "api.example.com"],
        )
        self.assertEqual(
            scope_filter_urls(
                [
                    "https://example.com/",
                    "https://api.example.com/v1",
                    "https://admin.example.com/panel",
                ],
                scope,
            ),
            ["https://example.com/", "https://api.example.com/v1"],
        )
        self.assertEqual(
            filter_in_scope(["example.com", "api.example.com", "admin.example.com"], scope),
            ["example.com", "api.example.com"],
        )

    def test_scope_file_with_directives(self) -> None:
        scope_text = "\n".join(
            [
                "# comment",
                "example.com",
                "*.example.com",
                "exclude:admin.example.com",
                "url:https://example.com/api/",
                "cidr:192.0.2.0/24",
            ]
        )
        tmp_dir = Path("tmp")
        tmp_dir.mkdir(parents=True, exist_ok=True)
        scope_path = tmp_dir / f"scope_{uuid4().hex}.txt"
        try:
            scope_path.write_text(scope_text, encoding="utf-8")
            scope = load_scope(str(scope_path))
        finally:
            scope_path.unlink(missing_ok=True)
        self.assertTrue(is_in_scope("example.com", scope))
        self.assertTrue(is_in_scope("https://example.com/api/users", scope))
        self.assertFalse(is_in_scope("admin.example.com", scope))

    def test_explain_scope_decision_mentions_matching_rule(self) -> None:
        scope = load_scope("example.com,exclude-url:https://example.com/private/")
        allowed, reason = explain_scope_decision("https://example.com/private/report", scope)
        self.assertFalse(allowed)
        self.assertIn("exclude-url:https://example.com/private/", reason)


if __name__ == "__main__":
    unittest.main()
