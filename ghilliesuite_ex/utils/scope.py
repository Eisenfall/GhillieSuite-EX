"""
ghilliesuite_ex/utils/scope.py
──────────────────────────────
Strict scope loading and enforcement.

Supported rule styles:
  • `example.com`                → include exact host only
  • `*.example.com`              → include subdomains only (not the apex)
  • `include:example.com`        → explicit include host
  • `exclude:admin.example.com`  → explicit exclude host
  • `url:https://app.example.com/api/`
  • `exclude-url:https://app.example.com/private/`
  • `cidr:10.10.10.0/24`
  • `exclude-cidr:10.10.10.128/25`
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from pathlib import Path
import posixpath
from typing import Any
from urllib.parse import SplitResult, unquote, urlsplit, urlunsplit


@dataclass(frozen=True)
class ScopeRule:
    include: bool
    kind: str
    value: Any
    raw: str


@dataclass(frozen=True)
class ScopeSpec:
    rules: tuple[ScopeRule, ...]
    entries: tuple[str, ...]

    def __iter__(self):
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    def __getitem__(self, index):
        return self.entries[index]

    def to_dict(self) -> dict[str, Any]:
        return {
            "entries": list(self.entries),
            "rules": [
                {
                    "include": rule.include,
                    "kind": rule.kind,
                    "value": str(rule.value),
                    "raw": rule.raw,
                }
                for rule in self.rules
            ],
        }


@dataclass(frozen=True)
class ScopeTarget:
    raw: str
    host: str
    normalized_url: str | None
    ip: Any | None


def load_scope(scope_input: str) -> ScopeSpec:
    """
    Parse scope from either a comma-separated string or a file path.

    Rules are strict:
      - example.com only matches example.com
      - *.example.com only matches subdomains
      - exclude rules override include rules
    """
    path = Path(scope_input)
    if path.exists() and path.is_file():
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    else:
        raw_lines = [s.strip() for s in scope_input.split(",")]

    entries: list[str] = []
    rules: list[ScopeRule] = []
    for line in raw_lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rule = _parse_scope_rule(line)
        entries.append(rule.raw)
        rules.append(rule)

    if not rules:
        raise ValueError(
            "Scope is empty! Provide at least one include rule via --scope. "
            "Example: --scope example.com or --scope scope.txt"
        )

    if not any(rule.include for rule in rules):
        raise ValueError("Scope must contain at least one include rule.")

    deduped_entries = tuple(dict.fromkeys(entries))
    deduped_rules = tuple({rule.raw: rule for rule in rules}.values())
    return ScopeSpec(rules=deduped_rules, entries=deduped_entries)


def is_in_scope(target: str, scope: ScopeSpec | list[str]) -> bool:
    """Return True when target is allowed and not excluded by the scope rules."""
    allowed, _reason = explain_scope_decision(target, scope)
    return allowed


def validate_target_scope(target: str, scope: ScopeSpec | list[str]) -> None:
    """Raise ValueError when the target is outside scope or explicitly excluded."""
    allowed, reason = explain_scope_decision(target, scope)
    if not allowed:
        raise ValueError(reason)


def explain_scope_decision(target: str, scope: ScopeSpec | list[str]) -> tuple[bool, str]:
    """
    Return (allowed, explanation) for a target against the given scope rules.
    Exclude rules always override include rules.
    """
    spec = _coerce_scope_spec(scope)
    parsed_target = _parse_target(target)

    matched_includes: list[str] = []
    matched_excludes: list[str] = []

    for rule in spec.rules:
        if _rule_matches(rule, parsed_target):
            if rule.include:
                matched_includes.append(rule.raw)
            else:
                matched_excludes.append(rule.raw)

    if matched_excludes:
        return (False, f"Target '{target}' is explicitly excluded by scope rule(s): {', '.join(matched_excludes)}")
    if matched_includes:
        return (True, f"Target '{target}' is allowed by scope rule(s): {', '.join(matched_includes)}")
    return (False, f"Target '{target}' does not match any include rule in the provided scope.")


def enforce_scope(raw_output: str, scope: ScopeSpec | list[str]) -> str:
    """Filter multi-line tool output to only lines that mention an in-scope target."""
    lines = raw_output.splitlines()
    filtered = [line for line in lines if is_in_scope(line, scope)]
    return "\n".join(filtered)


def scope_filter_domains(domains: list[str], scope: ScopeSpec | list[str]) -> list[str]:
    """Filter a list of domain strings to in-scope entries only."""
    return [d for d in domains if is_in_scope(d, scope)]


def scope_filter_urls(urls: list[str], scope: ScopeSpec | list[str]) -> list[str]:
    """Filter a list of URLs to in-scope entries only."""
    return [u for u in urls if is_in_scope(u, scope)]


def filter_in_scope(targets: list[str], scope: ScopeSpec | list[str]) -> list[str]:
    """Return only targets that are in scope (domains, URLs, or literal IPs)."""
    return [t for t in targets if is_in_scope(t, scope)]


def scope_has_url_rules(scope: ScopeSpec | list[str]) -> bool:
    """Whether scope includes path rules that whole-site scanners cannot enforce."""
    return any(rule.kind == "url_prefix" for rule in _coerce_scope_spec(scope).rules)


def _coerce_scope_spec(scope: ScopeSpec | list[str]) -> ScopeSpec:
    if isinstance(scope, ScopeSpec):
        return scope

    entries = [str(item).strip() for item in scope if str(item).strip()]
    rules = tuple(_parse_scope_rule(entry) for entry in entries)
    return ScopeSpec(rules=rules, entries=tuple(entries))


def _parse_scope_rule(line: str) -> ScopeRule:
    raw = line.strip()
    lowered = raw.lower()

    if ":" in raw:
        prefix, remainder = raw.split(":", 1)
        directive = prefix.strip().lower()
        value = remainder.strip()

        if directive in {"include", "host"}:
            return _build_host_rule(value, include=True, raw=raw)
        if directive in {"exclude", "exclude-host"}:
            return _build_host_rule(value, include=False, raw=raw)
        if directive in {"url", "include-url"}:
            return ScopeRule(include=True, kind="url_prefix", value=_normalize_url_prefix(value), raw=raw)
        if directive == "exclude-url":
            return ScopeRule(include=False, kind="url_prefix", value=_normalize_url_prefix(value), raw=raw)
        if directive in {"cidr", "include-cidr"}:
            return ScopeRule(include=True, kind="cidr", value=ip_network(value, strict=False), raw=raw)
        if directive == "exclude-cidr":
            return ScopeRule(include=False, kind="cidr", value=ip_network(value, strict=False), raw=raw)

    return _build_host_rule(lowered, include=True, raw=raw)


def _build_host_rule(value: str, include: bool, raw: str) -> ScopeRule:
    host = _normalize_host_literal(value)
    if "*" in host and not host.startswith("*."):
        raise ValueError(f"Invalid wildcard scope rule: '{raw}'. Use '*.example.com'.")

    if host.startswith("*."):
        base = host[2:]
        if not base or "*" in base:
            raise ValueError(f"Invalid wildcard scope rule: '{raw}'.")
        return ScopeRule(include=include, kind="host_wildcard", value=base, raw=raw)

    return ScopeRule(include=include, kind="host_exact", value=host, raw=raw)


def _normalize_host_literal(value: str) -> str:
    host = value.strip().lower().rstrip(".")
    if not host:
        raise ValueError("Empty host scope rule is not allowed.")
    return host


def _normalize_url_prefix(value: str) -> str:
    normalized = _canonical_url(value)
    if normalized is None:
        raise ValueError(f"Invalid URL scope prefix: '{value}'. Use a full http/https URL.")
    return normalized


def _canonical_url(value: str) -> str | None:
    try:
        parsed = urlsplit(value.strip())
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError:
        return None
    if scheme not in {"http", "https"} or not host or parsed.username or parsed.password:
        return None
    if port == {"http": 80, "https": 443}[scheme]:
        port = None
    authority = f"[{host}]" if ":" in host else host
    if port is not None:
        authority += f":{port}"

    path = parsed.path or "/"
    # Scope decisions must reflect paths after ordinary URL decoding and dot
    # removal, including encoded slashes and encoded dot segments.
    for _ in range(4):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    if unquote(path) != path:
        return None
    path = path.replace("\\", "/")
    trailing = path.endswith("/")
    path = posixpath.normpath("/" + path.lstrip("/"))
    if trailing and path != "/":
        path += "/"
    return urlunsplit(SplitResult(scheme, authority, path, parsed.query, ""))


def _parse_target(target: str) -> ScopeTarget:
    raw = target.strip()
    parsed_url: str | None = None

    if "://" in raw:
        parsed_url = _canonical_url(raw)
        host = (urlsplit(parsed_url).hostname or "") if parsed_url else ""
    else:
        pseudo = urlsplit(f"//{raw}")
        host = (pseudo.hostname or raw.split("/", 1)[0]).lower().rstrip(".")

    ip_obj = None
    try:
        ip_obj = ip_address(host)
    except ValueError:
        ip_obj = None

    return ScopeTarget(raw=raw, host=host, normalized_url=parsed_url, ip=ip_obj)


def _rule_matches(rule: ScopeRule, target: ScopeTarget) -> bool:
    if not target.host:
        return False

    if rule.kind == "host_exact":
        return target.host == rule.value
    if rule.kind == "host_wildcard":
        return target.host.endswith("." + rule.value) and target.host != rule.value
    if rule.kind == "url_prefix":
        if target.normalized_url is None:
            return False
        prefix = urlsplit(rule.value)
        candidate = urlsplit(target.normalized_url)
        if (candidate.scheme, candidate.netloc) != (prefix.scheme, prefix.netloc):
            return False
        base = prefix.path.rstrip("/") or "/"
        path = candidate.path
        path_match = path == base or path.startswith(base.rstrip("/") + "/")
        return path_match and (not prefix.query or candidate.query == prefix.query)
    if rule.kind == "cidr":
        return target.ip is not None and target.ip in rule.value
    return False
