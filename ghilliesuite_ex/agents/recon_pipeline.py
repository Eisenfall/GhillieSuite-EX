"""
Pure recon pipeline helpers for target selection and delta scheduling.

These functions keep ReconAgent focused on orchestration while preserving the
current selection behavior for httpx, katana, and arjun.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ghilliesuite_ex.utils.scope import ScopeSpec, filter_in_scope, is_in_scope, scope_has_url_rules

_ARJUN_STATIC_EXTS = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp",
    ".css", ".js", ".map",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".ico", ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".mp4", ".mp3", ".avi", ".mov", ".mkv",
)
_ARJUN_SEO_PATHS = ("/page/", "/wp-content/", "/author/", "/tag/", "/category/")
_ARJUN_PRIORITY_MARKERS = (".php", ".aspx", "/api/")


def dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def build_httpx_targets(subdomains: list[str], scope: list[str], root_target: str = "") -> list[str]:
    targets: list[str] = []
    if root_target.startswith(("http://", "https://")):
        targets.append(root_target)
    elif root_target:
        targets.extend((f"http://{root_target}", f"https://{root_target}"))
    for domain in subdomains:
        targets.append(f"http://{domain}")
        targets.append(f"https://{domain}")
    return dedupe_preserve_order(filter_in_scope(targets, scope))


def build_katana_candidates(live_urls: list[str], scope: list[str] | None = None) -> list[str]:
    candidates: list[str] = []
    for url in live_urls:
        parsed = urlsplit(url)
        if not parsed.scheme or not parsed.netloc:
            continue
        origin = f"{parsed.scheme}://{parsed.netloc}"
        seed = origin if scope is None or is_in_scope(origin, scope) else url
        if scope is None or is_in_scope(seed, scope):
            candidates.append(seed)
    return dedupe_preserve_order(candidates)


def katana_crawl_safe_for_scope(scope: ScopeSpec | list[str]) -> bool:
    """Katana's host/redirect flags cannot enforce URL path exclusions."""
    return not scope_has_url_rules(scope)


def select_katana_targets(
    candidates: list[str],
    *,
    history: set[str],
    last_crawl_run: dict[str, int],
    recon_run_count: int,
    recrawl_interval: int,
    max_targets: int,
) -> list[str]:
    delta: list[str] = []
    for url_target in candidates:
        if url_target not in history:
            delta.append(url_target)
            continue
        last_run = int(last_crawl_run.get(url_target, 0) or 0)
        if (recon_run_count - last_run) >= recrawl_interval:
            delta.append(url_target)
    return delta[:max_targets]


def is_arjun_priority(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return any(marker in path for marker in _ARJUN_PRIORITY_MARKERS)


def is_arjun_candidate(url: str) -> bool:
    path = urlsplit(url).path.lower()
    if not path:
        return False
    if any(path.endswith(ext) for ext in _ARJUN_STATIC_EXTS):
        return False
    if not is_arjun_priority(url):
        if any(seg in path for seg in _ARJUN_SEO_PATHS):
            return False
        if path.endswith("/"):
            return False
    return True


def get_arjun_base_path(url: str) -> str:
    """Extract a base path used to deduplicate similar arjun targets."""
    parts = urlsplit(url)
    path = parts.path
    if not path or path == "/":
        return f"{parts.scheme}://{parts.netloc}/"

    segments = [segment for segment in path.split("/") if segment]
    if segments:
        last = segments[-1]
        if "." in last or len(last) > 20:
            segments = segments[:-1]

    base_path = "/".join(segments)
    return f"{parts.scheme}://{parts.netloc}/{base_path}"


def select_arjun_targets(
    new_endpoints: list[str],
    *,
    history: set[str],
    scope: list[str],
    limit: int = 20,
) -> list[str]:
    raw_targets = [url for url in new_endpoints if url and url not in history]
    raw_targets = [url for url in raw_targets if is_in_scope(url, scope)]
    filtered_targets = [url for url in raw_targets if is_arjun_candidate(url)]
    filtered_targets = dedupe_preserve_order(filtered_targets)

    seen_bases: set[str] = set()
    blitz_targets: list[str] = []
    for url in filtered_targets:
        base = get_arjun_base_path(url)
        if base in seen_bases:
            continue
        seen_bases.add(base)
        blitz_targets.append(url)

    priority_targets = [url for url in blitz_targets if is_arjun_priority(url)]
    other_targets = [url for url in blitz_targets if url not in priority_targets]
    return (priority_targets + other_targets)[:limit]
