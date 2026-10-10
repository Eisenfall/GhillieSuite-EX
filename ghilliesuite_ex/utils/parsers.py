"""
ghilliesuite_ex/utils/parsers.py
─────────────────────
Structured output parsers for every tool in the arsenal.

CRITICAL DESIGN RULE:
  Raw tool output is NEVER sent to the LLM.
  Each parser distills stdout into a list of small, typed dicts that:
    1. Are written to the SQLite DB as Host/Endpoint/Finding records.
    2. Are summarised compactly by StateDB.get_summary_for_ai().

FILE I/O PARSERS:
  parse_subfinder() and parse_httpx() can accept a Path to an output file
  written by the tool (via -o or -json -o flags). This is the preferred mode
  for reliable output capture. Pass output_path=Path("...") to activate.
  Falling back to a raw string is still supported for backwards compatibility.

URL FILTERING (parse_katana, parse_gau):
  Static assets (images, fonts, CSS, sourcemaps, etc.) are silently dropped.
  Only URLs that contain parameters (?key=val) or match high-value API/auth
  path patterns are stored. This reduces DB noise and LLM token waste.

HOW TO ADD A PARSER FOR A NEW TOOL:
  1. Add a function named  parse_<tool_name>(output: str, **kwargs) -> list[dict]
  2. Add a corresponding ToolSpec.parser = "<tool_name>" in arsenal.py.
  3. The ExploitAgent/ReconAgent will automatically call it via get_parser().
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


# ── Static asset denylist — URLs matching these extensions are dropped ─────────
STATIC_EXT_DENYLIST: frozenset[str] = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".ico", ".svg", ".avif",
    ".mp4", ".mp3", ".mov", ".avi", ".webm",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css",
    ".map",   # JS sourcemaps — no logic
    ".pdf", ".zip", ".tar", ".gz", ".rar",
})

# Path fragments that always indicate a high-value endpoint regardless of params
_HIGH_VALUE_PATH_FRAGMENTS: tuple[str, ...] = (
    "/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/gql",
    "/rest/", "/admin", "/dashboard", "/login", "/logout",
    "/auth", "/oauth", "/signin", "/signup", "/register",
    "/user", "/account", "/profile", "/me/",
    "/order", "/payment", "/checkout",
    "/upload", "/import", "/export", "/download",
    "/config", "/settings", "/debug",
    "/webhook", "/callback", "/redirect",
)

# Keywords in page title or tech stack that suggest an AI/LLM surface
_AI_TECH_KEYWORDS: tuple[str, ...] = (
    "chatgpt", "openai", "gemini", "claude", "copilot",
    "llm", "chatbot", "assistant", "gpt",
    "langchain", "llama", "mistral", "huggingface",
    "ai chat", "ai assistant",
)


# ── Third-Party & CDN Denylist ────────────────────────────────────────────────
# NOTE: wp-content/plugins and /assets/ intentionally NOT blacklisted:
#   - wp-content/plugins is the #1 attack surface for WordPress bug bounty
#   - /assets/ can contain config.json, .env, and other sensitive files
_CDN_BLACKLIST: tuple[str, ...] = (
    "shopifycloud", "wp-includes",
    "cdn.", "fonts.googleapis", "cdnjs.cloudflare",
    "ajax.googleapis", "unpkg.com", "jsdelivr.net",
)

def is_high_value_url(url: str) -> bool:
    """
    Return True if this URL is worth storing and testing.

    Rules (any one match is sufficient):
      1. Has a query string with at least one parameter.
      2. Path contains a high-value API/auth/admin fragment.

    Static asset extensions are NEVER high-value regardless of other rules
    — the caller is responsible for pre-filtering with has_static_extension().
    NOTE: Also drops known CDNs using _CDN_BLACKLIST.
    """
    url_lower = url.lower()

    # Drop known CDN/Third-party noise
    if any(cdn in url_lower for cdn in _CDN_BLACKLIST):
        return False

    # Rule 0: Keep JS assets for secret/sink analysis (even without params)
    try:
        import urllib.parse
        if urllib.parse.urlparse(url).path.lower().endswith(".js"):
            return True
    except Exception:
        if url_lower.endswith(".js") or ".js?" in url_lower:
            return True

    # Rule 1: has parameters
    if "?" in url:
        return True
    # Rule 2: high-value path
    for fragment in _HIGH_VALUE_PATH_FRAGMENTS:
        if fragment in url_lower:
            return True
    return False


def has_static_extension(url: str) -> bool:
    """Return True if the URL path ends with a known static asset extension.
    Uses urllib.parse to aggressively bypass .js?v=123 spoofing."""
    import urllib.parse
    try:
        # urlparse safely separates out the exact path string, ignoring query params and fragments
        parsed_path = urllib.parse.urlparse(url).path.lower()
        suffix = Path(parsed_path).suffix
        return suffix in STATIC_EXT_DENYLIST
    except Exception:
        return False


def detect_ai_tech(title: str = "", tech_stack: str = "", server: str = "") -> bool:
    """
    Return True if the combined page metadata suggests an AI/LLM-backed service.
    Used by parse_httpx() to set the ai_detected flag on host records.
    """
    combined = f"{title} {tech_stack} {server}".lower()
    return any(kw in combined for kw in _AI_TECH_KEYWORDS)


# ── Helper ────────────────────────────────────────────────────────────────────

def get_parser(tool_name: str):
    """Return the parser function for a given tool name, or a passthrough."""
    parsers = {
        "subfinder":  parse_subfinder,
        "httpx":      parse_httpx,
        "katana":     parse_katana,
        "gau":        parse_gau,
        "nuclei":     parse_nuclei,
        "dalfox":     parse_dalfox,
        "sqlmap":     parse_sqlmap,
        "trufflehog": parse_trufflehog,
        "ffuf":       parse_ffuf,
        "dnsx":       parse_dnsx,
        "naabu":      parse_naabu,
        "arjun":      parse_arjun,
        "subzy":      parse_subzy,
        "gowitness":  parse_gowitness,
    }
    return parsers.get(tool_name, _passthrough)


def _passthrough(output: str, **kwargs) -> list[dict[str, Any]]:
    """Default parser: split output into lines."""
    return [{"line": line} for line in output.splitlines() if line.strip()]


def _load_output_text(output: str = "", output_path: Path | None = None) -> str:
    """Read parser input from a tool output file when present, else use stdout."""
    if output_path and output_path.exists():
        try:
            return output_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return output
    return output


# ── Recon Parsers ─────────────────────────────────────────────────────────────

def parse_subfinder(output: str = "", output_path: Path | None = None) -> list[dict[str, Any]]:
    """
    Parse subfinder output.  Preferred mode: read from -o output file.
    Fallback: parse raw stdout string.

    subfinder -silent -o produces one subdomain per line.
    Returns: [{"domain": str}, ...]
    """
    text = _load_output_text(output=output, output_path=output_path)

    results = []
    for line in text.splitlines():
        line = line.strip()
        if line and "." in line:
            results.append({"domain": line.lower()})
    return results


def parse_httpx(output: str = "", output_path: Path | None = None) -> list[dict[str, Any]]:
    """
    Parse httpx JSON output.  Preferred mode: read from -json -o output file.

    Each JSON object contains:
      url, status-code, webserver, title, technologies, host
    Also detects AI/LLM-backed services and sets ai_detected=True.

    Returns: [{"url", "status_code", "server", "title", "tech_stack", "ai_detected"}, ...]
    """
    text = _load_output_text(output=output, output_path=output_path)

    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        # ── JSON mode (httpx -json) ────────────────────────────────────────
        if line.startswith("{"):
            try:
                data = json.loads(line)
                title     = data.get("title", "")
                tech_list = data.get("technologies", [])
                tech_str  = ",".join(tech_list)
                server    = data.get("webserver", "")
                results.append({
                    "url":          data.get("url", ""),
                    "status_code":  data.get("status-code", 0),
                    "server":       server,
                    "title":        title,
                    "tech_stack":   tech_str,
                    "ai_detected":  detect_ai_tech(title, tech_str, server),
                })
                continue
            except json.JSONDecodeError:
                pass

        # ── Fallback: text output (httpx -silent -status-code -title) ─────
        url_match = re.match(r"(https?://\S+)", line)
        if not url_match:
            continue
        url = url_match.group(1)
        status_match = re.search(r"\[(\d{3})\]", line)
        status = int(status_match.group(1)) if status_match else 0
        brackets = re.findall(r"\[([^\]]+)\]", line)
        title = brackets[1] if len(brackets) > 1 else ""
        tech  = brackets[2] if len(brackets) > 2 else ""

        results.append({
            "url":         url,
            "status_code": status,
            "server":      "",
            "title":       title,
            "tech_stack":  tech,
            "ai_detected": detect_ai_tech(title, tech),
        })
    return results


def parse_katana(output: str = "", output_path: Path | None = None, **kwargs) -> list[dict[str, Any]]:
    """
    Parse katana crawl output — supports both JSONL file-based output (preferred)
    and plain text line-delimited output (backwards compatibility).

    With -j flag (JSONL mode), each line is a JSON object:
      {"timestamp":"...", "request":{"method":"GET","endpoint":"..."}, "response":{"status": 200}}

    Smart filtering applied:
      - Static asset extensions are dropped entirely.
      - Only high-value URLs (with params or API paths) are stored.
      - JS files are always kept (for secret/sink analysis in ExploitAgent).

    Returns: [{"url": str, "params": str, "method": str, "status_code": int, "source": str}, ...]
    """
    text = _load_output_text(output=output, output_path=output_path)

    seen: set[str] = set()
    results = []

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        url = ""
        method = "GET"
        status_code = 0
        source = ""

        # ── JSONL mode (katana -j) ─────────────────────────────────────────
        if line.startswith("{"):
            try:
                data = json.loads(line)
                req = data.get("request", {})
                resp = data.get("response", {})
                url = req.get("endpoint", "") or data.get("url", "")
                method = (req.get("method", "") or "GET").upper()
                status_code = int(resp.get("status", 0) or 0)
                source = data.get("source", "")
            except (json.JSONDecodeError, TypeError, ValueError):
                url = line if line.startswith("http") else ""

        # ── Plain text mode (katana without -j) ───────────────────────────
        elif line.startswith("http"):
            url = line

        if not url or url in seen:
            continue
        seen.add(url)

        # Filter out static assets (but keep .js for ExploitAgent analysis)
        if has_static_extension(url):
            continue

        # Only keep high-value URLs
        if not is_high_value_url(url):
            continue

        param_match = re.search(r"\?([^#]+)", url)
        params = ""
        if param_match:
            params = ",".join(
                kv.split("=")[0]
                for kv in param_match.group(1).split("&")
                if kv
            )

        results.append({
            "url":         url,
            "params":      params,
            "method":      method,
            "status_code": status_code,
            "source":      source,
        })

    return results


def parse_gau(output: str, **kwargs) -> list[dict[str, Any]]:
    """
    Parse gau URL output (one URL per line, many duplicates).

    Smart filtering applied (same rules as parse_katana):
      - Static asset extensions are dropped.
      - Only parameterised or high-value API/auth URLs are returned.

    Returns: [{"url": str, "params": str}, ...]
    """
    seen: set[str] = set()
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("http") or line in seen:
            continue
        seen.add(line)

        # Filter out static assets
        if has_static_extension(line):
            continue

        # Only keep high-value URLs
        if not is_high_value_url(line):
            continue

        param_match = re.search(r"\?([^#]+)", line)
        params = ""
        if param_match:
            params = ",".join(
                kv.split("=")[0]
                for kv in param_match.group(1).split("&")
                if kv
            )
        results.append({"url": line, "params": params})
    return results


# ── Vuln Scan Parsers ─────────────────────────────────────────────────────────

def parse_nuclei(output: str, **kwargs) -> list[dict[str, Any]]:
    """
    nuclei -json outputs one JSON object per line.
    Each line: {"templateID", "type", "severity", "matched-at", "info": {...}}
    Returns: [{"severity", "template_id", "name", "matched_url", "description"}, ...]
    """
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
            results.append({
                "severity":    data.get("info", {}).get("severity", "info").lower(),
                "template_id": data.get("templateID", data.get("template-id", "")),
                "name":        data.get("info", {}).get("name", ""),
                "matched_url": data.get("matched-at", ""),
                "description": data.get("info", {}).get("description", ""),
                "reference":   ",".join(data.get("info", {}).get("reference", [])),
                "request":     data.get("request", ""),
                "response":    data.get("response", ""),
            })
        except json.JSONDecodeError:
            # nuclei sometimes prints non-JSON status lines; skip them
            pass
    return results


# ── Exploitation Parsers ──────────────────────────────────────────────────────

def parse_dalfox(output: str, **kwargs) -> list[dict[str, Any]]:
    """
    dalfox --format json outputs a JSON array or one JSON object per line.
    Returns: [{"type", "url", "payload", "evidence"}, ...]
    """
    results = []
    # Try to parse as a full JSON array first
    try:
        data = json.loads(output)
        if isinstance(data, list):
            for item in data:
                url_val = item.get("data", "").strip()
                if not url_val:
                    continue  # Skip empty or malformed payload records
                results.append({
                    "type":     item.get("type", "XSS"),
                    "url":      url_val,
                    "payload":  item.get("payload", ""),
                    "evidence": item.get("evidence", ""),
                })
            return results
    except (json.JSONDecodeError, TypeError):
        pass

    # Fallback: parse line by line
    for line in output.splitlines():
        line = line.strip()
        if "[V]" in line or "[POC]" in line:
            url_match = re.search(r"https?://\S+", line)
            results.append({
                "type":     "XSS",
                "url":      url_match.group(0) if url_match else "",
                "payload":  "",
                "evidence": line[:300],
            })
    return results


def parse_sqlmap(output: str, **kwargs) -> list[dict[str, Any]]:
    """
    sqlmap --batch text output - detect injection points.
    Returns: [{"param", "technique", "dbms", "payload", "evidence"}, ...]
    """
    results = []
    current: dict[str, Any] = {}
    for line in output.splitlines():
        line = line.strip()
        lower = line.lower()
        if "parameter" in lower and ("appears to be" in lower or "is vulnerable" in lower):
            param_match = re.search(r"(?:parameter|Parameter)['\s]+(['\w]+)['\s]+(?:appears|is)", line)
            if param_match:
                if current.get("param"):
                    results.append({**current})
                    current = {}
                current["param"] = param_match.group(1)
        if "technique:" in lower:
            current["technique"] = line.split(":", 1)[-1].strip()
        if lower.startswith("payload:"):
            current["payload"] = line.split(":", 1)[-1].strip()
        if "back-end dbms:" in lower or "web application technology:" in lower:
            current["dbms"] = line.split(":", 1)[-1].strip()
            current["evidence"] = line

    if current.get("param"):
        results.append(current)

    return results


def parse_ffuf(output: str = "", output_path: Path | None = None, **kwargs) -> list[dict[str, Any]]:
    """
    Parse ffuf JSON output.  Preferred mode: read from -of json -o output file.

    ffuf JSON schema (top-level "results" array):
      {"results": [{"url", "status", "length", "lines", "words", "input": {...}}, ...]}

    Returns: [{"url": str, "status": int, "length": int, "lines": int}, ...]
    """
    text = _load_output_text(output=output, output_path=output_path)

    if not text.strip():
        return []

    try:
        data = json.loads(text)
        raw_results = data.get("results", [])
        return [
            {
                "url":    item.get("url", ""),
                "status": item.get("status", 0),
                "length": item.get("length", 0),
                "lines":  item.get("lines", 0),
            }
            for item in raw_results
            if item.get("url")
        ]
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass

    # Fallback: ffuf sometimes writes one JSON object per line
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
            if item.get("url"):
                results.append({
                    "url":    item.get("url", ""),
                    "status": item.get("status", 0),
                    "length": item.get("length", 0),
                    "lines":  item.get("lines", 0),
                })
        except json.JSONDecodeError:
            pass
    return results


# ── Cloud / Secret Parsers ────────────────────────────────────────────────────

def parse_trufflehog(output: str, **kwargs) -> list[dict[str, Any]]:
    """
    trufflehog --json outputs one JSON object per line.
    Returns: [{"secret_type", "raw_value_redacted", "source", "url"}, ...]
    """
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
            raw = data.get("Raw", data.get("raw", ""))
            redacted = raw[:4] + "…" + raw[-4:] if len(raw) > 8 else "[redacted]"
            results.append({
                "secret_type":        data.get("DetectorName", data.get("detector_name", "Unknown")),
                "raw_value_redacted": redacted,
                "source":             data.get("SourceMetadata", {}).get("Data", {}).get("Github", {}).get("repository", ""),
                "url":                data.get("SourceMetadata", {}).get("Data", {}).get("Github", {}).get("link", ""),
                "verified":           bool(data.get("Verified", data.get("verified", False))),
            })
        except json.JSONDecodeError:
            pass
    return results


# -------- New Recon Parsers --------

def parse_dnsx(output: str = "", output_path: Path | None = None) -> list[dict[str, Any]]:
    """
    Parse dnsx output.
    JSON lines expected with keys like: host/domain, ip.
    Fallback: "domain ip" or "ip domain" per line.
    Returns: [{"domain": str, "ip": str}, ...]
    """
    text = _load_output_text(output=output, output_path=output_path)

    results: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                data = json.loads(line)
                domain = data.get("host") or data.get("domain") or data.get("name") or ""
                ip = data.get("ip") or data.get("a") or data.get("address") or ""
                if isinstance(ip, (list, tuple)):
                    ip = ",".join(str(x) for x in ip if x)
                if domain and ip:
                    results.append({"domain": domain, "ip": ip})
                continue
            except json.JSONDecodeError:
                pass
        # Fallback line parsing
        parts = line.split()
        if len(parts) >= 2:
            a, b = parts[0].strip(), parts[1].strip()
            # Heuristic: IP contains digits and dots
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", a):
                results.append({"domain": b, "ip": a})
            elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", b):
                results.append({"domain": a, "ip": b})
    return results


def parse_naabu(output: str = "", output_path: Path | None = None) -> list[dict[str, Any]]:
    """
    Parse naabu output.
    JSON lines expected with keys like: host, ip, port, protocol.
    Fallback: "host:port" or "ip:port" per line.
    Returns: [{"host": str, "ip": str, "port": int, "proto": str}, ...]
    """
    text = _load_output_text(output=output, output_path=output_path)

    results: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                data = json.loads(line)
                host = data.get("host") or data.get("hostname") or data.get("ip") or ""
                ip = data.get("ip") or ""
                port = int(data.get("port") or 0)
                proto = (data.get("protocol") or data.get("proto") or "tcp").lower()
                if host and port:
                    results.append({"host": host, "ip": ip, "port": port, "proto": proto})
                continue
            except (json.JSONDecodeError, ValueError, TypeError):
                pass
        # Fallback: host:port
        if ":" in line:
            host_part, port_part = line.rsplit(":", 1)
            try:
                port = int(port_part.strip())
            except ValueError:
                continue
            results.append({"host": host_part.strip(), "ip": "", "port": port, "proto": "tcp"})
    return results


def parse_arjun(output: str = "", output_path: Path | None = None) -> list[dict[str, Any]]:
    """
    Parse arjun output.
    JSON expected via -oJ: list of objects with url/endpoint, method, and params.
    Fallback: line parsing of "URL: param1, param2".
    Returns: [{"url": str, "method": str, "params": list[str]}]
    """
    text = _load_output_text(output=output, output_path=output_path)

    results: list[dict[str, Any]] = []
    # Try JSON as full document first
    try:
        data = json.loads(text)
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                url = item.get("url") or item.get("endpoint") or ""
                method = (item.get("method") or "GET").upper()
                params = item.get("params") or item.get("parameters") or []
                if isinstance(params, str):
                    params = [p.strip() for p in params.split(",") if p.strip()]
                if url and params:
                    results.append({"url": url, "method": method, "params": params})
            return results
        if isinstance(data, dict):
            # Common variants:
            # 1) {"results": [{"url": "...", "params": [...]}, ...]}
            # 2) {"https://example.com": ["p1","p2"], ...}
            if isinstance(data.get("results"), list):
                for item in data["results"]:
                    if not isinstance(item, dict):
                        continue
                    url = item.get("url") or item.get("endpoint") or ""
                    method = (item.get("method") or "GET").upper()
                    params = item.get("params") or item.get("parameters") or []
                    if isinstance(params, str):
                        params = [p.strip() for p in params.split(",") if p.strip()]
                    if url and params:
                        results.append({"url": url, "method": method, "params": params})
                if results:
                    return results
            for key, val in data.items():
                if isinstance(val, (list, tuple)) and isinstance(key, str) and key.startswith("http"):
                    params = [str(p).strip() for p in val if str(p).strip()]
                    if params:
                        results.append({"url": key, "method": "GET", "params": params})
            if results:
                return results
    except (json.JSONDecodeError, TypeError):
        pass

    # Fallback: line parsing
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Example: "https://example.com/api: param1, param2"
        if ": " in line and line.startswith(("http://", "https://")):
            url, param_text = line.rsplit(": ", 1)
            params = [p.strip() for p in param_text.split(",") if p.strip()]
            if url and params:
                results.append({"url": url, "method": "GET", "params": params})
    return results


def parse_subzy(output: str = "", output_path: Path | None = None) -> list[dict[str, Any]]:
    """
    Parse subzy output (subdomain takeover checks).
    JSON lines expected with domain/status fields.
    Fallback: detect "VULNERABLE" lines.
    Returns: [{"domain": str, "status": str, "service": str, "vulnerable": bool}]
    """
    text = _load_output_text(output=output, output_path=output_path)

    results: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                data = json.loads(line)
                domain = data.get("domain") or data.get("host") or ""
                status = data.get("status") or data.get("result") or ""
                # FIXED: extract service field from JSON data (P2 fix)
                service = data.get("service") or data.get("provider") or data.get("fingerprint") or ""
                vuln = data.get("vulnerable") is True or bool(re.search(r"(?<!not )\bvulnerable\b", status, re.I))
                if domain:
                    results.append({"domain": domain, "status": status, "service": service, "vulnerable": vuln})
                continue
            except json.JSONDecodeError:
                pass
        upper = line.upper()
        if re.search(r"(?<!NOT )\bVULNERABLE\b", upper):
            m = re.search(r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", line)
            if m:
                results.append({"domain": m.group(1), "status": "VULNERABLE", "service": "", "vulnerable": True})
    return results


def parse_gowitness(output: str = "", output_path: Path | None = None) -> list[dict[str, Any]]:
    """
    Parse gowitness JSON report if enabled.
    Returns: [{"url": str, "screenshot": str, "title": str, "status": int}]
    """
    text = _load_output_text(output=output, output_path=output_path)

    if not text.strip():
        return []

    results: list[dict[str, Any]] = []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                results.append({
                    "url": item.get("url", ""),
                    "screenshot": item.get("screenshot", "") or item.get("screenshot_path", ""),
                    "title": item.get("title", ""),
                    "status": int(item.get("status") or 0),
                })
            return results
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    # Fallback: JSON lines
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
            results.append({
                "url": item.get("url", ""),
                "screenshot": item.get("screenshot", "") or item.get("screenshot_path", ""),
                "title": item.get("title", ""),
                "status": int(item.get("status") or 0),
            })
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
    return results
