"""
ghilliesuite_ex/arsenal.py
───────────────
Tool Registry — the single source of truth for every binary GhillieSuite-EX can invoke.

HOW TO EXTEND:
  1. Add an entry to TOOL_REGISTRY with the tool name as the key.
  2. Fill in a ToolSpec (see the dataclass below for all fields).
  3. Add a matching parser function in ghilliesuite_ex/utils/parsers.py named parse_<tool_name>.
  4. Set hitl_required=True for ANY tool that sends active traffic or payloads.
  5. Done — the Supervisor AI will automatically discover and use the new tool via
     the description injected into its system prompt.

AUTH INJECTION:
  build_command() accepts optional auth_headers which are injected into tools
  that support the -H flag (httpx, katana, nuclei, dalfox, sqlmap).
  Pass as a flat list of header flag pairs: ["-H", "Cookie: ...", "-H", "Authorization: ..."]

FILE I/O:
  Tools marked with output_flag will write their results to disk instead of stdout.
  Use run_tool_to_file() from executor.py and pass the output path.
  Placeholder {output_file} is filled by build_command().
  Placeholder {input_file} is filled by build_command() for tools that read a list (httpx -l).
"""

from __future__ import annotations

import importlib.util
import hashlib
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from rich.table import Table


# ── Tools that accept auth headers via -H flag ────────────────────────────────
_AUTH_HEADER_TOOLS = frozenset({"httpx", "katana", "nuclei", "dalfox", "sqlmap"})
_REQUIRED_TOOL_NAMES = ("subfinder", "katana", "httpx", "nuclei")
_OPTIONAL_DEPENDENCIES: tuple[tuple[str, str], ...] = (
    ("playwright", "Python module for optional browser-backed checks"),
)
_PROFILE_DISABLED_TOOLS: dict[str, tuple[str, ...]] = {
    "vdp-safe": ("nuclei", "dalfox", "sqlmap", "ffuf", "trufflehog"),
    "balanced": (),
    "aggressive": (),
}

# ── Default short wordlist for ffuf (bundled fallback) ────────────────────────
# ── Default short wordlist for ffuf (bundled fallback) ────────────────────────
_BUNDLED_WORDLIST = str(
    Path(__file__).parent / "resources" / "common_dirs.txt"
)

# ── Tech-specific Smart Wordlists ─────────────────────────────────────────────
_PHP_WORDLIST = [
    ".env", ".env.example", ".env.backup", ".env.dev",
    "artisan", "telescope", "composer.json", "composer.lock",
    "config/database.php", "storage/logs/laravel.log"
]

_JAVA_SPRING_WORDLIST = [
    "actuator", "actuator/env", "actuator/heapdump", 
    "actuator/threaddump", "actuator/health", "jolokia",
    "WEB-INF/web.xml", "swagger-ui.html", "v2/api-docs"
]

_NODEJS_WORDLIST = [
    "package.json", "package-lock.json", "yarn.lock",
    "node_modules", ".npmrc", "tsconfig.json", "server.js",
    "app.js", ".env"
]

# ── Stealth Mode Overrides ────────────────────────────────────────────────────
# Applied when cfg.stealth_mode is True or build_command(..., stealth=True)
_STEALTH_ARGS: dict[str, list[str]] = {
    "nuclei": ["-rl", "15", "-c", "5", "-bs", "1", "-timeout", "5"],
    "sqlmap": ["--delay=1", "--threads=1", "--random-agent"],
    "ffuf":   ["-t", "1", "-p", "0.5"],
    "dirb":   ["-t", "1", "-p", "0.5"],
    "naabu":  ["-rate", "100", "-top-ports", "100"],
    "katana": ["-rl", "5", "-delay", "1"],    # Low-and-slow crawl: 5 req/s + 1s between pages
}

# Extended stealth args applied when WAF evasion mode is enabled
_WAF_EVASION_STEALTH_ARGS: dict[str, list[str]] = {
    "sqlmap": ["--delay=3", "--threads=1", "--fail-on-tarpit", "--random-agent", "--tamper=between,randomcase,space2comment"],
    "httpx":  ["-random-agent", "-http2", "-tls-probe", "-v", "-retries", "3"],
    "nuclei": ["-rl", "10", "-c", "5", "-bs", "1", "-timeout", "10", "-max-host-error", "3"],
}

# SQLMap lethal extraction and WAF fallback arg sets
SQLMAP_LETHAL_ARGS = ["--dbs"]
SQLMAP_WAF_FALLBACK_ARGS = ["--tamper=space2comment,randomcase", "--random-agent"]


def apply_stealth_args(tool_name: str, cmd: list[str], enabled: bool) -> list[str]:
    """
    Inject conservative rate-limiting arguments for WAF avoidance.
    Removes existing conflicting flags before appending stealth args.
    """
    if not enabled or tool_name not in _STEALTH_ARGS:
        return list(cmd)

    cleaned: list[str] = []
    skip_next = False
    for tok in cmd:
        if skip_next:
            skip_next = False
            continue

        if tool_name == "sqlmap":
            if tok in ("--delay", "--threads", "--timeout"):
                skip_next = True
                continue
            if tok.startswith(("--delay=", "--threads=", "--timeout=")):
                continue
        elif tool_name in ("nuclei",):
            if tok in ("-rl", "-c", "-bs", "-timeout"):
                skip_next = True
                continue
        elif tool_name in ("ffuf", "dirb"):
            if tok in ("-t", "-p", "-c", "--concurrency"):
                skip_next = True
                continue
        elif tool_name == "katana":
            if tok in ("-rl", "-delay", "-c", "--concurrency"):
                skip_next = True
                continue
        
        cleaned.append(tok)

    stealth_args = _STEALTH_ARGS[tool_name]
    if tool_name == "nuclei":
        try:
            from ghilliesuite_ex.config import cfg as _cfg
            timeout = max(1, int(getattr(_cfg, "nuclei_http_timeout", 5)))
        except Exception:
            timeout = 5
        stealth_args = list(stealth_args)
        if "-timeout" in stealth_args:
            idx = stealth_args.index("-timeout")
            if idx + 1 < len(stealth_args):
                stealth_args[idx + 1] = str(timeout)

    cleaned.extend(stealth_args)
    return cleaned


def apply_turbo_args(tool_name: str, cmd: list[str], enabled: bool) -> list[str]:
    """
    Boost performance flags for VPS/Data Center environments.
    """
    if not enabled:
        return list(cmd)

    # Simple scaling: if turbo is on, we swap the safe defaults for aggressive ones
    turbo_map = {
        "httpx":  [("-rl", "15", "150")],
        "ffuf":   [("-t", "10", "100")],
        "arjun":  [("-t", "5", "30")],
        "sqlmap": [("--threads=3", "--threads=10")],
        "nuclei": [("-rl", "5", "150"), ("-c", "5", "50")],
        "naabu":  [("-rate", "250", "1000"), ("-top-ports", "1000", "1000")],
    }

    if tool_name not in turbo_map:
        return list(cmd)

    new_cmd = list(cmd)
    for target_flag, old_val, new_val in [ (x[0], x[1], x[2]) if len(x)==3 else (x[0], None, x[1]) for x in turbo_map[tool_name] ]:
        for i, tok in enumerate(new_cmd):
            if old_val: # Pair flag (e.g. -rl 15)
                if tok == target_flag and i+1 < len(new_cmd) and new_cmd[i+1] == old_val:
                    new_cmd[i+1] = new_val
            else: # Single flag (e.g. --threads=3)
                if tok == target_flag:
                    new_cmd[i] = new_val
    
    return new_cmd


def _apply_nuclei_tuning(
    cmd: list[str],
    rate_limit: int | None,
    concurrency: int | None,
    http_timeout: int | None,
    severity: str | None = None,
    tags: str | None = None,
) -> list[str]:
    """
    Strip-then-inject Nuclei performance AND filter flags.

    By rebuilding these flags from config rather than the base_cmd,
    we guarantee that config.py / env vars ALWAYS win — no silent
    conflicts from previously hardcoded values.

    Strips: -rl, -c, -timeout, -severity, -tags (and their = variants).
    Then injects each provided value in the correct order.
    """
    # Flags that each consume the next token
    _pair_flags = {"-rl", "-c", "-timeout", "-severity", "-tags", "-bs"}
    # Flags also expressible as -flag=value
    _prefix_flags = ("-rl=", "-c=", "-timeout=", "-severity=", "-tags=", "-bs=")

    cleaned: list[str] = []
    skip_next = False
    for tok in cmd:
        if skip_next:
            skip_next = False
            continue
        if tok in _pair_flags:
            skip_next = True
            continue
        if tok.startswith(_prefix_flags):
            continue
        cleaned.append(tok)

    # Inject in a sensible order: timeout → rate → concurrency → severity → tags
    if http_timeout is not None:
        cleaned.extend(["-timeout", str(max(1, int(http_timeout)))])
    if rate_limit is not None:
        cleaned.extend(["-rl", str(max(1, int(rate_limit)))])
    if concurrency is not None:
        cleaned.extend(["-c", str(max(1, int(concurrency)))])
    if severity:
        cleaned.extend(["-severity", severity.strip()])
    if tags:
        cleaned.extend(["-tags", tags.strip()])

    return cleaned


def _replace_flag_value(cmd: list[str], flag: str, new_value: str) -> list[str]:
    """Replace the value immediately following `flag` in cmd with `new_value`.
    If the flag is not found, appends flag + new_value at the end."""
    new_cmd = list(cmd)
    for i, tok in enumerate(new_cmd):
        if tok == flag and i + 1 < len(new_cmd):
            new_cmd[i + 1] = new_value
            return new_cmd
    # Flag not present — append it
    new_cmd.extend([flag, new_value])
    return new_cmd


@dataclass
class ToolSpec:
    """Describes a single security tool available to the agent swarm."""


    binary: str
    """Executable name on PATH (e.g. 'subfinder', 'nuclei')."""

    base_cmd: list[str]
    """
    Command tokens. Placeholders:
        {target}      – the primary hunt target (domain/URL)
        {output_file} – an output file path that the tool writes to
        {input_file}  – an input file path the tool reads from (e.g. httpx -l)
        {wordlist}    – path to fuzzing wordlist (ffuf)
    These are filled in by build_command() before execution.
    """

    scope_flag: str | None
    """
    How this tool accepts the in-scope domain, e.g. '-d {domain}'.
    Set to None if scope must be enforced via output filtering instead.
    """

    category: str
    """One of: Recon | VulnScan | Exploitation | Cloud"""

    parser: str
    """Name of the parser function in ghilliesuite_ex/utils/parsers.py (parse_<parser>)."""

    hitl_required: bool
    """
    If True the ExploitAgent will call hitl_prompt() before executing this tool
    and will abort silently if the user answers 'n'.
    Set True for ANYTHING that sends active exploit payloads.
    """

    description: str
    """One-line description injected into the AI system prompt so the LLM
    knows when to suggest this tool."""

    uses_output_file: bool = False
    """If True, build_command() expects callers to pass output_file kwarg."""

    uses_input_file: bool = False
    """If True, build_command() expects callers to pass input_file kwarg."""

    supports_auth_headers: bool = field(init=False)

    def __post_init__(self) -> None:
        self.supports_auth_headers = self.binary in _AUTH_HEADER_TOOLS


@dataclass(frozen=True)
class OptionalDependencyStatus:
    name: str
    description: str
    installed: bool


@dataclass(frozen=True)
class ToolingStatus:
    profile: str
    installed: dict[str, bool]
    required_tools: tuple[str, ...]
    optional_tools: tuple[str, ...]
    disabled_by_profile: tuple[str, ...]
    optional_dependencies: tuple[OptionalDependencyStatus, ...]


# ── Registry ──────────────────────────────────────────────────────────────────
TOOL_REGISTRY: dict[str, ToolSpec] = {

    # ── Recon & Discovery ─────────────────────────────────────────────────────

    "subfinder": ToolSpec(
        binary="subfinder",
        base_cmd=["subfinder", "-d", "{target}", "-silent", "-all", "-o", "{output_file}"],
        scope_flag="-d {target}",
        category="Recon",
        parser="subfinder",
        hitl_required=False,
        uses_output_file=True,
        description="Passive subdomain enumeration using many sources (certsh, virustotal, etc.). Writes results to a file.",
    ),

    "dnsx": ToolSpec(
        binary="dnsx",
        base_cmd=["dnsx", "-l", "{input_file}", "-json", "-o", "{output_file}"],
        scope_flag=None,
        category="Recon",
        parser="dnsx",
        hitl_required=False,
        uses_output_file=True,
        uses_input_file=True,
        description="DNS resolution for subdomains; returns domain->IP mappings.",
    ),

    "naabu": ToolSpec(
        binary="naabu",
        base_cmd=[
            "naabu", "-list", "{input_file}", "-json", "-o", "{output_file}",
            "-top-ports", "1000", "-silent", "-rate", "250",
        ],
        scope_flag=None,
        category="Recon",
        parser="naabu",
        hitl_required=False,
        uses_output_file=True,
        uses_input_file=True,
        description="Fast port discovery for discovered hosts; JSON output for parsing.",
    ),

    "httpx": ToolSpec(
        binary="httpx",
        base_cmd=[
            "httpx",
            "-l", "{input_file}",
            "-silent", "-status-code", "-title", "-tech-detect",
            "-random-agent",       # WAF bypass: rotate User-Agent per request
            "-http2",              # Evasion: use modern protocol
            "-tls-probe",          # Evasion: probe TLS fingerprints
            "-insecure",           # Evasion: ignore invalid SSL certificates
            "-retries", "2",       # retry failed probes instead of silently dropping
            "-rl", "15",           # rate-limit to 15 req/s — SAFE for home routers
            "-json", "-o", "{output_file}",
        ],
        # httpx reads from -l file; scope enforced by feeding only in-scope hosts
        scope_flag=None,
        category="Recon",
        parser="httpx",
        hitl_required=False,
        uses_output_file=True,
        uses_input_file=True,
        description="HTTP probe — resolves hosts, detects status, server, tech stack, and page title. WAF-resilient: random-agent + retries + rate limit. JSON file output.",
    ),

    "katana": ToolSpec(
        binary="katana",
        base_cmd=[
            "katana", "-u", "{target}",
            "-silent",
            "-fs", "fqdn",
            "-dr",
            "-d", "{katana_depth}",  # depth injected by build_command from cfg.katana_depth
            "-jc",                    # parse inline JS
            "-j",                     # JSONL output format (richer metadata: method, source, params)
            "-o", "{output_file}",   # file-based output — eliminates stdout truncation
            "-ct", "5m",
            "-rl", "{katana_rl}",    # rate limit injected from cfg.katana_rate_limit
            "-f", "qurl",
            "-ef",
            "css,png,jpg,jpeg,svg,woff,woff2,ico,webp,gif,map,mp4,pdf,"
            "bmp,tif,tiff,ttf,otf,eot,mp3,wav,ogg,webm,m4a,m4v,avi,mov,mkv,"
            "zip,rar,7z,tar,gz,tgz,bz2,iso,exe,dmg,apk",
            "-exclude-path", "product/,image/,images/,assets/,static/,media/,node_modules/,vendor/",
        ],
        scope_flag="-u {target}",
        category="Recon",
        parser="katana",
        hitl_required=False,
        uses_output_file=True,  # switched to file-based JSONL output
        description=(
            "Fast web crawler — discovers endpoints, JS files, and form parameters. "
            "JSONL output for reliable parsing. Configurable depth/rate via KATANA_DEPTH/KATANA_RATE_LIMIT. "
            "Set KATANA_HEADLESS=1 for SPA/React/Vue targets (requires playwright)."
        ),
    ),

    "gau": ToolSpec(
        binary="gau",
        base_cmd=["gau", "{target}", "--threads", "5", "--subs"],
        scope_flag=None,  # gau takes domain as positional arg; enforced via scope filter
        category="Recon",
        parser="gau",
        hitl_required=False,
        description="Fetch known URLs from Wayback Machine, Common Crawl, and URLScan.",
    ),

    "arjun": ToolSpec(
        binary="arjun",
        base_cmd=["arjun", "-i", "{input_file}", "-oJ", "{output_file}", "-t", "5"],
        scope_flag=None,
        category="Recon",
        parser="arjun",
        hitl_required=False,
        uses_output_file=True,
        uses_input_file=True,
        description="Fast parameter discovery; uses 10 threads and JSON output.",
    ),

    "subzy": ToolSpec(
        binary="subzy",
        base_cmd=["subzy", "run", "--targets", "{input_file}", "--output", "{output_file}", "--json"],
        scope_flag=None,
        category="Recon",
        parser="subzy",
        hitl_required=False,
        uses_output_file=True,
        uses_input_file=True,
        description="Subdomain takeover detection using fingerprint checks.",
    ),

    "gowitness": ToolSpec(
        binary="gowitness",
        base_cmd=["gowitness", "file", "-f", "{input_file}", "--json", "-o", "{output_file}"],
        scope_flag=None,
        category="Recon",
        parser="gowitness",
        hitl_required=False,
        uses_output_file=True,
        uses_input_file=True,
        description="Captures screenshots of live web endpoints (optional).",
    ),

    # ── Vulnerability Scanning ────────────────────────────────────────────────

    "nuclei": ToolSpec(
        binary="nuclei",
        base_cmd=[
            "nuclei", "-u", "{target}",
            # NOTE: -severity, -tags, -rl, -c, -timeout are NOT hardcoded here.
            # They are injected at runtime by _apply_nuclei_tuning() from config/env.
            # This guarantees that NUCLEI_SEVERITY, NUCLEI_TAGS, NUCLEI_RATE_LIMIT
            # and NUCLEI_CONCURRENCY always take effect without conflicts.
            "-silent", "-j",
        ],
        scope_flag="-u {target}",
        category="VulnScan",
        parser="nuclei",
        hitl_required=True,
        description=(
            "Template-based vulnerability scanner. "
            "Tags: cve,sqli,xss,lfi,ssrf,rce,ssti,xxe + more high-signal BB tags. "
            "Severity: medium,high,critical (info/low dropped as BB noise). "
            "Rate/concurrency driven fully from config: NUCLEI_RATE_LIMIT / NUCLEI_CONCURRENCY."
        ),
    ),

    # ── Active Exploitation (HitL required) ───────────────────────────────────

    "dalfox": ToolSpec(
        binary="dalfox",
        base_cmd=[
            "dalfox", "file", "{target}",
            "--silence", "--format", "json", "-o", "{output_file}", "-w", "50",
            # NOTE: --skip-mining-dom removed to enable DOM XSS detection (BB favorite)
            "--skip-bav", "--skip-mining-dict"
        ],
        scope_flag=None,
        category="Exploitation",
        parser="dalfox",
        hitl_required=True,  # FIXED: dalfox fires active XSS payloads — HitL required
        description="XSS scanner and exploitation tool — discovers reflected, stored, and DOM XSS (Bulk Mode). DOM mining enabled.",
    ),

    "sqlmap": ToolSpec(
        binary="sqlmap",
        base_cmd=[
            "sqlmap", "-u", "{target}",
            "--batch", "--smart", "--threads=3",
            "--keep-alive", "--timeout=10", "--retries=1",
            "--output-dir=.sqlmap_out", "--forms",
        ],
        scope_flag="-u {target}",
        category="Exploitation",
        parser="sqlmap",
        hitl_required=True,  # FIXED: sqlmap writes to target DB — HitL required
        description="SQL injection 'Speedrun' mode: fast, smart, and multi-threaded.",
    ),

    "ffuf": ToolSpec(
        binary="ffuf",
        base_cmd=[
            "ffuf",
            "-w", "{wordlist}",
            "-u", "{target}/FUZZ",
            "-of", "json", "-o", "{output_file}",
            "-mc", "200,204,301,302,307,401,403",
            "-t", "10",
            "-s",  # silent
        ],
        scope_flag=None,
        category="Exploitation",
        parser="ffuf",
        hitl_required=False,  # Directory brute-force is non-destructive; SSRF payloads use force_auto
        uses_output_file=True,
        description=(
            "(?url=, ?path=, ?redirect=). Active SSRF payloads still gated by force_auto."
        ),
    ),

    # ── Cloud / Secret Scanning ───────────────────────────────────────────────

    "trufflehog": ToolSpec(
        binary="trufflehog",
        base_cmd=["trufflehog", "--no-update", "github", "--org={target}", "--json"],
        scope_flag=None,
        category="Cloud",
        parser="trufflehog",
        hitl_required=False,
        description="Scans git repos for leaked secrets, credentials, and API keys.",
    ),
}


def build_command(
    tool_name: str,
    target: str,
    extra_args: list[str] | None = None,
    output_file: str | Path | None = None,
    input_file: str | Path | None = None,
    wordlist: str | None = None,
    auth_headers: list[str] | None = None,
    stealth: bool | None = None,
    allow_redirects: bool | None = None,
    tech_stack: str = "",
) -> list[str]:
    """
    Resolve a ToolSpec's base_cmd by substituting all placeholders.

    Placeholders resolved:
        {target}       → target string
        {output_file}  → str(output_file)  [required if spec.uses_output_file]
        {input_file}   → str(input_file)   [required if spec.uses_input_file]
        {wordlist}     → wordlist or default bundled wordlist (ffuf only)

    Auth injection:
        If auth_headers is provided and the tool supports -H flags,
        the header pairs are appended BEFORE extra_args so they appear
        close to the base invocation.  Example:
            auth_headers=["-H", "Cookie: session=abc", "-H", "Authorization: Bearer xyz"]

    Args:
        tool_name:    Key in TOOL_REGISTRY.
        target:       Domain, URL, or organisation name.
        extra_args:   Additional CLI flags to append.
        output_file:  Path where the tool should write its output (for file-I/O tools).
        input_file:   Path the tool should read its input from (e.g. httpx -l).
        wordlist:     Path to wordlist (ffuf). Falls back to bundled list.
        auth_headers: Flat list of header flag pairs, e.g. ["-H", "Cookie: ..."].
        stealth:      If True, apply conservative rate-limiting overrides.

    Returns:
        A fully-formed list[str] ready for asyncio.create_subprocess_exec.
    """
    spec = TOOL_REGISTRY[tool_name]
    # B-08: use `not output_file` instead of `output_file is None` so that an
    # empty Path("") is also caught (truthy check: Path("") is falsy).
    if spec.uses_output_file and not output_file:
        raise ValueError(f"{tool_name} requires output_file but none was provided")
    if spec.uses_input_file and not input_file:
        raise ValueError(f"{tool_name} requires input_file but none was provided")
    out_str = str(output_file) if output_file else ""
    in_str  = str(input_file)  if input_file  else ""
    
    # Context-Aware Smart Wordlist Selection
    wl_str = wordlist
    if tool_name == "ffuf" and not wl_str:
        tech = tech_stack.lower()
        if any(kw in tech for kw in ("php", "laravel", "symfony")):
            wl_str = _write_temp_wordlist("php", _PHP_WORDLIST)
        elif any(kw in tech for kw in ("java", "spring", "tomcat", "jboss")):
            wl_str = _write_temp_wordlist("java", _JAVA_SPRING_WORDLIST)
        elif any(kw in tech for kw in ("node", "express", "next.js")):
            wl_str = _write_temp_wordlist("node", _NODEJS_WORDLIST)
        else:
            wl_str = _BUNDLED_WORDLIST
    elif not wl_str:
        wl_str = _BUNDLED_WORDLIST

    # Resolve Katana config placeholders before building cmd
    katana_depth_val = "6"
    katana_rl_val = "30"
    if tool_name == "katana":
        try:
            from ghilliesuite_ex.config import cfg as _cfg
            katana_depth_val = str(max(1, int(getattr(_cfg, "katana_depth", 6))))
            katana_rl_val = str(max(1, int(getattr(_cfg, "katana_rate_limit", 30))))
        except Exception:
            pass

    cmd = []
    for tok in spec.base_cmd:
        tok = tok.replace("{target}",       target)
        tok = tok.replace("{output_file}",  out_str)
        tok = tok.replace("{input_file}",   in_str)
        # B-07: only substitute {wordlist} for ffuf — other tools never use
        # this placeholder and a stray match would silently corrupt their args.
        if tool_name == "ffuf":
            tok = tok.replace("{wordlist}", wl_str or "")
        tok = tok.replace("{katana_depth}", katana_depth_val)
        tok = tok.replace("{katana_rl}",    katana_rl_val)
        cmd.append(tok)

    # Auth Injection for sqlmap (special --cookie= flag format)
    # NOTE: For all other tools (httpx, katana, nuclei, ffuf), cookie injection
    # is handled exclusively via auth_headers_flags → build_command(auth_headers=...)
    # to prevent double-injection. auth_headers_flags sanitizes the cookie value
    # (removes newlines from browser DevTools copy-paste) before injection.
    try:
        from ghilliesuite_ex.config import cfg as _cfg
        cookie_val = _cfg.auth_cookie
        if cookie_val and tool_name == "sqlmap" and "--cookie=" not in "".join(cmd):
            # Sanitize cookie for sqlmap as well
            import re as _re
            c = cookie_val.strip().replace("\r\n", "; ").replace("\n", "; ").replace("\r", "")
            c = _re.sub(r";\s*;", ";", c)
            c = _re.sub(r";\s+", "; ", c)
            c = c.strip("; ")
            cmd.append(f"--cookie={c}")
    except Exception:
        pass

    # Inject auth headers for supported tools
    if auth_headers and spec.supports_auth_headers:
        cmd.extend(auth_headers)

    if extra_args:
        cmd.extend(extra_args)

    # Inject global proxy if configured
    try:
        from ghilliesuite_ex.config import cfg as _cfg
        if _cfg.proxy:
            proxy_str = _cfg.proxy
            if tool_name == "httpx":
                cmd.extend(["-http-proxy", proxy_str])
            elif tool_name in ("nuclei", "katana"):
                cmd.extend(["-proxy", proxy_str])
            elif tool_name in ("sqlmap", "dalfox"):
                cmd.extend(["--proxy", proxy_str])
            elif tool_name == "ffuf":
                cmd.extend(["-x", proxy_str])
    except Exception:
        pass



    if tool_name == "katana":
        try:
            from ghilliesuite_ex.config import cfg as _cfg
            # Turbo mode: scale up rate limit
            if getattr(_cfg, "turbo_mode", False):
                cmd = _replace_flag_value(cmd, "-rl", str(max(1, int(getattr(_cfg, "katana_rate_limit", 30)) * 4)))
            # Headless mode: append -headless if enabled and playwright is available
            if getattr(_cfg, "katana_headless", False) and "-headless" not in cmd:
                import importlib.util
                if importlib.util.find_spec("playwright") is not None:
                    cmd.append("-headless")
                else:
                    import warnings
                    warnings.warn(
                        "KATANA_HEADLESS=1 set but playwright is not installed. "
                        "Falling back to static crawl mode. Install with: pip install playwright && playwright install chromium",
                        stacklevel=2,
                    )
        except Exception:
            pass

    # Keep the argument for callers, but do not enable automatic redirects:
    # the destination cannot be checked against scope before httpx requests it.

    if stealth is None:
        try:
            from ghilliesuite_ex.config import cfg as _cfg
            stealth = bool(getattr(_cfg, "stealth_mode", False))
        except Exception:
            stealth = False

    if stealth:
        cmd = apply_stealth_args(tool_name, cmd, enabled=True)

    # Inject turbo scaling if enabled
    try:
        from ghilliesuite_ex.config import cfg as _cfg
        if _cfg.turbo_mode:
            cmd = apply_turbo_args(tool_name, cmd, enabled=True)
    except Exception:
        pass

    # ── Nuclei FINAL PASS: config always wins (runs after stealth/turbo) ──────
    # Re-running _apply_nuclei_tuning here ensures that any rate/concurrency/
    # severity/tags injected by stealth or turbo are stripped and replaced with
    # the authoritative config values. This is the single source of truth.
    if tool_name == "nuclei":
        try:
            from ghilliesuite_ex.config import cfg as _cfg
            _sev = getattr(_cfg, "nuclei_severity", "medium,high,critical")
            _profile = getattr(_cfg, "execution_profile", "balanced")
            if _profile == "vdp-safe":
                _sev = "high,critical"
            # aggressive: honours NUCLEI_SEVERITY env (already resolved above)

            _tags = getattr(
                _cfg, "nuclei_tags",
                "cve,sqli,xss,lfi,ssrf,rce,ssti,xxe,idor,cors,redirect,"
                "auth-bypass,default-login,token,crlf,header-injection,"
                "file-upload,panel,login,misconfig,takeover,graphql,"
                "unauth,open-redirect,backup,config,debug,injection"
            )
            _rate_limit = getattr(_cfg, "nuclei_rate_limit", None)
            _concurrency = getattr(_cfg, "nuclei_concurrency", None)
            _fast_nuclei = getattr(_cfg, "fast_nuclei", False)

            if _fast_nuclei:
                _rate_limit = int(_rate_limit) * 5 if _rate_limit else 500
                _concurrency = int(_concurrency) * 3 if _concurrency else 50
                if "-ni" not in cmd:
                    cmd.append("-ni")

            cmd = _apply_nuclei_tuning(
                cmd,
                rate_limit=_rate_limit,
                concurrency=_concurrency,
                http_timeout=getattr(_cfg, "nuclei_http_timeout", None),
                severity=_sev,
                tags=_tags,
            )
        except Exception:
            pass

    return cmd



def _write_temp_wordlist(name: str, payload_list: list[str]) -> str:
    """Write an immutable, content-addressed wordlist atomically."""
    tmp_dir = Path("tmp")
    tmp_dir.mkdir(parents=True, exist_ok=True)
    content = "\n".join(payload_list).encode("utf-8")
    digest = hashlib.sha256(content).hexdigest()[:16]
    out_path = tmp_dir / f"wordlist_{name}_{digest}.txt"
    if not out_path.exists() or out_path.read_bytes() != content:
        with tempfile.NamedTemporaryFile(dir=tmp_dir, prefix="wordlist_", delete=False) as tmp_file:
            temp_path = Path(tmp_file.name)
            tmp_file.write(content)
        try:
            temp_path.replace(out_path)
        finally:
            temp_path.unlink(missing_ok=True)
    return str(out_path)


def get_tool_descriptions(category_filter: str | None = None) -> str:
    """
    Return a formatted string listing tools and their descriptions.
    This is injected into the AI system prompt so the LLM knows what tools exist.

    Args:
        category_filter: If provided (e.g. 'Recon'), only list tools in that category.
    """
    lines: list[str] = []
    for name, spec in TOOL_REGISTRY.items():
        if category_filter and spec.category != category_filter:
            continue
        hitl = " ⚠️ [HitL required]" if spec.hitl_required else ""
        lines.append(f"  • {name} ({spec.category}){hitl}: {spec.description}")
    return "\n".join(lines)


def collect_tooling_status(profile: str = "balanced") -> ToolingStatus:
    """Collect binary and optional dependency availability for a given profile."""
    normalized = (profile or "balanced").strip().lower()
    if normalized not in _PROFILE_DISABLED_TOOLS:
        normalized = "balanced"

    installed: dict[str, bool] = {
        name: shutil.which(spec.binary) is not None
        for name, spec in TOOL_REGISTRY.items()
    }
    disabled = tuple(_PROFILE_DISABLED_TOOLS.get(normalized, ()))
    required = tuple(name for name in _REQUIRED_TOOL_NAMES if name not in disabled)
    optional = tuple(
        name for name in TOOL_REGISTRY
        if name not in required and name not in disabled
    )
    optional_dependencies = tuple(
        OptionalDependencyStatus(
            name=name,
            description=description,
            installed=importlib.util.find_spec(name) is not None,
        )
        for name, description in _OPTIONAL_DEPENDENCIES
    )
    return ToolingStatus(
        profile=normalized,
        installed=installed,
        required_tools=required,
        optional_tools=optional,
        disabled_by_profile=disabled,
        optional_dependencies=optional_dependencies,
    )


def check_binaries(console: Console | None = None, profile: str = "balanced") -> dict[str, bool]:
    """
    Verify which tool binaries are present on PATH.
    Prints categorized Rich tables when a console is provided.

    Returns:
        Mapping of tool_name -> bool (True = found on PATH).
    """
    status = collect_tooling_status(profile=profile)

    if console:
        required_table = Table(
            title=f"Required Tools ({status.profile})",
            show_lines=True,
        )
        required_table.add_column("Tool", style="bold cyan")
        required_table.add_column("Category", style="dim")
        required_table.add_column("Status")
        for name in status.required_tools:
            found = status.installed.get(name, False)
            required_table.add_row(
                name,
                TOOL_REGISTRY[name].category,
                "[green]installed[/green]" if found else "[red]missing[/red]",
            )
        console.print(required_table)

        optional_table = Table(title="Optional Binaries", show_lines=True)
        optional_table.add_column("Tool", style="bold cyan")
        optional_table.add_column("Category", style="dim")
        optional_table.add_column("Status")
        for name in status.optional_tools:
            found = status.installed.get(name, False)
            optional_table.add_row(
                name,
                TOOL_REGISTRY[name].category,
                "[green]installed[/green]" if found else "[yellow]missing[/yellow]",
            )
        console.print(optional_table)

        deps_table = Table(title="Optional Dependencies", show_lines=True)
        deps_table.add_column("Dependency", style="bold cyan")
        deps_table.add_column("Purpose", style="dim")
        deps_table.add_column("Status")
        for dep in status.optional_dependencies:
            deps_table.add_row(
                dep.name,
                dep.description,
                "[green]installed[/green]" if dep.installed else "[yellow]missing[/yellow]",
            )
        console.print(deps_table)

        disabled_table = Table(title="Disabled By Profile", show_lines=True)
        disabled_table.add_column("Tool", style="bold cyan")
        disabled_table.add_column("Reason", style="dim")
        if status.disabled_by_profile:
            for name in status.disabled_by_profile:
                disabled_table.add_row(name, f"Disabled in profile '{status.profile}'")
        else:
            disabled_table.add_row("-", f"No binaries disabled in profile '{status.profile}'")
        console.print(disabled_table)

    return status.installed
