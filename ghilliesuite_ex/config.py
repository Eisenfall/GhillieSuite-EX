"""
ghilliesuite_ex/config.py
──────────────
Centralised configuration loader with AUTO-DETECT AI provider.

Auto-detection logic (no AI_PROVIDER env var needed):
  1. Check OPENAI_API_KEY — if it starts with 'sk-'  → provider = 'openai'
  2. Check GEMINI_API_KEY — if it starts with 'AIza' → provider = 'gemini'
  3. If BOTH are present: OpenAI takes priority.
  4. If NEITHER is present: fail at validate_config() with a helpful message.

Priority order: OpenAI > Gemini
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# ── Load .env from the directory where the CLI is invoked, then from project root
load_dotenv(dotenv_path=Path.cwd() / ".env", override=False)
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env", override=False)


# ── Key-prefix detection constants ─────────────────────────────────────────────
_OPENAI_PREFIX = "sk-"
_GEMINI_PREFIX = "AIza"
VALID_EXECUTION_PROFILES = ("vdp-safe", "balanced", "aggressive")
_PLACEHOLDER_PREFIXES = (
    "your_",
    "your-",
    "replace_",
    "replace-",
    "example_",
    "example-",
)


def normalize_execution_profile(value: str | None) -> str:
    """Normalize and validate the runtime execution profile."""
    profile = (value or "balanced").strip().lower()
    if profile not in VALID_EXECUTION_PROFILES:
        allowed = ", ".join(VALID_EXECUTION_PROFILES)
        raise ValueError(f"Invalid execution profile '{value}'. Expected one of: {allowed}.")
    return profile


def _looks_like_placeholder_secret(value: str) -> bool:
    """
    Return True when a configured key appears to be a copied example value
    rather than a real secret.
    """
    cleaned = (value or "").strip()
    if not cleaned:
        return False

    lowered = cleaned.lower()
    if lowered in {
        "sk-...",
        "aizasy...",
        "your-key-here",
        "replace-me",
        "replace_with_real_key",
    }:
        return True
    if cleaned.endswith("..."):
        return True
    if "<" in cleaned or ">" in cleaned:
        return True
    if "changeme" in lowered:
        return True
    return lowered.startswith(_PLACEHOLDER_PREFIXES)


def detect_ai_provider() -> tuple[str, str]:
    """
    Inspect environment variables and return (provider_name, api_key).

    Detection rules (evaluated in priority order):
      1. OPENAI_API_KEY starting with 'sk-'   → ('openai', key)
      2. GEMINI_API_KEY starting with 'AIza'  → ('gemini', key)
      3. OPENAI_API_KEY set (any value)        → ('openai', key)  [manual override fallback]
      4. GEMINI_API_KEY set (any value)        → ('gemini', key)  [manual override fallback]
      5. Neither set                           → ('none', '')

    Returns:
        Tuple of (provider: str, active_key: str).
        provider is one of 'openai' | 'gemini' | 'none'.
    """
    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()

    # ── Priority 1: OpenAI key with correct prefix ─────────────────────────
    if openai_key.startswith(_OPENAI_PREFIX):
        return ("openai", openai_key)

    # ── Priority 2: Gemini key with correct prefix ─────────────────────────
    if gemini_key.startswith(_GEMINI_PREFIX):
        return ("gemini", gemini_key)

    # ── Priority 3: OpenAI key present (but unusual prefix — warn at validate)
    if openai_key:
        return ("openai", openai_key)

    # ── Priority 4: Gemini key present (but unusual prefix)
    if gemini_key:
        return ("gemini", gemini_key)

    # ── Nothing found ──────────────────────────────────────────────────────
    return ("none", "")


# ── Config dataclass populated from env ────────────────────────────────────────
@dataclass(frozen=True)
class RuntimeConfigOverrides:
    """Runtime-only settings applied by the CLI on top of env-backed config."""

    execution_profile: str | None = None
    auth_cookie: str | None = None
    auth_header: str | None = None
    proxy: str | None = None
    enable_screenshots: bool | None = None
    ai_planner: bool | None = None
    force_exploit: bool | None = None
    waf_evasion: bool | None = None
    output_dir: str | None = None
    evidence_dir: str | None = None
    allow_redirects: bool | None = None
    stealth_mode: bool | None = None
    disable_stealth: bool | None = None
    nuclei_timeout: int | None = None
    fast_nuclei: bool | None = None
    nuclei_rate_limit: int | None = None
    nuclei_concurrency: int | None = None
    nuclei_http_timeout: int | None = None
    js_max_workers: int | None = None
    js_max_files: int | None = None
    js_llm_concurrency: int | None = None
    js_snippet_max_len: int | None = None
    js_http_timeout: float | None = None
    js_llm_timeout: float | None = None
    recon_enable_dnsx: bool | None = None
    recon_enable_naabu: bool | None = None
    recon_enable_subzy: bool | None = None
    turbo_mode: bool | None = None
    force_auto: bool | None = None
    max_agent_loops: int | None = None
    default_timeout: int | None = None


@dataclass
class Config:
    # ── Raw keys (both loaded; detect_ai_provider() picks the winner)
    gemini_api_key: str = field(default_factory=lambda: os.getenv("GEMINI_API_KEY", "").strip())
    openai_api_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", "").strip())

    # ── Auto-detected provider + active key (populated post-init)
    ai_provider: str = field(init=False, default="none")
    active_api_key: str = field(init=False, default="")
    ai_enabled: bool = field(init=False, default=False)
    ai_status_message: str = field(init=False, default="AI triage disabled")
    ai_disabled_reason: str = field(init=False, default="")

    execution_profile: str = field(
        default_factory=lambda: normalize_execution_profile(
            os.getenv("EXECUTION_PROFILE", "balanced")
        )
    )

    # —— Optional fallback provider (used when primary refuses/blocks)
    ai_fallback_provider: str = field(
        default_factory=lambda: os.getenv("AI_FALLBACK_PROVIDER", "").strip().lower()
    )
    ai_fallback_api_key: str = field(
        default_factory=lambda: os.getenv("AI_FALLBACK_API_KEY", "").strip()
    )
    ai_fallback_base_url: str = field(
        default_factory=lambda: os.getenv("AI_FALLBACK_BASE_URL", "").strip()
    )
    ai_fallback_model: str = field(
        default_factory=lambda: os.getenv("AI_FALLBACK_MODEL", "").strip()
    )

    # —— Provider-specific fallback settings (used by ExploitAgent)
    ollama_base_url: str = field(
        default_factory=lambda: os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").strip()
    )
    ollama_model: str = field(
        default_factory=lambda: os.getenv("OLLAMA_MODEL", "llama3.1:8b").strip()
    )
    anthropic_api_key: str = field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", "").strip()
    )
    anthropic_model: str = field(
        default_factory=lambda: os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20240620").strip()
    )
    xai_api_key: str = field(
        default_factory=lambda: os.getenv("XAI_API_KEY", "").strip()
    )
    xai_model: str = field(
        default_factory=lambda: os.getenv("XAI_MODEL", "grok-2-1212").strip()
    )


    # ── CVE / NVD
    nvd_api_key: str = field(default_factory=lambda: os.getenv("NVD_API_KEY", "").strip())

    # ── Execution limits
    max_agent_loops: int = field(
        default_factory=lambda: int(os.getenv("MAX_AGENT_LOOPS", "15"))
    )
    default_timeout: int = field(
        default_factory=lambda: int(os.getenv("DEFAULT_TIMEOUT", "180"))
    )
    nuclei_timeout: int = field(
        default_factory=lambda: int(os.getenv("NUCLEI_TIMEOUT", "600"))
    )
    fast_nuclei: bool = field(
        default_factory=lambda: os.getenv("FAST_NUCLEI", "0").strip() in ("1", "true", "yes", "on")
    )
    nuclei_rate_limit: int = field(
        default_factory=lambda: int(os.getenv("NUCLEI_RATE_LIMIT", "20"))
    )
    nuclei_concurrency: int = field(
        default_factory=lambda: int(os.getenv("NUCLEI_CONCURRENCY", "10"))
    )
    nuclei_http_timeout: int = field(
        default_factory=lambda: int(os.getenv("NUCLEI_HTTP_TIMEOUT", "5"))
    )
    nuclei_severity: str = field(
        default_factory=lambda: os.getenv(
            "NUCLEI_SEVERITY", "medium,high,critical"
        ).strip()
    )
    """
    Comma-separated severity filter for Nuclei.
    Bug bounty default: 'medium,high,critical' — drops info/low noise.
    Override per-run: NUCLEI_SEVERITY=low,medium,high,critical
    """
    nuclei_tags: str = field(
        default_factory=lambda: os.getenv(
            "NUCLEI_TAGS",
            "cve,sqli,xss,lfi,ssrf,rce,ssti,xxe,idor,cors,redirect,"
            "auth-bypass,default-login,token,crlf,header-injection,"
            "file-upload,panel,login,misconfig,takeover,graphql,"
            "unauth,open-redirect,backup,config,debug,injection",
        ).strip()
    )
    """
    Comma-separated Nuclei tags. Focused on high-signal bug bounty findings.
    Deliberately excludes 'tech' and 'disclosure' — pure noise in BB context.
    Override per-run: NUCLEI_TAGS=cve,sqli,xss,rce
    """

    # â”€â”€ JS Deep Inspection limits
    js_max_workers: int = field(
        default_factory=lambda: int(os.getenv("JS_MAX_WORKERS", "8"))
    )
    js_max_files: int = field(
        default_factory=lambda: int(os.getenv("JS_MAX_FILES", "300"))
    )
    js_llm_concurrency: int = field(
        default_factory=lambda: int(os.getenv("JS_LLM_CONCURRENCY", "2"))
    )
    js_snippet_max_len: int = field(
        default_factory=lambda: int(os.getenv("JS_SNIPPET_MAX_LEN", "500"))
    )
    js_http_timeout: float = field(
        default_factory=lambda: float(os.getenv("JS_HTTP_TIMEOUT", "10"))
    )
    js_llm_timeout: float = field(
        default_factory=lambda: float(os.getenv("JS_LLM_TIMEOUT", "8"))
    )

    # ── Katana Crawler settings ────────────────────────────────────────────────
    katana_max_targets: int = field(
        default_factory=lambda: int(os.getenv("KATANA_MAX_TARGETS", "20"))
    )
    """Max concurrent Katana crawl targets. Default 20 for deep-wide recon."""

    katana_headless: bool = field(
        default_factory=lambda: os.getenv("KATANA_HEADLESS", "0").strip() in ("1", "true", "yes", "on")
    )
    """Enable Katana headless (Chromium) mode for SPA/React/Vue targets. Requires playwright."""

    katana_rate_limit: int = field(
        default_factory=lambda: int(os.getenv("KATANA_RATE_LIMIT", "30"))
    )
    """Katana requests-per-second rate limit. Default 30 for balanced deep crawling."""

    katana_depth: int = field(
        default_factory=lambda: int(os.getenv("KATANA_DEPTH", "6"))
    )
    """Katana crawl depth. Default 6 for deep endpoint discovery."""

    katana_recrawl_interval: int = field(
        default_factory=lambda: int(os.getenv("KATANA_RECRAWL_INTERVAL", "3"))
    )
    """Recrawl previously-seen Katana targets every N Recon runs. Default 3."""

    katana_max_endpoints_per_target: int = field(
        default_factory=lambda: int(os.getenv("KATANA_MAX_ENDPOINTS_PER_TARGET", "4000"))
    )
    """Maximum in-scope endpoints inserted from one Katana target crawl."""

    # —— Optional recon add-ons (OFF by default; enable via env/CLI)
    recon_enable_dnsx: bool = field(
        default_factory=lambda: os.getenv("RECON_ENABLE_DNSX", "0").strip().lower()
        in ("1", "true", "yes", "on")
    )
    recon_enable_naabu: bool = field(
        default_factory=lambda: os.getenv("RECON_ENABLE_NAABU", "0").strip().lower()
        in ("1", "true", "yes", "on")
    )
    recon_enable_subzy: bool = field(
        default_factory=lambda: os.getenv("RECON_ENABLE_SUBZY", "0").strip().lower()
        in ("1", "true", "yes", "on")
    )

    # ── SQLite state DB path
    # Hardcoded to a stable home-directory path so the DB is always found
    # regardless of CWD, enabling 100% reliable 4-day unattended runs.
    db_path: str = field(
        default_factory=lambda: os.path.abspath(
            os.getenv("DB_PATH", os.path.expanduser("~/GhillieSuite-EX/ghilliesuite_state.db"))
        )
    )

    # ── Tools that ALWAYS require Human-in-the-Loop confirmation
    hitl_tools: frozenset[str] = field(
        default_factory=lambda: frozenset({"sqlmap", "dalfox"})
    )

    # ── Retained for config compatibility; nuclei approval happens before scanning.
    nuclei_hitl_severities: frozenset[str] = field(
        default_factory=lambda: frozenset({"critical"})
    )

    # ── Authenticated scanning — set at runtime by the CLI (not from .env)
    # These are intentionally not loaded from environment variables because
    # session cookies/tokens change per engagement and should never be stored
    # persistently in .env files.
    auth_cookie: str = ""
    """Value of --cookie CLI flag. e.g. 'session=abc123; csrf=xyz'"""

    auth_header: str = ""
    """Value of --header CLI flag. e.g. 'Authorization: Bearer eyJ...' """

    proxy: str = field(
        default_factory=lambda: os.getenv("GHILLIE_PROXY", "").strip()
    )
    """Global HTTP/SOCKS5 proxy (e.g., http://127.0.0.1:8080)."""

    # Optional screenshots (gowitness) — set at runtime by CLI
    enable_screenshots: bool = False
    """If True, enable gowitness screenshots during recon."""

    # AI request resilience
    ai_timeout: float = field(
        default_factory=lambda: float(os.getenv("AI_TIMEOUT", "60"))
    )
    """Timeout (seconds) for AI calls, including Commander planning."""

    ai_retries: int = field(
        default_factory=lambda: int(os.getenv("AI_RETRIES", "3"))
    )
    """Retry attempts for AI calls before failing."""

    ai_retry_backoff: float = field(
        default_factory=lambda: float(os.getenv("AI_RETRY_BACKOFF", "1.5"))
    )
    """Backoff multiplier (seconds) between AI retries."""

    # Report and evidence paths — set at runtime by CLI
    output_dir: str = "reports"
    """Directory where JSON/MD/HTML reports are written."""

    evidence_dir: str = "evidence"
    """Directory where request/response evidence files are stored."""

    generate_bounty_draft: bool = field(
        default_factory=lambda: os.getenv("GENERATE_BOUNTY_DRAFT", "0").strip().lower()
        in ("1", "true", "yes", "on")
    )
    """If True, generate a disclosure draft for high/critical findings."""

    @property
    def auth_headers_flags(self) -> list[str]:
        """
        Build the flat -H flag list consumed by build_command(auth_headers=...).
        Returns an empty list when no auth has been configured.

        Cookie sanitization: browser DevTools copies cookies as multiline strings
        (each cookie separated by ";\n"). We collapse them to a single line so
        httpx / katana / nuclei receive a valid single-line header value.

        Example output when both are set:
          ["-H", "Cookie: session=abc", "-H", "Authorization: Bearer xyz"]
        """
        flags: list[str] = []
        if self.auth_cookie:
            # Sanitize: strip whitespace, collapse newlines between cookies
            # into "; " so the value is always a single-line HTTP header value.
            c = self.auth_cookie.strip()
            c = c.replace("\r\n", "; ").replace("\n", "; ").replace("\r", "")
            c = re.sub(r";\s*;", ";", c)   # collapse double semicolons
            c = re.sub(r";\s+", "; ", c)   # normalise spaces after semicolons
            c = c.strip("; ")
            flags += ["-H", f"Cookie: {c}"]
        if self.auth_header:
            flags += ["-H", self.auth_header]
        return flags

    @property
    def is_authenticated(self) -> bool:
        """True when any auth credential has been configured."""
        return bool(self.auth_cookie or self.auth_header)

    # ── Automation — set at runtime by the CLI --force-auto flag
    force_auto: bool = False
    turbo_mode: bool = False
    recon_jitter: bool = True


    """
    If True, all hitl_prompt() calls are silently approved.
    USE WITH EXTREME CAUTION — only on pre-authorised targets.
    Ideal for CI/CD pipelines and scheduled automated scans.
    """

    # ── Stealth mode — set at runtime by the CLI --stealth flag
    stealth_mode: bool = False
    """
    If True, apply conservative per-tool rate limiting to reduce WAF 429s.
    Injected into nuclei/sqlmap/ffuf/dirb command lines by build_command().
    """
    # ── Disable stealth override — set at runtime by the CLI --disable-stealth flag
    disable_stealth: bool = False
    """
    If True, ignore Commander/WAF stealth signals and run full execution.
    This overrides any auto-stealth detection for lab or WAF stress testing.
    """

    # ── Redirect control — set at runtime by CLI --allow-redirects flag
    allow_redirects: bool = False
    """If True, allow httpx to follow redirects during recon probing."""

    # ── Optional AI planner in Supervisor
    ai_planner: bool = False
    """If True, allow the Supervisor to request advisory targeting from the LLM."""

    force_exploit: bool = False
    """
    If True, bypass AI Commander filtering in ExploitAgent and run brute-force scans.
    """

    waf_evasion: bool = False
    """
    Enables WAF-evasion runtime hardening (request spoofing and FFUF hardening).
    Mutation probe stages are removed.
    """
    _runtime_defaults: dict[str, object] = field(init=False, repr=False, default_factory=dict)

    def __post_init__(self) -> None:
        """Run auto-detection immediately after the dataclass is initialised."""
        self.execution_profile = normalize_execution_profile(self.execution_profile)
        self.ai_provider, self.active_api_key = detect_ai_provider()
        if self.ai_provider != "none" and self.active_api_key:
            self.enable_ai()
        else:
            self.disable_ai("No AI provider API key configured.")
        self._capture_runtime_defaults()

    def set_execution_profile(self, profile: str) -> None:
        """Update the execution profile after CLI parsing."""
        self.execution_profile = normalize_execution_profile(profile)

    def _capture_runtime_defaults(self) -> None:
        self._runtime_defaults = {
            "execution_profile": self.execution_profile,
            "auth_cookie": self.auth_cookie,
            "auth_header": self.auth_header,
            "proxy": self.proxy,
            "enable_screenshots": self.enable_screenshots,
            "ai_planner": self.ai_planner,
            "force_exploit": self.force_exploit,
            "waf_evasion": self.waf_evasion,
            "output_dir": self.output_dir,
            "evidence_dir": self.evidence_dir,
            "allow_redirects": self.allow_redirects,
            "stealth_mode": self.stealth_mode,
            "disable_stealth": self.disable_stealth,
            "nuclei_timeout": self.nuclei_timeout,
            "fast_nuclei": self.fast_nuclei,
            "nuclei_rate_limit": self.nuclei_rate_limit,
            "nuclei_concurrency": self.nuclei_concurrency,
            "nuclei_http_timeout": self.nuclei_http_timeout,
            "js_max_workers": self.js_max_workers,
            "js_max_files": self.js_max_files,
            "js_llm_concurrency": self.js_llm_concurrency,
            "js_snippet_max_len": self.js_snippet_max_len,
            "js_http_timeout": self.js_http_timeout,
            "js_llm_timeout": self.js_llm_timeout,
            "recon_enable_dnsx": self.recon_enable_dnsx,
            "recon_enable_naabu": self.recon_enable_naabu,
            "recon_enable_subzy": self.recon_enable_subzy,
            "turbo_mode": self.turbo_mode,
            "force_auto": self.force_auto,
            "max_agent_loops": self.max_agent_loops,
            "default_timeout": self.default_timeout,
        }

    def reset_runtime_overrides(self) -> None:
        """Restore runtime-mutated settings to their env-backed defaults."""
        for field_name, value in self._runtime_defaults.items():
            setattr(self, field_name, value)

    def apply_runtime_overrides(self, overrides: RuntimeConfigOverrides) -> None:
        """Apply CLI/runtime overrides in one explicit place."""
        self.reset_runtime_overrides()

        if overrides.execution_profile is not None:
            self.set_execution_profile(overrides.execution_profile)
        if overrides.auth_cookie is not None:
            self.auth_cookie = overrides.auth_cookie.strip()
        if overrides.auth_header is not None:
            self.auth_header = overrides.auth_header.strip()
        if overrides.proxy is not None:
            self.proxy = overrides.proxy.strip()

        for field_name in (
            "enable_screenshots",
            "ai_planner",
            "force_exploit",
            "waf_evasion",
            "output_dir",
            "evidence_dir",
            "allow_redirects",
            "stealth_mode",
            "disable_stealth",
            "nuclei_timeout",
            "fast_nuclei",
            "nuclei_rate_limit",
            "nuclei_concurrency",
            "nuclei_http_timeout",
            "js_max_workers",
            "js_max_files",
            "js_llm_concurrency",
            "js_snippet_max_len",
            "js_http_timeout",
            "js_llm_timeout",
            "recon_enable_dnsx",
            "recon_enable_naabu",
            "recon_enable_subzy",
            "turbo_mode",
            "force_auto",
            "max_agent_loops",
            "default_timeout",
        ):
            value = getattr(overrides, field_name)
            if value is not None:
                setattr(self, field_name, value)

    def enable_ai(self) -> None:
        """Mark AI triage as available for this run."""
        self.ai_enabled = True
        self.ai_disabled_reason = ""
        self.ai_status_message = "AI triage enabled"

    def disable_ai(self, reason: str = "") -> None:
        """Mark AI triage as unavailable and preserve the reason for reports."""
        self.ai_enabled = False
        self.ai_disabled_reason = (reason or "").strip()
        self.ai_status_message = "AI triage disabled"

    @property
    def provider_display(self) -> str:
        """Human-readable provider label for log messages."""
        labels = {
            "openai": "OpenAI (gpt-4o-mini)",
            "gemini": "Google Gemini (gemini-2.5-pro)",
            "none": "None — no API key found",
        }
        return labels.get(self.ai_provider, self.ai_provider)

    @property
    def openai_model(self) -> str:
        return "gpt-4o-mini"

    @property
    def gemini_model(self) -> str:
        return "gemini-2.5-pro"


# ── Global singleton ────────────────────────────────────────────────────────────
cfg = Config()


# ── Validation ─────────────────────────────────────────────────────────────────
def validate_config(ai_provider: str | None = None) -> str:
    """
    Validate that a usable AI provider was detected.

    Args:
        ai_provider: Optional override. If None, uses the auto-detected provider.
                     Pass a value only when the user explicitly supplies --ai-provider.

    Returns:
        The resolved provider name ('openai' or 'gemini') to use for this run.

    Raises:
        RuntimeError: If no valid API key is available for the resolved provider.
    """
    resolved = ai_provider or cfg.ai_provider

    if resolved == "none" or not cfg.active_api_key:
        raise RuntimeError(
            "No AI provider API key found.\n\n"
            "Add ONE of the following to your .env file:\n"
            "  OPENAI_API_KEY=sk-...          # for OpenAI (auto-detected)\n"
            "  GEMINI_API_KEY=AIza...         # for Google Gemini (auto-detected)\n\n"
            "Get a Gemini key free at: https://aistudio.google.com/app/apikey\n"
            "Get an OpenAI key at:     https://platform.openai.com/api-keys"
        )

    if resolved == "openai" and _looks_like_placeholder_secret(cfg.openai_api_key):
        raise RuntimeError(
            "OPENAI_API_KEY looks like a placeholder example, not a real secret.\n\n"
            "Update .env with your actual OpenAI API key before running check-config or AI-assisted hunts."
        )

    if resolved == "gemini" and _looks_like_placeholder_secret(cfg.gemini_api_key):
        raise RuntimeError(
            "GEMINI_API_KEY looks like a placeholder example, not a real secret.\n\n"
            "Update .env with your actual Gemini API key before running check-config or AI-assisted hunts."
        )

    # Warn if key doesn't match the expected prefix (manual override fallback)
    if resolved == "openai" and cfg.openai_api_key and not cfg.openai_api_key.startswith(_OPENAI_PREFIX):
        import warnings
        warnings.warn(
            f"OPENAI_API_KEY does not start with '{_OPENAI_PREFIX}'. "
            "Proceeding anyway — verify the key is correct.",
            stacklevel=2,
        )

    if resolved == "gemini" and cfg.gemini_api_key and not cfg.gemini_api_key.startswith(_GEMINI_PREFIX):
        import warnings
        warnings.warn(
            f"GEMINI_API_KEY does not start with '{_GEMINI_PREFIX}'. "
            "Proceeding anyway — verify the key is correct.",
            stacklevel=2,
        )

    return resolved
