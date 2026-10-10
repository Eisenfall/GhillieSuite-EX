"""
ghilliesuite_ex/utils/executor.py
──────────────────────
Async subprocess executor — the only place in the codebase where external
binaries are actually invoked.

Design decisions:
  • asyncio.create_subprocess_exec is used (not shell=True) to avoid shell
    injection and to cleanly handle stderr separately from stdout.
  • FileNotFoundError is caught and converted to a ToolResult with an
    informative error message so the agent loop never crashes on a missing binary.
  • A configurable timeout (seconds) terminates runaway processes.
  • stdout is capped at MAX_OUTPUT_BYTES to prevent memory issues on
    verbose tools like gau.
  • run_tool_to_file() runs binaries that write their output directly to disk
    (subfinder -o, httpx -json -o, ffuf -of json -o) for reliable inter-tool
    data handoff without brittle stdin piping.
  • WAF Cooldown: sleep is performed OUTSIDE the lock so concurrent tools are
    never blocked waiting on the lock itself.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from pathlib import Path


def _build_tool_env() -> dict[str, str]:
    """
    Build a subprocess environment that guarantees Go-installed security tools
    are found even when GhillieSuite-EX is launched from a context that does
    not source ~/.bashrc (e.g. desktop launcher, tmux, cron, or a different
    user account whose .profile was not evaluated).

    Strategy: prepend well-known Go binary directories to the existing PATH.
    Only directories that actually exist are added to avoid stale entries.
    The existing PATH is always preserved so system tools remain accessible.
    """
    env = os.environ.copy()
    home = Path.home()

    # Go binary install locations (in priority order)
    go_bin_candidates = [
        home / "go" / "bin",              # go install default: ~/go/bin
        Path("/usr/local/go/bin"),         # manual Go toolchain install
        Path("/usr/local/bin"),            # common homebrew / manual installs
        Path("/opt/go/bin"),               # some distro layouts
        Path("/snap/bin"),                 # snap-installed tools
    ]

    current_path = env.get("PATH", "")
    extra = os.pathsep.join(
        str(p) for p in go_bin_candidates
        if p.is_dir() and str(p) not in current_path
    )
    if extra:
        env["PATH"] = extra + os.pathsep + current_path

    return env


# Build once at module load; shared across all tool invocations.
# Re-evaluated on each import so it picks up the correct HOME.
_TOOL_ENV: dict[str, str] = _build_tool_env()


_EVASION_COOLDOWN_SECONDS = 60
_last_waf_block_time = 0.0
# B-10 fix: do NOT create asyncio primitives at module import time — they must
# be created inside a running event loop.  Lazy-initialise on first use.
_cooldown_lock: asyncio.Lock | None = None


def _get_cooldown_lock() -> asyncio.Lock:
    """Return the WAF-cooldown lock, creating it lazily inside the running loop."""
    global _cooldown_lock
    if _cooldown_lock is None:
        _cooldown_lock = asyncio.Lock()
    return _cooldown_lock


MAX_OUTPUT_BYTES = 512 * 1024  # 512 KB cap on raw stdout


async def _bounded_communicate(proc, stdin_data: bytes | None = None) -> tuple[bytes, bytes]:
    """Drain both pipes to EOF while retaining only the first output window."""
    if getattr(proc, "stdout", None) is None or getattr(proc, "stderr", None) is None:
        return await proc.communicate(input=stdin_data) if stdin_data is not None else await proc.communicate()

    if stdin_data is not None and proc.stdin is not None:
        proc.stdin.write(stdin_data)
        await proc.stdin.drain()
        proc.stdin.close()

    async def _drain(stream) -> bytes:
        retained = bytearray()
        while chunk := await stream.read(65536):
            remaining = MAX_OUTPUT_BYTES - len(retained)
            if remaining > 0:
                retained.extend(chunk[:remaining])
        return bytes(retained)

    stdout, stderr, _ = await asyncio.gather(
        _drain(proc.stdout), _drain(proc.stderr), proc.wait(),
    )
    return stdout, stderr


@dataclass
class ToolResult:
    """Return value from run_tool() and run_tool_to_file()."""

    # B-05: all str fields have explicit defaults so ToolResult can never have
    # None for stdout/stderr (guards against TypeError on [:100] slices when
    # callers construct the dataclass partially in tests or error paths).
    stdout:     str  = field(default="")
    stderr:     str  = field(default="")
    returncode: int  = field(default=0)
    error:      str  = field(default="")   # populated on exceptions (timeout, missing binary, etc.)
    output_file: Path | None = field(default=None)  # set by run_tool_to_file()

    @property
    def ok(self) -> bool:
        """True if the tool ran without fatal errors."""
        return not self.error and self.returncode == 0

    def truncated_stdout(self, max_chars: int = 3000) -> str:
        """Return a truncated stdout string safe to display in Rich panels."""
        if len(self.stdout) <= max_chars:
            return self.stdout
        half = max_chars // 2
        return self.stdout[:half] + f"\n…[{len(self.stdout) - max_chars} chars omitted]…\n" + self.stdout[-half:]


async def run_tool(
    cmd: list[str],
    timeout: int = 180,
    stdin_data: str | None = None,
) -> ToolResult:
    """
    Execute an external binary asynchronously and return its output.

    Args:
        cmd:        Full command as a list of strings, e.g. ['subfinder', '-d', 'example.com']
        timeout:    Seconds before the process is forcibly killed. Default: 180.
        stdin_data: Optional text to pipe into the process's stdin (e.g. a host list for httpx).

    Returns:
        ToolResult with stdout, stderr, returncode, and an error string if applicable.
    """
    global _last_waf_block_time

    # Global Evasion Cooldown Check — sleep OUTSIDE lock to avoid blocking other tools
    wait_needed = 0.0
    async with _get_cooldown_lock():
        now = time.time()
        elapsed = now - _last_waf_block_time
        if elapsed < _EVASION_COOLDOWN_SECONDS:
            wait_needed = _EVASION_COOLDOWN_SECONDS - elapsed
    if wait_needed > 0:
        await asyncio.sleep(wait_needed)

    stdin_pipe = asyncio.subprocess.PIPE if stdin_data else None

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=stdin_pipe,
            env=_TOOL_ENV,
        )

        stdin_bytes = stdin_data.encode() if stdin_data else None

        try:
            stdout_raw, stderr_raw = await asyncio.wait_for(
                _bounded_communicate(proc, stdin_bytes),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await _bounded_communicate(proc)
            return ToolResult(
                stdout="",
                stderr="",
                returncode=-1,
                error=f"⏱  Tool '{cmd[0]}' timed out after {timeout}s and was killed.",
            )

        # Cap raw output to prevent memory exhaustion
        stdout_text = stdout_raw[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        stderr_text = stderr_raw[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")

        res = ToolResult(
            stdout=stdout_text,
            stderr=stderr_text,
            returncode=proc.returncode or 0,
        )

        # Detect WAF Blocks (403/429)
        combined = (stdout_text + stderr_text).lower()
        if "403 forbidden" in combined or "429 too many requests" in combined:
            async with _get_cooldown_lock():
                _last_waf_block_time = time.time()

        return res

    except FileNotFoundError:
        binary = cmd[0]
        return ToolResult(
            stdout="",
            stderr="",
            returncode=127,
            error=(
                f"❌  Binary '{binary}' not found on PATH. "
                f"Install it and ensure it is accessible. "
                f"Run 'GhillieSuite-EX.sec check-tools' to see all missing binaries."
            ),
        )

    except PermissionError:
        return ToolResult(
            stdout="", stderr="", returncode=126,
            error=f"🔒  Permission denied trying to execute '{cmd[0]}'.",
        )

    except Exception as exc:  # noqa: BLE001
        return ToolResult(
            stdout="", stderr="", returncode=-1,
            error=f"💥  Unexpected error running '{cmd[0]}': {exc}",
        )


async def run_tool_to_file(
    cmd: list[str],
    output_path: Path,
    timeout: int = 180,
) -> ToolResult:
    """
    Execute an external binary that writes its results directly to a file.

    This is the preferred execution method for recon tools that support an
    output file flag (e.g. subfinder -o, httpx -json -o, ffuf -of json -o,
    katana -j -o).
    File-based I/O completely eliminates the brittle stdin-piping approach and
    ensures zero data loss regardless of stdout buffering behaviour.

    Args:
        cmd:         Full command list. The caller is responsible for including
                     the output file flag (e.g. ['-o', str(output_path)]).
        output_path: Expected output file path. Used to verify the tool wrote
                     something and to populate ToolResult.output_file.
        timeout:     Seconds before the process is forcibly killed.

    Returns:
        ToolResult where .output_file is set to output_path if it exists after
        execution, otherwise None. .stdout will contain any progress text the
        tool wrote to stdout (usually empty for -silent tools).
    """
    global _last_waf_block_time

    # Ensure parent directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        output_path.unlink(missing_ok=True)
    except OSError:
        pass

    # Global Evasion Cooldown Check — sleep OUTSIDE lock to avoid blocking other tools
    wait_needed = 0.0
    async with _get_cooldown_lock():
        now = time.time()
        elapsed = now - _last_waf_block_time
        if elapsed < _EVASION_COOLDOWN_SECONDS:
            wait_needed = _EVASION_COOLDOWN_SECONDS - elapsed
    if wait_needed > 0:
        await asyncio.sleep(wait_needed)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_TOOL_ENV,
        )

        try:
            stdout_raw, stderr_raw = await asyncio.wait_for(
                _bounded_communicate(proc),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await _bounded_communicate(proc)
            return ToolResult(
                stdout="",
                stderr="",
                returncode=-1,
                error=f"⏱  Tool '{cmd[0]}' timed out after {timeout}s and was killed.",
            )

        stdout_text = stdout_raw[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        stderr_text = stderr_raw[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")

        # Verify that the tool actually wrote a fresh, non-empty output file.
        resolved_output = None
        if output_path.exists():
            try:
                if output_path.stat().st_size > 0:
                    resolved_output = output_path.resolve()
            except OSError:
                resolved_output = None

        res = ToolResult(
            stdout=stdout_text,
            stderr=stderr_text,
            returncode=proc.returncode or 0,
            output_file=resolved_output,
        )

        # Detect WAF Blocks (403/429)
        combined = (stdout_text + stderr_text).lower()
        if "403 forbidden" in combined or "429 too many requests" in combined:
            async with _get_cooldown_lock():
                _last_waf_block_time = time.time()

        return res

    except FileNotFoundError:
        binary = cmd[0]
        return ToolResult(
            stdout="",
            stderr="",
            returncode=127,
            error=(
                f"❌  Binary '{binary}' not found on PATH. "
                f"Install it and ensure it is accessible. "
                f"Run 'GhillieSuite-EX.sec check-tools' to see all missing binaries."
            ),
        )

    except PermissionError:
        return ToolResult(
            stdout="", stderr="", returncode=126,
            error=f"🔒  Permission denied trying to execute '{cmd[0]}'.",
        )

    except Exception as exc:  # noqa: BLE001
        return ToolResult(
            stdout="", stderr="", returncode=-1,
            error=f"💥  Unexpected error running '{cmd[0]}': {exc}",
        )
