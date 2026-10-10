# GhillieSuite-EX

Python CLI for authorized pentest and bug bounty automation.

GhillieSuite-EX coordinates recon, targeted validation, reporting, and safety gates around common open-source security tools. It is built to reduce repetitive workflow overhead, not to replace manual testing or program-specific judgment.

## Current Shape

- CLI entrypoint: `ghilliesuite_ex/main.py`
- CLI framework: Typer
- Orchestration: rules-first `SupervisorAgent` with optional AI advisory targeting
- Recon flow: `ReconAgent` plus helper logic in `ghilliesuite_ex/agents/recon_pipeline.py`
- Exploit flow: `ExploitAgent` with extracted approval and target-selection helpers
- State layer: SQLite via `StateDB`
- Reporting: JSON, Markdown, standalone HTML, and optional bounty draft text
- Safety model: execution profiles plus Human-in-the-Loop gates

The current architecture is intentionally split so orchestration, selection logic, state management, and report rendering are easier to test independently.

## Architecture

```text
CLI (Typer)
  -> main.py preflight
     - config validation
     - scope validation
     - tool availability checks
     - runtime override application
  -> SupervisorAgent
     - ReconAgent
       - recon_pipeline helpers
     - ExploitAgent
       - exploit_targets helpers
       - exploit_approval helpers
     - ReporterAgent
       - build_report_data()
       - render_markdown_report()
       - HtmlReporter

StateDB
  - hosts
  - endpoints
  - findings
  - services
  - screenshots
  - target-session isolation metadata
```

## Quick Start

### 1. Create a virtual environment

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e .
```

Windows PowerShell:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

Contributor or local audit workflow:

```bash
python -m pip install -e ".[dev]"
```

### 2. Configure `.env`

```bash
cp .env.example .env
```

Set one real AI key if you want AI assistance:

- `OPENAI_API_KEY=...`
- or `GEMINI_API_KEY=...`

Notes:

- provider detection is automatic
- blank values are expected in `.env.example`
- placeholder-like values such as `sk-...` are rejected by `check-config`

### 3. Install external tools

Core tools:

- `subfinder`
- `httpx`
- `katana`
- `nuclei`

Default recon add-ons:

- `gau`
- `arjun`

Optional tools:

- `dnsx`
- `naabu`
- `subzy`
- `gowitness`
- `dalfox`
- `sqlmap`
- `trufflehog`
- `ffuf`

Use the CLI to validate what is actually available on your machine:

```bash
python -m ghilliesuite_ex.main check-tools
```

## Safe Validation Commands

These commands are safe baseline checks and do not start a real hunt:

```bash
python -m ghilliesuite_ex.main --help
python -m ghilliesuite_ex.main version
python -m ghilliesuite_ex.main check-config
python -m ghilliesuite_ex.main check-tools
python -m unittest discover -s tests -v
```

`check-config` is expected to fail until you put a real key in `.env`.

## Hunt Command

Minimal example:

```bash
python -m ghilliesuite_ex.main hunt \
  --target example.com \
  --scope scope_example.txt
```

Authenticated example:

```bash
python -m ghilliesuite_ex.main hunt \
  --target app.example.com \
  --scope scope_example.txt \
  --cookie "session=abc123; csrf=xyz" \
  --header "Authorization: Bearer <token>"
```

Important:

- only run hunts against targets you are explicitly authorized to test
- do not use real secrets in shared screenshots, logs, or tickets
- `--force-auto` bypasses approval prompts and should be treated as a high-trust mode

## Execution Profiles

`vdp-safe`

- recon-focused
- active exploitation paths are restricted
- best fit for stricter disclosure programs

`balanced`

- default profile
- targeted exploitation and validation where policy allows

`aggressive`

- broadest profile
- unlocks force-exploit-oriented behavior
- intended for lab or clearly pre-authorized targets

Safety policy is centralized in `ghilliesuite_ex/safety.py`.

Scope and scanner behavior:

- Automatic redirect following is disabled. The `--allow-redirects` flag is retained for CLI compatibility but does not enable redirects.
- URL path rules restrict the crawler and scanners that cannot guarantee path containment. Those stages are skipped for path-restricted scopes; direct probes still check each URL against scope.
- Nuclei uses the templates installed with Nuclei. Files under `ghilliesuite_ex/templates/` are packaged examples and are not automatically included in hunts.
- An SSRF-prone parameter name is reported as an unverified informational lead. Cloud metadata responses require evidence beyond an echoed payload before a confirmed label is used.

## Reports and Artifacts

By default, reports are written to `reports/` and evidence files to `evidence/`.

Typical report outputs:

- `<target>_<timestamp>.json`
- `<target>_<timestamp>.md`
- `<target>_<timestamp>.html`
- `<target>_<timestamp>_run.json`

Optional output:

- `<target>_bounty_draft.txt`

Notes:

- HTML reports are standalone and do not depend on Tailwind CDN or Google Fonts
- report content is redacted before being written
- run manifests are lightweight audit records for preflight failures and completed hunts
- run manifests intentionally exclude cookies, auth headers, and raw captured HTTP evidence

To enable the optional draft:

```bash
GENERATE_BOUNTY_DRAFT=1
```

That toggle is off by default.

## Runtime Notes

- use a virtual environment; system Python and repo `.venv` can differ
- Python package installation and external security binaries are separate concerns
- packaged runtime assets live under `ghilliesuite_ex/resources/` and `ghilliesuite_ex/templates/`
- target isolation is owned by `StateDB`; switching targets can reset per-target data

## Testing

Canonical baseline command:

```bash
python -m unittest discover -s tests -v
```

The project keeps the suite in `unittest` style. `pytest` can still be used as a wrapper if installed, but `unittest discover` is the baseline command that the repository is aligned around.

The suite mocks external scanners and HTTP calls. Passing tests verify local control flow; a live hunt also depends on the installed scanner versions and target behavior.

## Main Commands

```text
python -m ghilliesuite_ex.main hunt
python -m ghilliesuite_ex.main check-tools
python -m ghilliesuite_ex.main check-config
python -m ghilliesuite_ex.main version
```

## Refactor Highlights

Recent refactors moved the project toward smaller, testable boundaries:

- centralized runtime override handling in config
- centralized safety policy by execution profile
- extracted exploit approval and target-selection helpers
- extracted recon pipeline helpers
- clearer `StateDB` target-session ownership
- thinner `ReporterAgent` with shared JSON/Markdown/HTML report shaping
- standalone HTML reports plus per-run manifests

## Repository Hygiene

Committed:

- source code
- tests
- templates
- packaged runtime resources
- documentation

Ignored:

- `.env`
- `.venv/`
- generated reports
- generated evidence
- local SQLite files

## Legal and Safety Reminder

This tool is for authorized security testing only. The operator is responsible for scope control, program compliance, rate discipline, and safe handling of credentials and evidence.
