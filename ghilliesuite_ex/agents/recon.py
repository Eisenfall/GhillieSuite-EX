"""
ghilliesuite_ex/agents/recon.py
--------------------------------
ReconAgent - coverage-first reconnaissance.

Pipeline order:
  1) subfinder  -> subdomains
  2) httpx      -> HTTP probing (file-based handoff)
  3) katana     -> crawl live hosts (concurrent, file-based JSONL)
  4) gau        -> historical URLs (default add-on stage)
  5) arjun      -> parameter discovery (default add-on stage)
  6) dnsx       -> DNS enrichment (optional)
  7) naabu      -> port scan enrichment (optional)
  8) subzy      -> takeover checks (optional)

Auth credentials from cfg.auth_headers_flags are injected into httpx and katana
commands so authenticated endpoints are probed correctly.
"""


from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from rich.status import Status

from ghilliesuite_ex.arsenal import build_command
from ghilliesuite_ex.state.models import Endpoint, Finding, Host, Screenshot, Service
from ghilliesuite_ex.utils.executor import run_tool, run_tool_to_file
from ghilliesuite_ex.utils.parsers import (
    get_parser,
    parse_dnsx,
    parse_naabu,
    parse_subfinder,
    parse_arjun,
    parse_gowitness,
)
from ghilliesuite_ex.utils.scope import is_in_scope, scope_filter_domains, scope_has_url_rules
from ghilliesuite_ex.utils.ui import tool_result_panel
from .exploit_approval import auto_approve

from .recon_pipeline import (
    build_httpx_targets,
    build_katana_candidates,
    katana_crawl_safe_for_scope,
    select_arjun_targets,
    select_katana_targets,
)
from .base import AgentResult, AgentTask, BaseAgent

# Temp file locations for inter-tool data handoff
# B-04: anchor to CWD so tmp/ is always created relative to where the tool
# is invoked, not wherever Python resolves a bare 'tmp' path at import time.
_TMP_DIR          = Path.cwd() / "tmp"

class ReconAgent(BaseAgent):
    """
    Runs a file-based core chain:
      subfinder -> httpx -> katana
    then add-on stages:
      gau -> arjun (enabled by default)
      dnsx -> naabu -> subzy (optional toggles)
    All tools have hitl_required=False so no user confirmation is needed.
    Auth credentials from cfg are injected into httpx and katana.
    """

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        path_restricted = scope_has_url_rules(self.scope)
        if path_restricted:
            self.console.print("[dim]URL path scope: whole-site recon add-ons are disabled.[/dim]")
        timeout = self.cfg.default_timeout
        items_added = 0
        stage_failures: list[str] = []
        stage_skips: list[str] = []

        auth_headers = self.cfg.auth_headers_flags  # [] if no auth configured
        run_dir = _TMP_DIR / f"recon_{uuid4().hex}"
        run_dir.mkdir(parents=True, exist_ok=True)
        subfinder_out = run_dir / "subfinder_out.txt"
        httpx_in = run_dir / "httpx_in.txt"
        httpx_out = run_dir / "httpx_out.json"
        arjun_in = run_dir / "arjun_in.txt"
        arjun_out = run_dir / "arjun_out.json"
        dnsx_in = run_dir / "dnsx_in.txt"
        dnsx_out = run_dir / "dnsx_out.json"
        naabu_in = run_dir / "naabu_in.txt"
        naabu_out = run_dir / "naabu_out.json"
        subzy_in = run_dir / "subzy_in.txt"
        subzy_out = run_dir / "subzy_out.json"

        def approved(tool: str, command: list[str]) -> bool:
            allowed = auto_approve(
                bool(getattr(self.cfg, "force_auto", False)), self.console,
                tool, command, f"Recon scan of {target}",
                safe_mode=task.safe_mode, cfg=self.cfg,
            )
            if not allowed:
                stage_skips.append(tool)
            return allowed
        recon_run_count = int(getattr(self, "_recon_run_count", 0)) + 1
        httpx_history: set[str] = getattr(self, "_httpx_history", set())
        katana_history: set[str] = getattr(self, "_katana_history", set())
        katana_last_crawl_run: dict[str, int] = getattr(self, "_katana_last_crawl_run", {})
        gau_history: set[str] = getattr(self, "_gau_history", set())
        arjun_history: set[str] = getattr(self, "_arjun_history", set())
        dnsx_history: set[str] = getattr(self, "_dnsx_history", set())
        naabu_history: set[str] = getattr(self, "_naabu_history", set())
        subzy_history: set[str] = getattr(self, "_subzy_history", set())

        # B-11: wrap all phases in try/finally so state is ALWAYS
        # persisted back to the instance even if an exception escapes.
        # Without this, _recon_run_count and *_history are lost on any
        # mid-run failure, corrupting the recrawl-interval calculations.
        try:

            # Phase 1: subfinder
            self.console.print(f"[cyan]  Phase 1 - subfinder -> {target}[/cyan]")
            root_domain = (urlsplit(target).hostname or "") if "://" in target else target.split("/")[0].split(":")[0]
            sf_history: set[str] = getattr(self.cfg, "_subfinder_history", set())
            run_sf = root_domain not in sf_history

            subdomains: list[str] = []
            sf_result = None
            if run_sf:
                sf_cmd = build_command("subfinder", root_domain, output_file=subfinder_out)
                if approved("subfinder", sf_cmd):
                    with Status("[cyan]Running subfinder...[/cyan]", console=self.console):
                        sf_result = await run_tool_to_file(sf_cmd, subfinder_out, timeout=timeout)
                    if sf_result.ok:
                        sf_history.add(root_domain)
                        setattr(self.cfg, "_subfinder_history", sf_history)
                    else:
                        stage_failures.append("subfinder")
            else:
                self.console.print(f"[dim]subfinder: skipped (root domain {root_domain} already scanned)[/dim]")

            if sf_result and sf_result.ok and sf_result.output_file:  # B-12: only parse if output_file is confirmed non-empty
                parsed = parse_subfinder(output_path=sf_result.output_file)
                raw_domains = [r["domain"] for r in parsed]
                subdomains = scope_filter_domains(raw_domains, self.scope)
                for domain in subdomains:
                    await self.db.insert_host(Host(domain=domain))
                    items_added += 1
                tool_result_panel(
                    self.console, "subfinder",
                    sf_cmd, sf_result.ok or bool(sf_result.output_file),
                    f"Found {len(subdomains)} in-scope subdomain(s)",
                )
            elif sf_result and sf_result.output_file is None and sf_result.ok:
                # B-12: subfinder ran successfully but produced 0 bytes — do NOT
                # fall back to a stale previous run's output file.
                self.console.print("[dim]subfinder: ran but produced no output (0 bytes)[/dim]")
            elif sf_result:
                self.console.print(f"[dim]subfinder: {sf_result.error or sf_result.stderr[:100]}[/dim]")

            if not subdomains:
                self.console.print("[yellow]  WARNING: subfinder found no subdomains - falling back to root target[/yellow]")
                subdomains = [root_domain]
            elif root_domain not in subdomains:
                subdomains.insert(0, root_domain)
            # Phase 2: httpx (file-based handoff from subfinder)
            live_count = 0
            live_urls: list[str] = []
            new_endpoints: list[str] = []
            httpx_targets = build_httpx_targets(subdomains, self.scope, root_target=target)
            httpx_delta = [url for url in httpx_targets if url not in httpx_history]

            if httpx_delta:
                self.console.print(
                    f"[cyan]  Phase 2 - httpx probing {len(httpx_delta)} target(s) from subfinder output[/cyan]"
                )
                httpx_in.write_text("\n".join(httpx_delta) + "\n", encoding="utf-8")
                httpx_cmd = build_command(
                    "httpx",
                    target,
                    input_file=httpx_in,
                    output_file=httpx_out,
                    auth_headers=auth_headers,
                    allow_redirects=False,
                )
                if approved("httpx", httpx_cmd):
                    with Status("[cyan]Running httpx...[/cyan]", console=self.console):
                        httpx_result = await run_tool_to_file(httpx_cmd, httpx_out, timeout=timeout)
                else:
                    httpx_result = None


                if httpx_result and (httpx_result.ok or httpx_result.output_file):
                    parsed_rows = get_parser("httpx")(output_path=httpx_result.output_file or httpx_out)
                    for row in parsed_rows:
                        url = str(row.get("url") or "").strip()
                        if not url or not is_in_scope(url, self.scope):
                            continue

                        hostname = urlsplit(url).hostname or ""
                        if not hostname:
                            continue

                        host_id = await self.db.upsert_host(
                            Host(
                                domain=hostname,
                                status_code=int(row.get("status_code") or 0),
                                server=str(row.get("server") or ""),
                                tech_stack=str(row.get("tech_stack") or ""),
                            )
                        )
                        items_added += 1
                        live_count += 1
                        live_urls.append(url)
                        new_endpoints.append(url)

                        if host_id:
                            await self.db.insert_endpoint(
                                Endpoint(
                                    url=url,
                                    source_tool="httpx",
                                    host_id=host_id,
                                )
                            )
                elif httpx_result:
                    self.console.print(f"[dim]httpx: {httpx_result.error or httpx_result.stderr[:100]}[/dim]")

                if httpx_result:
                    if httpx_result.ok:
                        httpx_history.update(httpx_delta)
                    else:
                        stage_failures.append("httpx")
                    tool_result_panel(
                        self.console, "httpx", httpx_cmd, httpx_result.ok,
                        f"Found {live_count} live HTTP service(s)",
                    )
            else:
                self.console.print("[dim]httpx: skipped (no new targets)[/dim]")

            # Optional: gowitness screenshots
            if self.cfg.enable_screenshots and live_urls and not path_restricted:
                self.console.print(f"[cyan]  Optional - gowitness screenshots ({len(live_urls)} URL(s))[/cyan]")
                go_in = run_dir / "gowitness_in.txt"
                go_out = run_dir / "gowitness_out.json"
                go_in.write_text("\n".join(live_urls[:100]), encoding="utf-8")
                gow_cmd = build_command("gowitness", target, input_file=go_in, output_file=go_out)
                if approved("gowitness", gow_cmd):
                    with Status("[cyan]Running gowitness...[/cyan]", console=self.console):
                        gow_result = await run_tool_to_file(gow_cmd, go_out, timeout=timeout)
                else:
                    gow_result = None
                screenshots_added = 0
                if gow_result and (gow_result.ok or gow_result.output_file):
                    rows = parse_gowitness(output_path=gow_result.output_file or go_out)
                    for row in rows:
                        url = row.get("url") or ""
                        shot_path = row.get("screenshot") or ""
                        title = row.get("title") or ""
                        status = int(row.get("status") or 0)
                        if not url or not shot_path:
                            continue
                        p = Path(shot_path)
                        if not p.is_absolute():
                            # Try resolving relative to gowitness output or cwd
                            for base in (go_out.parent, Path.cwd()):
                                candidate = (base / shot_path).resolve()
                                if candidate.exists():
                                    p = candidate
                                    break
                        if p.exists():
                            await self.db.insert_screenshot(
                                Screenshot(
                                    url=url,
                                    path=str(p),
                                    title=title,
                                    status=status,
                                    source_tool="gowitness",
                                )
                            )
                            screenshots_added += 1
                if gow_result:
                    if not gow_result.ok:
                        stage_failures.append("gowitness")
                    tool_result_panel(
                        self.console, "gowitness", gow_cmd, gow_result.ok,
                        f"Screenshots captured: {screenshots_added}",
                    )

            # Phase 3: katana (delta-only, concurrent)
            katana_urls_found = 0
            if task.tool_name and task.tool_name != "katana":
                self.console.print(f"[dim]  Supervisor specified {task.tool_name} - skipping katana.[/dim]")
            else:
                live_hosts = await self.db.get_hosts()
                host_by_domain = {h.domain: h for h in live_hosts}
                stored_httpx_urls = [
                    ep.url for ep in await self.db.get_endpoints()
                    if ep.source_tool == "httpx" and is_in_scope(ep.url, self.scope)
                ]
                katana_candidates = build_katana_candidates(live_urls + stored_httpx_urls, scope=self.scope)
                if not katana_crawl_safe_for_scope(self.scope):
                    self.console.print("[dim]katana: skipped because this scope restricts URL paths.[/dim]")
                    katana_candidates = []
                try:
                    recrawl_interval = max(1, int(getattr(self.cfg, "katana_recrawl_interval", 3)))
                except Exception:
                    recrawl_interval = 3

                if katana_candidates:
                    # Determine max concurrent targets - turbo mode doubles the limit
                    try:
                        _max_t = int(getattr(self.cfg, "katana_max_targets", 10))
                        if getattr(self.cfg, "turbo_mode", False):
                            _max_t = min(_max_t * 2, 50)
                    except Exception:
                        _max_t = 10

                    targets_to_crawl = select_katana_targets(
                        katana_candidates,
                        history=katana_history,
                        last_crawl_run=katana_last_crawl_run,
                        recon_run_count=recon_run_count,
                        recrawl_interval=recrawl_interval,
                        max_targets=_max_t,
                    )
                else:
                    targets_to_crawl = []

                if targets_to_crawl:
                    self.console.print(
                        f"[cyan]  Phase 3 - katana crawling {len(targets_to_crawl)} target(s) "
                        f"concurrently (max={_max_t}, delta={len(targets_to_crawl)})[/cyan]"
                    )

                    _sem = asyncio.Semaphore(_max_t)

                    async def _run_katana_single(url_target: str):
                        """Crawl a single target with Katana using file-based JSONL output."""
                        import hashlib
                        _safe = hashlib.md5(url_target.encode()).hexdigest()[:8]
                        _out_path = run_dir / f"katana_{_safe}.jsonl"
                        async with _sem:
                            _cmd = build_command(
                                "katana", url_target,
                                output_file=_out_path,
                                auth_headers=auth_headers,
                            )
                            if not approved("katana", _cmd):
                                return url_target, None
                            return url_target, await run_tool_to_file(_cmd, _out_path, timeout=timeout)

                    with Status("[cyan]Concurrent Katana crawl in progress...[/cyan]", console=self.console):
                        crawl_tasks = [_run_katana_single(u) for u in targets_to_crawl]
                        crawl_results = await asyncio.gather(*crawl_tasks, return_exceptions=True)

                    try:
                        max_eps_per_target = max(1, int(getattr(self.cfg, "katana_max_endpoints_per_target", 4000)))
                    except Exception:
                        max_eps_per_target = 4000

                    for item in crawl_results:
                        if isinstance(item, Exception):
                            self.console.print(f"[dim]katana: task error - {item}[/dim]")
                            stage_failures.append("katana")
                            continue
                        url_target, katana_result = item
                        if katana_result is None:
                            continue
                        if not katana_result.ok:
                            self.console.print(f"[dim]katana [{url_target[:40]}]: {katana_result.error or katana_result.stderr[:80]}[/dim]")
                            stage_failures.append("katana")
                            continue

                        parsed_eps = get_parser("katana")(
                            output="",
                            output_path=katana_result.output_file,
                        )
                        domain = urlsplit(url_target).hostname or ""
                        host = host_by_domain.get(domain)
                        inserted_for_target = 0
                        seen_target_urls: set[str] = set()
                        for ep_item in parsed_eps:
                            ep_url = str(ep_item.get("url") or "")
                            if not ep_url or ep_url in seen_target_urls:
                                continue
                            if not is_in_scope(ep_url, self.scope):
                                continue
                            if inserted_for_target >= max_eps_per_target:
                                break

                            seen_target_urls.add(ep_url)
                            ep = Endpoint(
                                url=ep_url,
                                params=ep_item.get("params", ""),
                                source_tool="katana",
                                host_id=host.id if host else None,
                            )
                            await self.db.insert_endpoint(ep)
                            items_added += 1
                            katana_urls_found += 1
                            inserted_for_target += 1
                            new_endpoints.append(ep_url)

                        if inserted_for_target >= max_eps_per_target:
                            self.console.print(
                                f"[dim]katana [{url_target[:40]}]: endpoint cap reached ({max_eps_per_target})[/dim]"
                            )
                        katana_history.add(url_target)
                        katana_last_crawl_run[url_target] = recon_run_count

                    tool_result_panel(
                        self.console, "katana",
                        build_command("katana", targets_to_crawl[0], output_file=run_dir / "katana_preview.jsonl"),
                        "katana" not in stage_failures,
                        f"Crawled {len(targets_to_crawl)} targets -> {katana_urls_found} high-value endpoint(s)",
                    )
                else:
                    self.console.print("[dim]katana: skipped (no new live URLs)[/dim]")

            # Phase 4: gau (delta-only, existing add-on)
            gau_urls_added = 0
            if root_domain not in gau_history:
                self.console.print(f"[cyan]  Phase 4 - gau historical URLs -> {target}[/cyan]")
                gau_cmd = build_command("gau", target)
                if approved("gau", gau_cmd):
                    with Status("[cyan]Running gau...[/cyan]", console=self.console):
                        gau_result = await run_tool(gau_cmd, timeout=timeout)
                else:
                    gau_result = None
                if gau_result and gau_result.ok:
                    parsed_gau = get_parser("gau")(gau_result.stdout)
                    for entry in parsed_gau:
                        if is_in_scope(entry["url"], self.scope):
                            ep = Endpoint(
                                url=entry["url"],
                                params=entry.get("params", ""),
                                source_tool="gau",
                            )
                            await self.db.insert_endpoint(ep)
                            items_added += 1
                            gau_urls_added += 1
                            new_endpoints.append(entry["url"])
                    gau_history.add(root_domain)
                elif gau_result:
                    self.console.print(f"[dim]gau: {gau_result.error or gau_result.stderr[:100]}[/dim]")
                    stage_failures.append("gau")
                if gau_result:
                    tool_result_panel(
                        self.console, "gau", gau_cmd, gau_result.ok,
                        f"Stored {gau_urls_added} high-value in-scope URL(s)",
                    )
            else:
                self.console.print("[dim]gau: skipped (already ran for target)[/dim]")

            # Phase 5: arjun (delta-only, existing add-on)
            arjun_urls_added = 0
            pending_endpoints = [
                ep.url for ep in await self.db.get_endpoints()
                if is_in_scope(ep.url, self.scope)
            ]
            arjun_targets = select_arjun_targets(
                new_endpoints + pending_endpoints,
                history=arjun_history,
                scope=self.scope,
                limit=20,
            )
            if path_restricted:
                arjun_targets = []
            if arjun_targets:
                self.console.print("[cyan]  Phase 5 - arjun parameter discovery[/cyan]")
                arjun_in.write_text("\n".join(arjun_targets) + "\n", encoding="utf-8")
                arjun_cmd = build_command(
                    "arjun",
                    target,
                    input_file=arjun_in,
                    output_file=arjun_out,
                    extra_args=["-t", "10"],
                )
                if approved("arjun", arjun_cmd):
                    with Status("[cyan]Running arjun (list mode)...[/cyan]", console=self.console):
                        arjun_result = await run_tool_to_file(arjun_cmd, arjun_out, timeout=300)
                else:
                    arjun_result = None
                parsed_rows: list[dict] = []
                successful_arjun_targets: set[str] = set()
                if arjun_result and arjun_result.ok:
                    parsed_rows = parse_arjun(output_path=arjun_result.output_file or arjun_out)
                    successful_arjun_targets.update(arjun_targets)
                elif arjun_result:
                    self.console.print("[dim]arjun list mode failed; falling back to concurrent per-URL mode.[/dim]")
                    sem = asyncio.Semaphore(5)

                    async def _run_single(idx: int, url: str):
                        per_out = run_dir / f"arjun_out_{idx}.json"
                        per_cmd = ["arjun", "-u", url, "-oJ", str(per_out), "-t", "10"]
                        async with sem:
                            if not approved("arjun", per_cmd):
                                return url, per_out, None
                            per_res = await run_tool_to_file(per_cmd, per_out, timeout=300)
                        return url, per_out, per_res

                    with Status("[cyan]Running arjun (per-URL, concurrent)...[/cyan]", console=self.console):
                        results = await asyncio.gather(
                            *[_run_single(idx, url) for idx, url in enumerate(arjun_targets)],
                            return_exceptions=True,  # B-06: one crash must not abort all results,
                        )

                    # B-06: iterate defensively -- an Exception item means that
                    # individual task crashed; log it and continue with the rest.
                    for item in results:
                        if isinstance(item, Exception):
                            self.console.print(
                                f"[yellow]arjun per-URL error ({type(item).__name__}): {item}[/yellow]"
                            )
                            stage_failures.append("arjun")
                            continue
                        per_url, per_out, per_res = item
                        if per_res is None:
                            continue
                        if per_res.ok:
                            successful_arjun_targets.add(per_url)
                            parsed_rows.extend(parse_arjun(output_path=per_res.output_file or per_out))
                        else:
                            stage_failures.append("arjun")

                for row in parsed_rows:
                    url = row.get("url") or ""
                    params = row.get("params") or []
                    if not url or not params:
                        continue
                    if not is_in_scope(url, self.scope):
                        continue
                
                    params_str = ",".join(sorted(set(params)))
                    # Update existing endpoint or insert new one with these params
                    await self.db.update_endpoint_params(url, params_str)
                    # Ensure it exists in DB (in case update_endpoint_params found nothing to update)
                    ep = Endpoint(url=url, params=params_str, source_tool="arjun")
                    await self.db.insert_endpoint(ep)
                
                    items_added += 1
                    arjun_urls_added += 1

                arjun_history.update(successful_arjun_targets)
                if arjun_result and not successful_arjun_targets:
                    stage_failures.append("arjun")
                if arjun_result:
                    tool_result_panel(
                        self.console, "arjun", arjun_cmd,
                        len(successful_arjun_targets) == len(arjun_targets),
                        f"Discovered params for {arjun_urls_added} URL(s)",
                    )
            else:
                self.console.print("[dim]arjun: skipped (no new endpoints)[/dim]")

            # Optional add-on: dnsx (explicitly gated by config/CLI toggle)
            dnsx_hosts_added = 0
            if getattr(self.cfg, "recon_enable_dnsx", False) and not path_restricted:
                if root_domain in dnsx_history:
                    self.console.print("[dim]dnsx: skipped (already ran for target)[/dim]")
                else:
                    try:
                        dnsx_targets = list(
                            dict.fromkeys(d for d in subdomains if d and is_in_scope(d, self.scope))
                        )
                        if dnsx_targets:
                            self.console.print(
                                f"[cyan]  Optional - dnsx DNS enrichment ({len(dnsx_targets)} domain(s))[/cyan]"
                            )
                            dnsx_in.write_text("\n".join(dnsx_targets) + "\n", encoding="utf-8")
                            dnsx_cmd = build_command(
                                "dnsx",
                                target,
                                input_file=dnsx_in,
                                output_file=dnsx_out,
                            )
                            if approved("dnsx", dnsx_cmd):
                                with Status("[cyan]Running dnsx...[/cyan]", console=self.console):
                                    dnsx_result = await run_tool_to_file(dnsx_cmd, dnsx_out, timeout=timeout)
                            else:
                                dnsx_result = None

                            if dnsx_result and (dnsx_result.ok or dnsx_result.output_file):
                                rows = parse_dnsx(output_path=dnsx_result.output_file or dnsx_out)
                                for row in rows:
                                    domain = str(row.get("domain") or "").strip().lower()
                                    ip = str(row.get("ip") or "").strip()
                                    if not domain or not is_in_scope(domain, self.scope):
                                        continue
                                    await self.db.upsert_host(Host(domain=domain, ip=ip))
                                    items_added += 1
                                    dnsx_hosts_added += 1
                                if dnsx_result.ok:
                                    dnsx_history.add(root_domain)
                            elif dnsx_result:
                                self.console.print(
                                    f"[dim]dnsx: {dnsx_result.error or dnsx_result.stderr[:100]}[/dim]"
                                )

                            if dnsx_result:
                                if not dnsx_result.ok:
                                    stage_failures.append("dnsx")
                                tool_result_panel(
                                    self.console, "dnsx", dnsx_cmd, dnsx_result.ok,
                                    f"Resolved {dnsx_hosts_added} in-scope host/IP mapping(s)",
                                )
                        else:
                            self.console.print("[dim]dnsx: skipped (no in-scope domains)[/dim]")
                    except Exception as exc:
                        stage_failures.append("dnsx")
                        # B-09: visible error + short traceback for post-mortem debugging.
                        import traceback as _tb
                        self.console.print(
                            f"[yellow]! dnsx: non-blocking error ({type(exc).__name__}): {exc}[/yellow]"
                        )
                        self.console.print(f"[dim]{_tb.format_exc(limit=5)}[/dim]")
            else:
                self.console.print("[dim]dnsx: skipped (RECON_ENABLE_DNSX=0)[/dim]")

            # Optional add-on: naabu (explicitly gated by config/CLI toggle)
            naabu_services_added = 0
            if getattr(self.cfg, "recon_enable_naabu", False) and not path_restricted:
                if root_domain in naabu_history:
                    self.console.print("[dim]naabu: skipped (already ran for target)[/dim]")
                else:
                    try:
                        host_rows = await self.db.get_hosts(self.scope)
                        naabu_targets = list(dict.fromkeys(h.domain for h in host_rows if h.domain))
                        if not naabu_targets:
                            naabu_targets = list(
                                dict.fromkeys(d for d in subdomains if d and is_in_scope(d, self.scope))
                            )

                        if naabu_targets:
                            self.console.print(
                                f"[cyan]  Optional - naabu service scan ({len(naabu_targets)} host(s))[/cyan]"
                            )
                            naabu_in.write_text("\n".join(naabu_targets) + "\n", encoding="utf-8")
                            naabu_cmd = build_command(
                                "naabu",
                                target,
                                input_file=naabu_in,
                                output_file=naabu_out,
                            )
                            if approved("naabu", naabu_cmd):
                                with Status("[cyan]Running naabu...[/cyan]", console=self.console):
                                    naabu_result = await run_tool_to_file(naabu_cmd, naabu_out, timeout=timeout)
                            else:
                                naabu_result = None

                            if naabu_result and (naabu_result.ok or naabu_result.output_file):
                                parsed_rows = parse_naabu(output_path=naabu_result.output_file or naabu_out)

                                hosts_now = await self.db.get_hosts(self.scope)
                                host_by_domain = {h.domain: h for h in hosts_now}
                                ip_to_domain: dict[str, str] = {}
                                for h in hosts_now:
                                    for ip_candidate in str(h.ip or "").split(","):
                                        ip_candidate = ip_candidate.strip()
                                        if ip_candidate:
                                            ip_to_domain[ip_candidate] = h.domain

                                for row in parsed_rows:
                                    host_raw = str(row.get("host") or "").strip().lower()
                                    ip_raw = str(row.get("ip") or "").strip()
                                    port = int(row.get("port") or 0)
                                    proto = str(row.get("proto") or "tcp").strip().lower() or "tcp"
                                    if port <= 0:
                                        continue

                                    domain = host_raw
                                    if domain and not is_in_scope(domain, self.scope):
                                        domain = ip_to_domain.get(ip_raw, "")
                                    if not domain:
                                        domain = ip_to_domain.get(ip_raw, "")
                                    if not domain or not is_in_scope(domain, self.scope):
                                        continue

                                    host = host_by_domain.get(domain)
                                    host_id = host.id if host else 0
                                    if not host_id:
                                        host_id = await self.db.upsert_host(Host(domain=domain, ip=ip_raw))
                                        host_by_domain[domain] = Host(id=host_id, domain=domain, ip=ip_raw)

                                    if host_id:
                                        await self.db.insert_service(
                                            Service(
                                                host_id=host_id,
                                                port=port,
                                                proto=proto,
                                                source_tool="naabu",
                                            )
                                        )
                                        items_added += 1
                                        naabu_services_added += 1

                                if naabu_result.ok:
                                    naabu_history.add(root_domain)
                            elif naabu_result:
                                self.console.print(
                                    f"[dim]naabu: {naabu_result.error or naabu_result.stderr[:100]}[/dim]"
                                )

                            if naabu_result:
                                if not naabu_result.ok:
                                    stage_failures.append("naabu")
                                tool_result_panel(
                                    self.console, "naabu", naabu_cmd, naabu_result.ok,
                                    f"Stored {naabu_services_added} service record(s)",
                                )
                        else:
                            self.console.print("[dim]naabu: skipped (no hosts to scan)[/dim]")
                    except Exception as exc:
                        stage_failures.append("naabu")
                        # B-09: visible error + short traceback for post-mortem debugging.
                        import traceback as _tb
                        self.console.print(
                            f"[yellow]! naabu: non-blocking error ({type(exc).__name__}): {exc}[/yellow]"
                        )
                        self.console.print(f"[dim]{_tb.format_exc(limit=5)}[/dim]")
            else:
                self.console.print("[dim]naabu: skipped (RECON_ENABLE_NAABU=0)[/dim]")

            # Optional add-on: subzy (explicitly gated by config/CLI toggle)
            subzy_findings_added = 0
            if getattr(self.cfg, "recon_enable_subzy", False) and not path_restricted:
                if root_domain in subzy_history:
                    self.console.print("[dim]subzy: skipped (already ran for target)[/dim]")
                else:
                    try:
                        subzy_targets = list(
                            dict.fromkeys(d for d in subdomains if d and is_in_scope(d, self.scope))
                        )
                        if not subzy_targets:
                            subzy_targets = list(
                                dict.fromkeys(h.domain for h in await self.db.get_hosts(self.scope) if h.domain)
                            )

                        if subzy_targets:
                            self.console.print(
                                f"[cyan]  Optional - subzy takeover check ({len(subzy_targets)} domain(s))[/cyan]"
                            )
                            subzy_in.write_text("\n".join(subzy_targets) + "\n", encoding="utf-8")
                            subzy_cmd = build_command(
                                "subzy",
                                target,
                                input_file=subzy_in,
                                output_file=subzy_out,
                            )
                            if approved("subzy", subzy_cmd):
                                with Status("[cyan]Running subzy...[/cyan]", console=self.console):
                                    subzy_result = await run_tool_to_file(subzy_cmd, subzy_out, timeout=timeout)
                            else:
                                subzy_result = None

                            if subzy_result and (subzy_result.ok or subzy_result.output_file):
                                parsed_rows = get_parser("subzy")(output_path=subzy_result.output_file or subzy_out)
                                for row in parsed_rows:
                                    domain = str(row.get("domain") or "").strip().lower()
                                    status = str(row.get("status") or "").strip()
                                    service = str(row.get("service") or "").strip()
                                    vulnerable = row.get("vulnerable") is True
                                    if not domain or not vulnerable or not is_in_scope(domain, self.scope):
                                        continue

                                    evidence = f"subzy flagged potential takeover on {domain}"
                                    if service:
                                        evidence += f" (service: {service})"

                                    await self.db.insert_finding(
                                        Finding(
                                            tool="subzy",
                                            target=domain,
                                            severity="high",
                                            title="Potential subdomain takeover",
                                            evidence=evidence,
                                            reproducible_steps=(
                                                "1. Verify dangling DNS/CNAME for the subdomain.\n"
                                                "2. Attempt provider ownership claim workflow.\n"
                                                "3. Re-check HTTP response and takeover proof."
                                            ),
                                            raw_output=f"status={status}; service={service}",
                                        )
                                    )
                                    items_added += 1
                                    subzy_findings_added += 1
                                if subzy_result.ok:
                                    subzy_history.add(root_domain)
                            elif subzy_result:
                                self.console.print(
                                    f"[dim]subzy: {subzy_result.error or subzy_result.stderr[:100]}[/dim]"
                                )

                            if subzy_result:
                                if not subzy_result.ok:
                                    stage_failures.append("subzy")
                                tool_result_panel(
                                    self.console, "subzy", subzy_cmd, subzy_result.ok,
                                    f"Potential takeover findings stored: {subzy_findings_added}",
                                )
                        else:
                            self.console.print("[dim]subzy: skipped (no in-scope subdomains)[/dim]")
                    except Exception as exc:
                        stage_failures.append("subzy")
                        # B-09: visible error + short traceback for post-mortem debugging.
                        import traceback as _tb
                        self.console.print(
                            f"[yellow]! subzy: non-blocking error ({type(exc).__name__}): {exc}[/yellow]"
                        )
                        self.console.print(f"[dim]{_tb.format_exc(limit=5)}[/dim]")
            else:
                self.console.print("[dim]subzy: skipped (RECON_ENABLE_SUBZY=0)[/dim]")


        finally:
            # B-11: always persist state, even on exception.
            setattr(self, "_httpx_history",         httpx_history)
            setattr(self, "_katana_history",        katana_history)
            setattr(self, "_katana_last_crawl_run", katana_last_crawl_run)
            setattr(self, "_recon_run_count",       recon_run_count)
            setattr(self, "_gau_history",           gau_history)
            setattr(self, "_arjun_history",         arjun_history)
            setattr(self, "_dnsx_history",          dnsx_history)
            setattr(self, "_naabu_history",         naabu_history)
            setattr(self, "_subzy_history",         subzy_history)
            if run_dir.resolve().parent == _TMP_DIR.resolve():
                shutil.rmtree(run_dir, ignore_errors=True)

        status = "error" if stage_failures else ("skipped" if stage_skips else "ok")
        stage_note = f" Failed stages: {', '.join(dict.fromkeys(stage_failures))}." if stage_failures else ""
        if stage_skips:
            stage_note += f" Skipped by approval: {', '.join(dict.fromkeys(stage_skips))}."
        return AgentResult(
            agent=self.name,
            status=status,
            summary=(
                f"Recon complete - {len(subdomains)} subdomains, "
                f"{live_count} live hosts, "
                f"{katana_urls_found} crawled endpoints. "
                f"(Auth: {'active' if auth_headers else 'none'}){stage_note}"
            ),
            items_added=items_added,
            error=", ".join(dict.fromkeys(stage_failures)),
        )
