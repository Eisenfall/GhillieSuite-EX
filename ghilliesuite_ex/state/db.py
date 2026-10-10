"""
ghilliesuite_ex/state/db.py
────────────────
Async SQLite state manager using aiosqlite.

Agents read from and write to this DB instead of passing raw tool output
around — which would rapidly blow out the LLM's context window.

The DB stores:
  • hosts      — live domains/IPs discovered during recon
  • endpoints  — crawled URLs with parameter info
  • findings   — confirmed or suspected vulnerabilities
  • cve_cache  — cached CVE lookups (avoid redundant NVD API calls)

Usage:
    async with StateDB(cfg.db_path) as db:
        await db.insert_host(host)
        hosts = await db.get_hosts()
"""

from __future__ import annotations

import json
from pathlib import Path

import aiosqlite
from ghilliesuite_ex.utils.scope import is_in_scope

from .models import CVEResult, Endpoint, Finding, Host, Service, Screenshot, TargetSession

# ── DDL ───────────────────────────────────────────────────────────────────────
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    domain       TEXT    NOT NULL UNIQUE,
    ip           TEXT    DEFAULT '',
    status_code  INTEGER DEFAULT 0,
    server       TEXT    DEFAULT '',
    tech_stack   TEXT    DEFAULT '',
    discovered_at TEXT   NOT NULL
);

CREATE TABLE IF NOT EXISTS services (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id       INTEGER NOT NULL REFERENCES hosts(id),
    port          INTEGER NOT NULL,
    proto         TEXT    DEFAULT 'tcp',
    service       TEXT    DEFAULT '',
    source_tool   TEXT    DEFAULT '',
    discovered_at TEXT    NOT NULL,
    UNIQUE(host_id, port, proto)
);

CREATE TABLE IF NOT EXISTS endpoints (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT    NOT NULL,
    method      TEXT    DEFAULT 'GET',
    params      TEXT    DEFAULT '',
    source_tool TEXT    DEFAULT '',
    host_id     INTEGER REFERENCES hosts(id),
    found_at    TEXT    NOT NULL,
    UNIQUE(url, method)
);

CREATE TABLE IF NOT EXISTS screenshots (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    url          TEXT    NOT NULL,
    path         TEXT    NOT NULL,
    title        TEXT    DEFAULT '',
    status       INTEGER DEFAULT 0,
    source_tool  TEXT    DEFAULT '',
    captured_at  TEXT    NOT NULL,
    UNIQUE(url, path)
);

CREATE TABLE IF NOT EXISTS findings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    tool              TEXT NOT NULL,
    target            TEXT NOT NULL,
    severity          TEXT NOT NULL,
    title             TEXT NOT NULL,
    evidence          TEXT DEFAULT '',
    reproducible_steps TEXT DEFAULT '',
    raw_output        TEXT DEFAULT '',
    timestamp         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_cache (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    keyword      TEXT NOT NULL,
    cve_id       TEXT NOT NULL,
    description  TEXT DEFAULT '',
    cvss_score   REAL DEFAULT 0.0,
    poc_url      TEXT DEFAULT '',
    published_date TEXT DEFAULT '',
    fetched_at   TEXT NOT NULL
);
"""

# Tables that hold per-target scan data — wiped when target changes
_DATA_TABLES = ["findings", "endpoints", "services", "screenshots", "hosts", "cve_cache"]


def _merge_endpoint_params(*values: str) -> str:
    return ",".join(sorted({
        name.strip() for value in values for name in (value or "").split(",") if name.strip()
    }))


class StateDB:
    """
    Async context manager wrapping aiosqlite.

    Example:
        async with StateDB("mydb.db") as db:
            await db.insert_host(host)
    """

    def __init__(self, db_path: str = ".ghilliesuite_state.db", target: str | None = None) -> None:
        self._path = db_path
        self._target = target
        self._conn: aiosqlite.Connection | None = None
        self._target_session = TargetSession(
            requested_target=target,
            stored_target_before=None,
            active_target=target,
            data_reset=False,
        )

    # ── Context manager ───────────────────────────────────────────────────────

    async def __aenter__(self) -> "StateDB":
        self._conn = await aiosqlite.connect(self._path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(SCHEMA_SQL)
        await self._migrate_endpoint_schema()
        await self._conn.commit()

        # ── Target-change detection ───────────────────────────────────────────
        # If the caller supplies a target and it differs from the stored one,
        # wipe all per-target data so old scan results never contaminate a new hunt.
        self._target_session = await self._ensure_target_session()

        return self

    async def __aexit__(self, *_) -> None:
        if self._conn:
            await self._conn.close()

    # ── Helpers ───────────────────────────────────────────────────────────────

    @property
    def _db(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("StateDB must be used as an async context manager.")
        return self._conn

    @property
    def target_session(self) -> TargetSession:
        """Return target-isolation metadata for the current DB context."""
        return self._target_session

    async def _migrate_endpoint_schema(self) -> None:
        """Replace the legacy URL-only unique key while keeping existing endpoint IDs."""
        indexes = await (await self._db.execute("PRAGMA index_list('endpoints')")).fetchall()
        legacy_key = False
        for index in indexes:
            if not index["unique"]:
                continue
            columns = await (await self._db.execute(
                f"PRAGMA index_info('{index['name']}')"
            )).fetchall()
            if [column["name"] for column in columns] == ["url"]:
                legacy_key = True
                break
        if not legacy_key:
            return
        await self._db.executescript("""
            CREATE TABLE endpoints_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                method TEXT DEFAULT 'GET',
                params TEXT DEFAULT '',
                source_tool TEXT DEFAULT '',
                host_id INTEGER REFERENCES hosts(id),
                found_at TEXT NOT NULL,
                UNIQUE(url, method)
            );
            INSERT INTO endpoints_new (id, url, method, params, source_tool, host_id, found_at)
                SELECT id, url, method, params, source_tool, host_id, found_at FROM endpoints;
            DROP TABLE endpoints;
            ALTER TABLE endpoints_new RENAME TO endpoints;
        """)

    async def _ensure_target_session(self) -> TargetSession:
        """
        Centralize target-isolation behavior and expose its outcome explicitly.
        """
        row = await (
            await self._db.execute("SELECT value FROM meta WHERE key = 'target'")
        ).fetchone()
        stored_target = row["value"] if row else None

        if self._target is None:
            return TargetSession(
                requested_target=None,
                stored_target_before=stored_target,
                active_target=stored_target,
                data_reset=False,
            )

        reset_applied = False
        if stored_target != self._target:
            if stored_target is not None:
                drop_sql = "\n".join(
                    f"DROP TABLE IF EXISTS {table};" for table in _DATA_TABLES
                )
                await self._conn.executescript(drop_sql)
                await self._conn.executescript(SCHEMA_SQL)
                reset_applied = True

            await self._conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('target', ?)",
                (self._target,),
            )
            await self._conn.commit()

        return TargetSession(
            requested_target=self._target,
            stored_target_before=stored_target,
            active_target=self._target,
            data_reset=reset_applied,
        )

    # ── Hosts ─────────────────────────────────────────────────────────────────

    async def insert_host(self, host: Host) -> int:
        """Insert or ignore a host record. Returns the row id."""
        ip_val = host.ip
        if isinstance(ip_val, (list, tuple)):
            ip_val = ",".join(str(x) for x in ip_val if x)
        tech_val = host.tech_stack
        if isinstance(tech_val, (list, tuple)):
            tech_val = ",".join(str(x) for x in tech_val if x)
        cursor = await self._db.execute(
            """
            INSERT OR IGNORE INTO hosts (domain, ip, status_code, server, tech_stack, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (host.domain, ip_val, host.status_code, host.server, tech_val, host.discovered_at),
        )
        await self._db.commit()
        # If ignored (duplicate), fetch the existing id
        if cursor.rowcount == 0:
            row = await self._db.execute("SELECT id FROM hosts WHERE domain = ?", (host.domain,))
            result = await row.fetchone()
            return result["id"] if result else 0
        return cursor.lastrowid  # type: ignore[return-value]

    async def upsert_host(self, host: Host) -> int:
        """
        Insert or update a host record. Updates non-empty fields on conflict.
        Returns the row id of the host.
        """
        ip_val = host.ip
        if isinstance(ip_val, (list, tuple)):
            ip_val = ",".join(str(x) for x in ip_val if x)
        tech_val = host.tech_stack
        if isinstance(tech_val, (list, tuple)):
            tech_val = ",".join(str(x) for x in tech_val if x)
        # Try insert first
        host_id = await self.insert_host(Host(
            domain=host.domain,
            ip=ip_val,
            status_code=host.status_code,
            server=host.server,
            tech_stack=tech_val,
            discovered_at=host.discovered_at,
        ))
        # Update non-empty fields if already exists
        if host_id:
            updates = []
            params: list = []
            if ip_val:
                updates.append("ip = ?")
                params.append(ip_val)
            if host.status_code:
                updates.append("status_code = ?")
                params.append(host.status_code)
            if host.server:
                updates.append("server = ?")
                params.append(host.server)
            if tech_val:
                updates.append("tech_stack = ?")
                params.append(tech_val)
            if updates:
                params.append(host.domain)
                await self._db.execute(
                    f"UPDATE hosts SET {', '.join(updates)} WHERE domain = ?",
                    params,
                )
                await self._db.commit()
        return host_id

    async def get_hosts(self, scope_domains: list[str] | None = None) -> list[Host]:
        """
        Return all live hosts, optionally filtered to in-scope domains.
        scope_domains may contain wildcards like '*.example.com'.
        """
        rows = await (await self._db.execute("SELECT * FROM hosts")).fetchall()
        hosts = [
            Host(
                id=r["id"],
                domain=r["domain"],
                ip=r["ip"],
                status_code=r["status_code"],
                server=r["server"],
                tech_stack=r["tech_stack"],
                discovered_at=r["discovered_at"],
            )
            for r in rows
        ]
        if scope_domains:
            hosts = [h for h in hosts if is_in_scope(h.domain, scope_domains)]
        return hosts

    # -------- Services --------

    async def insert_service(self, service: Service) -> int:
        """Insert or ignore a service record. Returns the row id."""
        cursor = await self._db.execute(
            """
            INSERT OR IGNORE INTO services (host_id, port, proto, service, source_tool, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                service.host_id,
                service.port,
                service.proto,
                service.service,
                service.source_tool,
                service.discovered_at,
            ),
        )
        await self._db.commit()
        if cursor.rowcount == 0:
            row = await (await self._db.execute(
                "SELECT id FROM services WHERE host_id = ? AND port = ? AND proto = ?",
                (service.host_id, service.port, service.proto),
            )).fetchone()
            return row["id"] if row else 0
        return cursor.lastrowid or 0  # type: ignore[return-value]

    async def get_services(self, host_id: int | None = None) -> list[Service]:
        query = "SELECT * FROM services WHERE 1=1"
        params: list = []
        if host_id is not None:
            query += " AND host_id = ?"
            params.append(host_id)
        rows = await (await self._db.execute(query, params)).fetchall()
        return [
            Service(
                id=r["id"],
                host_id=r["host_id"],
                port=r["port"],
                proto=r["proto"],
                service=r["service"],
                source_tool=r["source_tool"],
                discovered_at=r["discovered_at"],
            )
            for r in rows
        ]

    # ── Endpoints ─────────────────────────────────────────────────────────────

    async def insert_endpoint(self, ep: Endpoint) -> int:
        method = (ep.method or "GET").upper()
        cursor = await self._db.execute(
            """
            INSERT OR IGNORE INTO endpoints (url, method, params, source_tool, host_id, found_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (ep.url, method, ep.params, ep.source_tool, ep.host_id, ep.found_at),
        )
        if cursor.rowcount == 0:
            row = await (await self._db.execute(
                "SELECT id, params FROM endpoints WHERE url = ? AND method = ?", (ep.url, method),
            )).fetchone()
            if row:
                merged = _merge_endpoint_params(row["params"], ep.params)
                await self._db.execute(
                    "UPDATE endpoints SET params = ?, host_id = COALESCE(host_id, ?) WHERE id = ?",
                    (merged, ep.host_id, row["id"]),
                )
                await self._db.commit()
            return row["id"] if row else 0
        await self._db.commit()
        return cursor.lastrowid or 0  # type: ignore[return-value]

    async def update_endpoint_params(self, url: str, params: str) -> None:
        """Update params for an existing endpoint, merging with any current params."""
        rows = await (
            await self._db.execute("SELECT id, params FROM endpoints WHERE url = ?", (url,))
        ).fetchall()
        if not rows:
            return
        for row in rows:
            await self._db.execute(
                "UPDATE endpoints SET params = ? WHERE id = ?",
                (_merge_endpoint_params(row["params"], params), row["id"]),
            )
        await self._db.commit()

    async def get_endpoints(
        self,
        host_id: int | None = None,
        with_params_only: bool = False,
    ) -> list[Endpoint]:
        """
        Fetch endpoints, optionally filtered by host or whether they have query params.
        with_params_only=True is used by ExploitAgent to find sqlmap/dalfox candidates.
        """
        query = "SELECT * FROM endpoints WHERE 1=1"
        params: list = []
        if host_id is not None:
            query += " AND host_id = ?"
            params.append(host_id)
        if with_params_only:
            query += " AND params != ''"
        rows = await (await self._db.execute(query, params)).fetchall()
        return [
            Endpoint(
                id=r["id"],
                url=r["url"],
                method=r["method"],
                params=r["params"],
                source_tool=r["source_tool"],
                host_id=r["host_id"],
                found_at=r["found_at"],
            )
            for r in rows
        ]

    # -------- Screenshots --------

    async def insert_screenshot(self, shot: Screenshot) -> int:
        """Insert or ignore a screenshot record. Returns the row id."""
        cursor = await self._db.execute(
            """
            INSERT OR IGNORE INTO screenshots
              (url, path, title, status, source_tool, captured_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                shot.url,
                shot.path,
                shot.title,
                shot.status,
                shot.source_tool,
                shot.captured_at,
            ),
        )
        await self._db.commit()
        if cursor.rowcount == 0:
            row = await (await self._db.execute(
                "SELECT id FROM screenshots WHERE url = ? AND path = ?",
                (shot.url, shot.path),
            )).fetchone()
            return row["id"] if row else 0
        return cursor.lastrowid or 0  # type: ignore[return-value]

    async def get_screenshots(self) -> list[Screenshot]:
        rows = await (await self._db.execute("SELECT * FROM screenshots")).fetchall()
        return [
            Screenshot(
                id=r["id"],
                url=r["url"],
                path=r["path"],
                title=r["title"],
                status=r["status"],
                source_tool=r["source_tool"],
                captured_at=r["captured_at"],
            )
            for r in rows
        ]

    # ── Findings ──────────────────────────────────────────────────────────────

    async def insert_finding(self, f: Finding) -> int:
        cursor = await self._db.execute(
            """
            INSERT INTO findings
              (tool, target, severity, title, evidence, reproducible_steps, raw_output, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f.tool, f.target, f.severity, f.title,
                f.evidence, f.reproducible_steps,
                f.raw_output[:2000],  # cap raw output to avoid DB bloat
                f.timestamp,
            ),
        )
        await self._db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    async def get_findings(self, severity: str | None = None) -> list[Finding]:
        query = "SELECT * FROM findings"
        params: list = []
        if severity:
            query += " WHERE severity = ?"
            params.append(severity.lower())
        query += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
        rows = await (await self._db.execute(query, params)).fetchall()
        return [
            Finding(
                id=r["id"],
                tool=r["tool"],
                target=r["target"],
                severity=r["severity"],
                title=r["title"],
                evidence=r["evidence"],
                reproducible_steps=r["reproducible_steps"],
                raw_output=r["raw_output"],
                timestamp=r["timestamp"],
            )
            for r in rows
        ]

    # ── CVE Cache ─────────────────────────────────────────────────────────────

    async def get_cached_cve(self, keyword: str) -> CVEResult | None:
        row = await (
            await self._db.execute(
                "SELECT * FROM cve_cache WHERE keyword = ? ORDER BY fetched_at DESC LIMIT 1",
                (keyword.lower(),),
            )
        ).fetchone()
        if not row:
            return None
        return CVEResult(
            keyword=row["keyword"],
            cve_id=row["cve_id"],
            description=row["description"],
            cvss_score=row["cvss_score"],
            poc_url=row["poc_url"],
            published_date=row["published_date"],
            fetched_at=row["fetched_at"],
        )

    async def cache_cve(self, cve: CVEResult) -> None:
        await self._db.execute(
            """
            INSERT INTO cve_cache (keyword, cve_id, description, cvss_score, poc_url, published_date, fetched_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cve.keyword.lower(), cve.cve_id, cve.description,
                cve.cvss_score, cve.poc_url, cve.published_date, cve.fetched_at,
            ),
        )
        await self._db.commit()

    # ── Compact summary for AI ────────────────────────────────────────────────

    async def get_summary_for_ai(self) -> str:
        """
        Returns a compact JSON string (< ~500 tokens) that the AI uses to
        decide what to do next.  Raw tool output is NEVER passed to the LLM.
        """
        hosts = await self.get_hosts()
        endpoints = await self.get_endpoints()
        findings = await self.get_findings()

        summary = {
            "hosts_count": len(hosts),
            "hosts_sample": [
                {"domain": h.domain, "status": h.status_code, "tech": h.tech_stack}
                for h in hosts[:10]          # send max 10 examples
            ],
            "endpoints_count": len(endpoints),
            "endpoints_with_params": sum(1 for e in endpoints if e.params),
            "endpoints_sample": [e.url for e in endpoints[:10]],
            "findings": [
                {"severity": f.severity, "title": f.title, "target": f.target}
                for f in findings
            ],
        }
        return json.dumps(summary, indent=2)


# ── Scope helpers ─────────────────────────────────────────────────────────────

