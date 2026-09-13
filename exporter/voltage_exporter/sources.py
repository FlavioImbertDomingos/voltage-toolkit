"""Row sources for the SDM checks: a SQL query over any DB-API driver, or a CSV file.

    source: {type: sql, dsn: "sqlite:///data/nonprod.db"}                    # stdlib sqlite3
    source: {type: sql, driver: psycopg, dsn: "postgresql://ro@db/nonprod",
             password_env: NONPROD_DB_PASSWORD}                             # any DB-API 2.0 driver
    source: {type: sql, driver: pyodbc, connect: {DSN: nonprod, UID: ro}, password_env: ...}
    source: {type: file, path: /exports/customers_masked.csv}

Read-only by construction: one SELECT (or one file), no writes, no DDL. The exporter's
DB account should be read-only too -- say so in the runbook, not just here.
"""

from __future__ import annotations

import csv
import importlib
import os
import sqlite3
from dataclasses import dataclass, field
from typing import Any


class SourceError(Exception):
    pass


@dataclass
class Source:
    type: str  # sql | file
    dsn: str = ""
    driver: str = ""  # DB-API module name; "" + sqlite:// dsn -> stdlib sqlite3
    connect: dict[str, Any] = field(default_factory=dict)  # kwargs for driver.connect()
    password_env: str = ""
    path: str = ""  # file
    timeout: float = 10.0

    @staticmethod
    def from_config(d: dict) -> Source:
        if not isinstance(d, dict) or not d.get("type"):
            raise SourceError("source needs a 'type' (sql | file)")
        t = str(d["type"]).lower()
        if t == "file" and not d.get("path"):
            raise SourceError("file source needs 'path'")
        if t == "sql" and not (d.get("dsn") or d.get("connect")):
            raise SourceError("sql source needs 'dsn' or 'connect'")
        if t not in ("sql", "file"):
            raise SourceError(f"unknown source type {t!r}")
        return Source(
            type=t,
            dsn=str(d.get("dsn") or ""),
            driver=str(d.get("driver") or ""),
            connect=dict(d.get("connect") or {}),
            password_env=str(d.get("password_env") or ""),
            path=str(d.get("path") or ""),
            timeout=float(d.get("timeout_seconds", 10)),
        )

    def describe(self) -> str:
        if self.type == "file":
            return f"file:{self.path}"
        return f"sql:{self.driver or 'sqlite3'}:{_redact(self.dsn) or 'connect{...}'}"


def _redact(dsn: str) -> str:
    # user:password@host -> user:***@host
    if "@" in dsn and "://" in dsn:
        head, _, tail = dsn.partition("://")
        creds, _, rest = tail.rpartition("@")
        if ":" in creds:
            creds = creds.split(":", 1)[0] + ":***"
        return f"{head}://{creds}@{rest}" if creds else dsn
    return dsn


def query_rows(src: Source, query: str = "", columns: list[str] | None = None, limit: int = 100000) -> list[tuple]:
    """Rows as tuples. SQL: the query's columns in order. File: `columns` in order (header names)."""
    if src.type == "file":
        return _file_rows(src, columns or [], limit)
    return _sql_rows(src, query, limit)


def _file_rows(src: Source, columns: list[str], limit: int) -> list[tuple]:
    if not columns:
        raise SourceError("file source needs 'columns' to select")
    try:
        with open(src.path, encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames:
                raise SourceError(f"{src.path}: empty file")
            names = {n.strip().lower(): n for n in reader.fieldnames if n}
            missing = [c for c in columns if c.lower() not in names]
            if missing:
                raise SourceError(f"{src.path}: no column(s) {missing}; header is {reader.fieldnames}")
            out = []
            for r in reader:
                out.append(tuple((r.get(names[c.lower()]) or "") for c in columns))
                if len(out) >= limit:
                    break
            return out
    except OSError as exc:
        raise SourceError(f"{src.path}: {exc}") from exc


def _sql_rows(src: Source, query: str, limit: int) -> list[tuple]:
    if not query:
        raise SourceError("sql source needs 'query'")
    q = query.strip().rstrip(";")
    if not q.lower().startswith(("select", "with")):
        raise SourceError("only SELECT / WITH queries are allowed")
    conn = _connect(src)
    try:
        cur = conn.cursor()
        cur.execute(q)
        rows = cur.fetchmany(limit)
        return [tuple(r) for r in rows]
    except Exception as exc:  # noqa: BLE001 - driver-specific error classes
        raise SourceError(f"{src.describe()}: {type(exc).__name__}: {exc}") from exc
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass


def _connect(src: Source):  # noqa: ANN202 - DB-API connection, type varies by driver
    if not src.driver and src.dsn.startswith("sqlite://"):
        # sqlite:///relative.db -> relative.db ; sqlite:////abs.db -> /abs.db ; sqlite://:memory:
        path = src.dsn[len("sqlite:///") :] if src.dsn.startswith("sqlite:///") else src.dsn[len("sqlite://") :]
        if path != ":memory:" and not os.path.exists(path):
            raise SourceError(f"sqlite database {path} does not exist")
        try:
            if path == ":memory:":
                return sqlite3.connect(path, timeout=src.timeout)
            return sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=src.timeout)
        except sqlite3.Error as exc:
            raise SourceError(f"sqlite {path}: {exc}") from exc
    driver = src.driver or "sqlite3"
    try:
        mod = importlib.import_module(driver)
    except ImportError as exc:
        raise SourceError(f"DB-API driver {driver!r} is not installed in the exporter image") from exc
    kwargs = dict(src.connect)
    if src.password_env:
        pw = os.environ.get(src.password_env)
        if not pw:
            raise SourceError(f"env var {src.password_env} is not set")
        kwargs["password"] = pw
    try:
        if src.dsn and not kwargs:
            return mod.connect(src.dsn)
        if src.dsn:
            return mod.connect(src.dsn, **kwargs)
        return mod.connect(**kwargs)
    except Exception as exc:  # noqa: BLE001
        raise SourceError(f"{src.describe()}: connect failed: {type(exc).__name__}: {exc}") from exc
