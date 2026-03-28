"""
network_bot.web.db.schema – SQLite schema initialization and connection helper.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path


_SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    color TEXT DEFAULT '#6366f1',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    color TEXT DEFAULT '#10b981'
);

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL,
    checks TEXT DEFAULT '["port_scan","ssl","http","dns","vuln","exposed_paths","cipher"]',
    ports TEXT DEFAULT '[80,443]',
    smtp_ports TEXT DEFAULT '[25,587,465]',
    enabled INTEGER DEFAULT 1,
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    hostname TEXT DEFAULT '',
    last_resolved_ip TEXT DEFAULT '',
    last_resolved_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS host_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    hostname TEXT DEFAULT '',
    ip_address TEXT DEFAULT '',
    resolved_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS target_tags (
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    tag_id INTEGER REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (target_id, tag_id)
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT DEFAULT 'running',
    triggered_by TEXT DEFAULT 'manual',
    filter_group TEXT,
    filter_tag TEXT,
    total_targets INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    target_host TEXT NOT NULL,
    target_name TEXT,
    check_name TEXT NOT NULL,
    passed INTEGER NOT NULL,
    findings TEXT DEFAULT '[]',
    metadata TEXT DEFAULT '{}',
    error TEXT,
    timestamp TEXT
);
"""


@contextmanager
def get_db(db_path: str):
    """Context manager that yields a SQLite connection with row_factory and foreign keys enabled."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _migrate(conn) -> None:
    """Add new columns to existing tables if they do not already exist."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(targets)")}
    for col, defn in [
        ("hostname", "TEXT DEFAULT ''"),
        ("last_resolved_ip", "TEXT DEFAULT ''"),
        ("last_resolved_at", "TEXT DEFAULT ''"),
    ]:
        if col not in existing:
            conn.execute(f"ALTER TABLE targets ADD COLUMN {col} {defn}")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS host_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
            hostname TEXT DEFAULT '',
            ip_address TEXT DEFAULT '',
            resolved_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()


def init_db(db_path: str) -> None:
    """Create all tables if they do not already exist."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(_SCHEMA_SQL)
    conn.commit()
    _migrate(conn)
    conn.close()
