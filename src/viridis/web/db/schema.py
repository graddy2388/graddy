"""
viridis.web.db.schema – SQLite schema initialization and connection helper.
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

-- ── Scans ──────────────────────────────────────────────────────────────────

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
    info_count INTEGER DEFAULT 0,
    profile_id INTEGER REFERENCES scan_profiles(id) ON DELETE SET NULL
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

-- ── Scan Profiles ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scan_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    checks TEXT DEFAULT '["port_scan","ssl","http","dns","vuln","exposed_paths","cipher"]',
    ports TEXT DEFAULT '[80,443,8080,8443,21,22,23,25,53,110,143,445,3306,3389,5432,6379,9200,27017]',
    smtp_ports TEXT DEFAULT '[25,587,465]',
    nmap_args TEXT DEFAULT '-sV -sC --top-ports 1000',
    tools TEXT DEFAULT '["nmap"]',
    intensity TEXT DEFAULT 'normal',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

-- ── Persistent Schedules ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    cron_expr TEXT NOT NULL,
    cron_human TEXT DEFAULT '',
    target_filter TEXT DEFAULT 'all',
    profile_id INTEGER REFERENCES scan_profiles(id) ON DELETE SET NULL,
    last_run TEXT,
    next_run TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

-- ── Scope Ranges ───────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scope_ranges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    in_scope INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
);

-- ── Host Inventory (discovered via subnet scan) ────────────────────────────

CREATE TABLE IF NOT EXISTS host_inventory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    hostname TEXT DEFAULT '',
    mac_address TEXT DEFAULT '',
    os_guess TEXT DEFAULT '',
    first_seen TEXT DEFAULT (datetime('now')),
    last_seen TEXT DEFAULT (datetime('now')),
    is_alive INTEGER DEFAULT 1,
    open_ports TEXT DEFAULT '[]',
    services TEXT DEFAULT '{}',
    notes TEXT DEFAULT ''
);

-- ── Host Services (detailed per-port service info) ─────────────────────────

CREATE TABLE IF NOT EXISTS host_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    service_name TEXT DEFAULT '',
    service_version TEXT DEFAULT '',
    banner TEXT DEFAULT '',
    last_updated TEXT DEFAULT (datetime('now')),
    UNIQUE(host_ip, port, protocol)
);

-- ── Identities (users/accounts discovered on hosts) ───────────────────────

CREATE TABLE IF NOT EXISTS host_identities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip TEXT NOT NULL,
    identity_type TEXT NOT NULL,
    username TEXT DEFAULT '',
    domain TEXT DEFAULT '',
    full_name TEXT DEFAULT '',
    groups TEXT DEFAULT '[]',
    is_active INTEGER DEFAULT 1,
    is_admin INTEGER DEFAULT 0,
    source TEXT DEFAULT '',
    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    discovered_at TEXT DEFAULT (datetime('now'))
);

-- ── Host Software Inventory ───────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS host_software (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_ip TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT DEFAULT '',
    source TEXT DEFAULT '',
    port INTEGER DEFAULT 0,
    cve_ids TEXT DEFAULT '[]',
    cve_summary TEXT DEFAULT '[]',
    last_seen TEXT DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_host_software_uniq ON host_software(host_ip, name, source, port);

-- ── AI Events (AI tool usage / exploitation detection) ────────────────────

CREATE TABLE IF NOT EXISTS ai_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_host TEXT NOT NULL,
    event_type TEXT NOT NULL,
    tool_name TEXT DEFAULT '',
    description TEXT DEFAULT '',
    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    severity TEXT DEFAULT 'info',
    raw_evidence TEXT DEFAULT '',
    detected_at TEXT DEFAULT (datetime('now'))
);
"""


@contextmanager
def get_db(db_path: str):
    """Context manager that yields a SQLite connection with row_factory and foreign keys enabled."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
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
    """Safely add new columns / tables to existing databases without data loss."""
    # targets columns
    existing_targets = {row[1] for row in conn.execute("PRAGMA table_info(targets)")}
    for col, defn in [
        ("hostname",         "TEXT DEFAULT ''"),
        ("last_resolved_ip", "TEXT DEFAULT ''"),
        ("last_resolved_at", "TEXT DEFAULT ''"),
        ("risk_score",       "INTEGER DEFAULT 0"),
        ("last_scanned_at",  "TEXT DEFAULT ''"),
        ("criticality",      "TEXT DEFAULT 'medium'"),
    ]:
        if col not in existing_targets:
            conn.execute(f"ALTER TABLE targets ADD COLUMN {col} {defn}")

    # scans columns
    existing_scans = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
    for col, defn in [
        ("profile_id",  "INTEGER"),
        ("scan_type",   "TEXT DEFAULT 'general'"),
        ("is_external", "INTEGER DEFAULT 0"),
        ("scan_name",   "TEXT DEFAULT ''"),
    ]:
        if col not in existing_scans:
            conn.execute(f"ALTER TABLE scans ADD COLUMN {col} {defn}")

    # Ensure all new tables exist (CREATE TABLE IF NOT EXISTS handles this)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS host_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
            hostname TEXT DEFAULT '',
            ip_address TEXT DEFAULT '',
            resolved_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS scan_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT DEFAULT '',
            checks TEXT DEFAULT '["port_scan","ssl","http","dns","vuln","exposed_paths","cipher"]',
            ports TEXT DEFAULT '[80,443,8080,8443,21,22,23,25,53,110,143,445,3306,3389,5432,6379,9200,27017]',
            smtp_ports TEXT DEFAULT '[25,587,465]',
            nmap_args TEXT DEFAULT '-sV -sC --top-ports 1000',
            tools TEXT DEFAULT '["nmap"]',
            intensity TEXT DEFAULT 'normal',
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            cron_expr TEXT NOT NULL,
            cron_human TEXT DEFAULT '',
            target_filter TEXT DEFAULT 'all',
            profile_id INTEGER REFERENCES scan_profiles(id) ON DELETE SET NULL,
            last_run TEXT,
            next_run TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS scope_ranges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cidr TEXT NOT NULL UNIQUE,
            description TEXT DEFAULT '',
            in_scope INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS host_inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            hostname TEXT DEFAULT '',
            mac_address TEXT DEFAULT '',
            os_guess TEXT DEFAULT '',
            first_seen TEXT DEFAULT (datetime('now')),
            last_seen TEXT DEFAULT (datetime('now')),
            is_alive INTEGER DEFAULT 1,
            open_ports TEXT DEFAULT '[]',
            services TEXT DEFAULT '{}',
            notes TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS host_services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT DEFAULT 'tcp',
            service_name TEXT DEFAULT '',
            service_version TEXT DEFAULT '',
            banner TEXT DEFAULT '',
            last_updated TEXT DEFAULT (datetime('now')),
            UNIQUE(host_ip, port, protocol)
        );

        CREATE TABLE IF NOT EXISTS host_identities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_ip TEXT NOT NULL,
            identity_type TEXT NOT NULL,
            username TEXT DEFAULT '',
            domain TEXT DEFAULT '',
            full_name TEXT DEFAULT '',
            groups TEXT DEFAULT '[]',
            is_active INTEGER DEFAULT 1,
            is_admin INTEGER DEFAULT 0,
            source TEXT DEFAULT '',
            scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
            discovered_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS ai_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_host TEXT NOT NULL,
            event_type TEXT NOT NULL,
            tool_name TEXT DEFAULT '',
            description TEXT DEFAULT '',
            scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
            severity TEXT DEFAULT 'info',
            raw_evidence TEXT DEFAULT '',
            detected_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS host_software (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_ip TEXT NOT NULL,
            name TEXT NOT NULL,
            version TEXT DEFAULT '',
            source TEXT DEFAULT '',
            port INTEGER DEFAULT 0,
            cve_ids TEXT DEFAULT '[]',
            cve_summary TEXT DEFAULT '[]',
            last_seen TEXT DEFAULT (datetime('now'))
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_host_software_uniq
            ON host_software(host_ip, name, source, port);
    """)
    conn.commit()


_DEFAULT_TAGS = [
    # OS
    ("windows",          "#3b82f6"),
    ("linux",            "#f97316"),
    ("macos",            "#8b5cf6"),
    ("unix",             "#6366f1"),
    # Device type
    ("web-server",       "#06b6d4"),
    ("database",         "#6366f1"),
    ("domain-controller","#dc2626"),
    ("firewall",         "#d97706"),
    ("router",           "#0891b2"),
    ("workstation",      "#4b5563"),
    ("server",           "#059669"),
    ("printer",          "#84cc16"),
    ("iot",              "#ec4899"),
    # Zone / classification
    ("dmz",              "#f59e0b"),
    ("internal",         "#10b981"),
    ("external",         "#ef4444"),
    ("critical",         "#dc2626"),
]


def init_db(db_path: str) -> None:
    """Create all tables and seed default data if not already present."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(_SCHEMA_SQL)
    conn.commit()
    _migrate(conn)
    # Seed default tags (skip if already exist)
    for name, color in _DEFAULT_TAGS:
        conn.execute(
            "INSERT OR IGNORE INTO tags (name, color) VALUES (?, ?)",
            (name, color),
        )
    # Seed default "General" group — all new targets start here
    conn.execute(
        "INSERT OR IGNORE INTO groups (name, description, color) VALUES (?, ?, ?)",
        ("General", "Default group for all targets", "#4b5563"),
    )
    conn.commit()
    conn.close()
