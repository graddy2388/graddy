"""
network_bot.web.db.crud – CRUD helpers for the web GUI database.

All functions accept a sqlite3 connection (with row_factory=sqlite3.Row) and
return plain dicts / lists-of-dicts so they're easy to serialise.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _row(row) -> Optional[Dict[str, Any]]:
    return dict(row) if row else None


def _rows(rows) -> List[Dict[str, Any]]:
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------

def get_groups(db) -> List[Dict[str, Any]]:
    cur = db.execute(
        """
        SELECT g.*, COUNT(t.id) AS target_count
        FROM groups g
        LEFT JOIN targets t ON t.group_id = g.id
        GROUP BY g.id
        ORDER BY g.name
        """
    )
    return _rows(cur.fetchall())


def get_group(db, id: int) -> Optional[Dict[str, Any]]:
    cur = db.execute("SELECT * FROM groups WHERE id = ?", (id,))
    return _row(cur.fetchone())


def create_group(db, name: str, description: str = "", color: str = "#6366f1") -> Dict[str, Any]:
    cur = db.execute(
        "INSERT INTO groups (name, description, color) VALUES (?, ?, ?)",
        (name, description, color),
    )
    db.commit()
    return get_group(db, cur.lastrowid)


def update_group(db, id: int, name: str, description: str, color: str) -> Optional[Dict[str, Any]]:
    db.execute(
        "UPDATE groups SET name = ?, description = ?, color = ? WHERE id = ?",
        (name, description, color, id),
    )
    db.commit()
    return get_group(db, id)


def delete_group(db, id: int) -> bool:
    cur = db.execute("DELETE FROM groups WHERE id = ?", (id,))
    db.commit()
    return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------

def get_tags(db) -> List[Dict[str, Any]]:
    cur = db.execute("SELECT * FROM tags ORDER BY name")
    return _rows(cur.fetchall())


def get_tag(db, id: int) -> Optional[Dict[str, Any]]:
    cur = db.execute("SELECT * FROM tags WHERE id = ?", (id,))
    return _row(cur.fetchone())


def create_tag(db, name: str, color: str = "#10b981") -> Dict[str, Any]:
    cur = db.execute("INSERT INTO tags (name, color) VALUES (?, ?)", (name, color))
    db.commit()
    return get_tag(db, cur.lastrowid)


def update_tag(db, id: int, name: str, color: str) -> Optional[Dict[str, Any]]:
    db.execute("UPDATE tags SET name = ?, color = ? WHERE id = ?", (name, color, id))
    db.commit()
    return get_tag(db, id)


def delete_tag(db, id: int) -> bool:
    cur = db.execute("DELETE FROM tags WHERE id = ?", (id,))
    db.commit()
    return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

def _attach_tags(db, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not targets:
        return targets
    ids = [t["id"] for t in targets]
    placeholders = ",".join("?" * len(ids))
    cur = db.execute(
        f"""
        SELECT tt.target_id, t.id, t.name, t.color
        FROM target_tags tt
        JOIN tags t ON t.id = tt.tag_id
        WHERE tt.target_id IN ({placeholders})
        ORDER BY t.name
        """,
        ids,
    )
    tag_map: Dict[int, List[Dict]] = {t["id"]: [] for t in targets}
    for row in cur.fetchall():
        tag_map[row["target_id"]].append(
            {"id": row["id"], "name": row["name"], "color": row["color"]}
        )
    for t in targets:
        t["tags"] = tag_map.get(t["id"], [])
    return targets


def get_targets(db, group_id=None, tag_id=None, enabled_only=False) -> List[Dict[str, Any]]:
    query = """
        SELECT t.id, t.name, t.host, t.group_id, t.checks, t.ports, t.smtp_ports,
               t.enabled, t.notes, t.created_at, t.updated_at,
               COALESCE(t.hostname, '') AS hostname,
               COALESCE(t.last_resolved_ip, '') AS last_resolved_ip,
               COALESCE(t.last_resolved_at, '') AS last_resolved_at,
               g.name AS group_name, g.color AS group_color
        FROM targets t
        LEFT JOIN groups g ON g.id = t.group_id
    """
    conditions = []
    params: List[Any] = []

    if group_id is not None:
        conditions.append("t.group_id = ?")
        params.append(group_id)
    if enabled_only:
        conditions.append("t.enabled = 1")
    if tag_id is not None:
        conditions.append(
            "EXISTS (SELECT 1 FROM target_tags tt WHERE tt.target_id = t.id AND tt.tag_id = ?)"
        )
        params.append(tag_id)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY t.name"

    cur = db.execute(query, params)
    targets = _rows(cur.fetchall())
    return _attach_tags(db, targets)


def get_target(db, id: int) -> Optional[Dict[str, Any]]:
    cur = db.execute(
        """
        SELECT t.id, t.name, t.host, t.group_id, t.checks, t.ports, t.smtp_ports,
               t.enabled, t.notes, t.created_at, t.updated_at,
               COALESCE(t.hostname, '') AS hostname,
               COALESCE(t.last_resolved_ip, '') AS last_resolved_ip,
               COALESCE(t.last_resolved_at, '') AS last_resolved_at,
               g.name AS group_name, g.color AS group_color
        FROM targets t
        LEFT JOIN groups g ON g.id = t.group_id
        WHERE t.id = ?
        """,
        (id,),
    )
    row = _row(cur.fetchone())
    if row is None:
        return None
    return _attach_tags(db, [row])[0]


def create_target(
    db,
    name: str,
    host: str,
    group_id=None,
    checks=None,
    ports=None,
    smtp_ports=None,
    enabled: int = 1,
    notes: str = "",
    hostname: str = "",
    last_resolved_ip: str = "",
    last_resolved_at: str = "",
) -> Dict[str, Any]:
    checks_json = json.dumps(checks) if checks is not None else '["port_scan","ssl","http","dns","vuln","exposed_paths","cipher"]'
    ports_json = json.dumps(ports) if ports is not None else '[80,443]'
    smtp_ports_json = json.dumps(smtp_ports) if smtp_ports is not None else '[25,587,465]'

    cur = db.execute(
        """
        INSERT INTO targets (name, host, group_id, checks, ports, smtp_ports, enabled, notes,
                             hostname, last_resolved_ip, last_resolved_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (name, host, group_id, checks_json, ports_json, smtp_ports_json, int(enabled), notes,
         hostname, last_resolved_ip, last_resolved_at),
    )
    db.commit()
    return get_target(db, cur.lastrowid)


def update_target(db, id: int, **fields) -> Optional[Dict[str, Any]]:
    allowed = {"name", "host", "group_id", "checks", "ports", "smtp_ports", "enabled", "notes",
               "hostname", "last_resolved_ip", "last_resolved_at"}
    update_fields = {k: v for k, v in fields.items() if k in allowed}

    for json_field in ("checks", "ports", "smtp_ports"):
        if json_field in update_fields and isinstance(update_fields[json_field], (list, tuple)):
            update_fields[json_field] = json.dumps(list(update_fields[json_field]))

    if not update_fields:
        return get_target(db, id)

    set_clause = ", ".join(f"{k} = ?" for k in update_fields)
    set_clause += ", updated_at = datetime('now')"
    values = list(update_fields.values()) + [id]

    db.execute(f"UPDATE targets SET {set_clause} WHERE id = ?", values)
    db.commit()
    return get_target(db, id)


def delete_target(db, id: int) -> bool:
    cur = db.execute("DELETE FROM targets WHERE id = ?", (id,))
    db.commit()
    return cur.rowcount > 0


def set_target_tags(db, target_id: int, tag_ids: List[int]) -> None:
    db.execute("DELETE FROM target_tags WHERE target_id = ?", (target_id,))
    for tag_id in tag_ids:
        db.execute(
            "INSERT OR IGNORE INTO target_tags (target_id, tag_id) VALUES (?, ?)",
            (target_id, tag_id),
        )
    db.commit()


def import_from_yaml(db, targets: List[Dict[str, Any]]) -> int:
    imported = 0
    for t in targets:
        host = t.get("host", "")
        name = t.get("name", host)
        if not host:
            continue

        group_id = None
        group_name = t.get("group")
        if group_name:
            cur = db.execute("SELECT id FROM groups WHERE name = ?", (group_name,))
            row = cur.fetchone()
            if row:
                group_id = row["id"]
            else:
                cur2 = db.execute("INSERT INTO groups (name) VALUES (?)", (group_name,))
                db.commit()
                group_id = cur2.lastrowid

        checks = t.get("checks")
        ports = t.get("ports")
        smtp_ports = t.get("smtp_ports")
        enabled = int(t.get("enabled", 1))
        notes = t.get("notes", "")

        checks_json = json.dumps(checks) if checks else '["port_scan","ssl","http","dns","vuln","exposed_paths","cipher"]'
        ports_json = json.dumps(ports) if ports else '[80,443]'
        smtp_ports_json = json.dumps(smtp_ports) if smtp_ports else '[25,587,465]'

        cur = db.execute(
            """
            INSERT INTO targets (name, host, group_id, checks, ports, smtp_ports, enabled, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (name, host, group_id, checks_json, ports_json, smtp_ports_json, enabled, notes),
        )
        db.commit()
        target_id = cur.lastrowid

        tag_names = t.get("tags", [])
        tag_ids = []
        for tag_name in tag_names:
            cur2 = db.execute("SELECT id FROM tags WHERE name = ?", (tag_name,))
            row = cur2.fetchone()
            if row:
                tag_ids.append(row["id"])
            else:
                cur3 = db.execute("INSERT INTO tags (name) VALUES (?)", (tag_name,))
                db.commit()
                tag_ids.append(cur3.lastrowid)

        set_target_tags(db, target_id, tag_ids)
        imported += 1

    return imported


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

def create_scan(
    db,
    triggered_by: str = "manual",
    filter_group: Optional[str] = None,
    filter_tag: Optional[str] = None,
    profile_id: Optional[int] = None,
) -> Dict[str, Any]:
    started_at = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        """
        INSERT INTO scans (started_at, triggered_by, filter_group, filter_tag, profile_id)
        VALUES (?, ?, ?, ?, ?)
        """,
        (started_at, triggered_by, filter_group, filter_tag, profile_id),
    )
    db.commit()
    return get_scan(db, cur.lastrowid)


def finish_scan(db, id: int, counts: Dict[str, int]) -> None:
    finished_at = datetime.now(timezone.utc).isoformat()
    db.execute(
        """
        UPDATE scans
        SET status = 'completed',
            finished_at = ?,
            total_targets = ?,
            critical_count = ?,
            high_count = ?,
            medium_count = ?,
            low_count = ?,
            info_count = ?
        WHERE id = ?
        """,
        (
            finished_at,
            counts.get("total_targets", 0),
            counts.get("critical", 0),
            counts.get("high", 0),
            counts.get("medium", 0),
            counts.get("low", 0),
            counts.get("info", 0),
            id,
        ),
    )
    db.commit()


def fail_scan(db, id: int) -> None:
    finished_at = datetime.now(timezone.utc).isoformat()
    db.execute(
        "UPDATE scans SET status = 'failed', finished_at = ? WHERE id = ?",
        (finished_at, id),
    )
    db.commit()


def get_scans(db, limit: int = 50) -> List[Dict[str, Any]]:
    cur = db.execute(
        "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
    )
    return _rows(cur.fetchall())


def get_scan(db, id: int) -> Optional[Dict[str, Any]]:
    cur = db.execute("SELECT * FROM scans WHERE id = ?", (id,))
    return _row(cur.fetchone())


def add_scan_result(
    db,
    scan_id: int,
    target_host: str,
    target_name: Optional[str],
    check_name: str,
    passed: bool,
    findings: list,
    metadata: dict,
    error: Optional[str],
    timestamp: Optional[str],
) -> None:
    db.execute(
        """
        INSERT INTO scan_results
            (scan_id, target_host, target_name, check_name, passed, findings, metadata, error, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            target_host,
            target_name,
            check_name,
            int(passed),
            json.dumps(findings),
            json.dumps(metadata),
            error,
            timestamp,
        ),
    )
    db.commit()


def add_host_history(db, target_id: int, hostname: str, ip_address: str) -> None:
    db.execute(
        "INSERT INTO host_history (target_id, hostname, ip_address) VALUES (?, ?, ?)",
        (target_id, hostname, ip_address),
    )
    db.commit()


def get_host_history(db, target_id: int) -> List[Dict[str, Any]]:
    cur = db.execute(
        "SELECT * FROM host_history WHERE target_id = ? ORDER BY resolved_at DESC",
        (target_id,),
    )
    return _rows(cur.fetchall())


def get_scan_results(db, scan_id: int) -> List[Dict[str, Any]]:
    cur = db.execute(
        "SELECT * FROM scan_results WHERE scan_id = ? ORDER BY id",
        (scan_id,),
    )
    rows = _rows(cur.fetchall())
    for row in rows:
        if isinstance(row.get("findings"), str):
            try:
                row["findings"] = json.loads(row["findings"])
            except Exception:
                row["findings"] = []
        if isinstance(row.get("metadata"), str):
            try:
                row["metadata"] = json.loads(row["metadata"])
            except Exception:
                row["metadata"] = {}
    return rows


def get_dashboard_stats(db) -> dict:
    cur = db.execute(
        "SELECT id FROM scans WHERE status = 'completed' ORDER BY started_at DESC LIMIT 10"
    )
    recent_scan_ids = [r["id"] for r in cur.fetchall()]

    threat_map: Dict[str, Dict[str, Any]] = {}
    recent_findings: List[Dict[str, Any]] = []

    if recent_scan_ids:
        placeholders = ",".join("?" * len(recent_scan_ids))
        cur = db.execute(
            f"""
            SELECT sr.target_name, sr.target_host, sr.check_name, sr.findings,
                   sr.scan_id, sr.timestamp
            FROM scan_results sr
            WHERE sr.scan_id IN ({placeholders})
            ORDER BY sr.scan_id DESC, sr.id DESC
            """,
            recent_scan_ids,
        )
        for row in cur.fetchall():
            try:
                findings_list = json.loads(row["findings"] or "[]")
            except Exception:
                findings_list = []
            target_label = row["target_name"] or row["target_host"]
            for f in findings_list:
                title = f.get("title", "")
                severity = f.get("severity", "info")
                key = f"{title}|{severity}"
                if key not in threat_map:
                    threat_map[key] = {"title": title, "severity": severity, "count": 0, "targets": []}
                threat_map[key]["count"] += 1
                if target_label not in threat_map[key]["targets"]:
                    threat_map[key]["targets"].append(target_label)
                if len(recent_findings) < 15:
                    recent_findings.append({
                        "target": target_label,
                        "check": row["check_name"],
                        "severity": severity,
                        "title": title,
                        "scan_id": row["scan_id"],
                        "ts": row["timestamp"] or "",
                    })

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    top_threats = sorted(
        threat_map.values(),
        key=lambda x: (sev_order.get(x["severity"], 5), -x["count"]),
    )[:10]

    cur = db.execute(
        """
        SELECT sr.target_name, sr.target_host, sr.findings
        FROM scan_results sr
        INNER JOIN (
            SELECT target_host, MAX(scan_id) AS max_scan_id
            FROM scan_results
            GROUP BY target_host
        ) latest ON sr.target_host = latest.target_host AND sr.scan_id = latest.max_scan_id
        """
    )
    vuln_map: Dict[str, Dict[str, Any]] = {}
    for row in cur.fetchall():
        try:
            findings_list = json.loads(row["findings"] or "[]")
        except Exception:
            findings_list = []
        host = row["target_host"]
        name = row["target_name"] or host
        if host not in vuln_map:
            vuln_map[host] = {"name": name, "host": host, "critical": 0, "high": 0}
        for f in findings_list:
            sev = f.get("severity", "")
            if sev == "critical":
                vuln_map[host]["critical"] += 1
            elif sev == "high":
                vuln_map[host]["high"] += 1

    for v in vuln_map.values():
        v["score"] = v["critical"] * 10 + v["high"] * 5

    vulnerable_targets = sorted(
        vuln_map.values(), key=lambda x: -x["score"]
    )[:5]

    cur = db.execute(
        """
        SELECT id, started_at, critical_count, high_count, medium_count, low_count, info_count
        FROM scans
        WHERE status = 'completed'
        ORDER BY started_at DESC
        LIMIT 7
        """
    )
    trend_rows = list(reversed(_rows(cur.fetchall())))
    trend = []
    for row in trend_rows:
        label = (row["started_at"] or "")[:10]
        trend.append({
            "label": label,
            "critical": row["critical_count"] or 0,
            "high": row["high_count"] or 0,
            "medium": row["medium_count"] or 0,
            "low": row["low_count"] or 0,
        })

    return {
        "top_threats": top_threats,
        "vulnerable_targets": vulnerable_targets,
        "trend": trend,
        "recent_findings": recent_findings[:15],
    }


# ---------------------------------------------------------------------------
# Scan Profiles
# ---------------------------------------------------------------------------

def get_scan_profiles(db) -> List[Dict[str, Any]]:
    cur = db.execute("SELECT * FROM scan_profiles ORDER BY name")
    rows = _rows(cur.fetchall())
    for row in rows:
        for f in ("checks", "ports", "smtp_ports", "tools"):
            if isinstance(row.get(f), str):
                try:
                    row[f] = json.loads(row[f])
                except Exception:
                    row[f] = []
    return rows


def get_scan_profile(db, id: int) -> Optional[Dict[str, Any]]:
    cur = db.execute("SELECT * FROM scan_profiles WHERE id = ?", (id,))
    row = _row(cur.fetchone())
    if row is None:
        return None
    for f in ("checks", "ports", "smtp_ports", "tools"):
        if isinstance(row.get(f), str):
            try:
                row[f] = json.loads(row[f])
            except Exception:
                row[f] = []
    return row


def create_scan_profile(
    db,
    name: str,
    description: str = "",
    checks: Optional[List] = None,
    ports: Optional[List] = None,
    smtp_ports: Optional[List] = None,
    nmap_args: str = "-sV -sC --top-ports 1000",
    tools: Optional[List] = None,
    intensity: str = "normal",
) -> Dict[str, Any]:
    default_checks = ["port_scan", "ssl", "http", "dns", "vuln", "exposed_paths", "cipher"]
    default_ports = [80, 443, 8080, 8443, 21, 22, 23, 25, 53, 110, 143, 445, 3306, 3389, 5432, 6379, 9200, 27017]
    cur = db.execute(
        """
        INSERT INTO scan_profiles (name, description, checks, ports, smtp_ports, nmap_args, tools, intensity)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            name, description,
            json.dumps(checks or default_checks),
            json.dumps(ports or default_ports),
            json.dumps(smtp_ports or [25, 587, 465]),
            nmap_args,
            json.dumps(tools or ["nmap"]),
            intensity,
        ),
    )
    db.commit()
    return get_scan_profile(db, cur.lastrowid)


def update_scan_profile(db, id: int, **fields) -> Optional[Dict[str, Any]]:
    allowed = {"name", "description", "checks", "ports", "smtp_ports", "nmap_args", "tools", "intensity"}
    update_fields = {k: v for k, v in fields.items() if k in allowed}
    for list_field in ("checks", "ports", "smtp_ports", "tools"):
        if list_field in update_fields and isinstance(update_fields[list_field], (list, tuple)):
            update_fields[list_field] = json.dumps(list(update_fields[list_field]))
    if not update_fields:
        return get_scan_profile(db, id)
    set_clause = ", ".join(f"{k} = ?" for k in update_fields)
    set_clause += ", updated_at = datetime('now')"
    values = list(update_fields.values()) + [id]
    db.execute(f"UPDATE scan_profiles SET {set_clause} WHERE id = ?", values)
    db.commit()
    return get_scan_profile(db, id)


def delete_scan_profile(db, id: int) -> bool:
    cur = db.execute("DELETE FROM scan_profiles WHERE id = ?", (id,))
    db.commit()
    return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Schedules
# ---------------------------------------------------------------------------

def get_schedules(db) -> List[Dict[str, Any]]:
    cur = db.execute(
        """
        SELECT s.*, p.name AS profile_name
        FROM schedules s
        LEFT JOIN scan_profiles p ON p.id = s.profile_id
        ORDER BY s.name
        """
    )
    return _rows(cur.fetchall())


def get_schedule(db, id: int) -> Optional[Dict[str, Any]]:
    cur = db.execute(
        """
        SELECT s.*, p.name AS profile_name
        FROM schedules s
        LEFT JOIN scan_profiles p ON p.id = s.profile_id
        WHERE s.id = ?
        """,
        (id,),
    )
    return _row(cur.fetchone())


def create_schedule(
    db,
    name: str,
    cron_expr: str,
    cron_human: str = "",
    target_filter: str = "all",
    profile_id: Optional[int] = None,
    enabled: int = 1,
) -> Dict[str, Any]:
    cur = db.execute(
        """
        INSERT INTO schedules (name, cron_expr, cron_human, target_filter, profile_id, enabled)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (name, cron_expr, cron_human, target_filter, profile_id, int(enabled)),
    )
    db.commit()
    return get_schedule(db, cur.lastrowid)


def update_schedule(db, id: int, **fields) -> Optional[Dict[str, Any]]:
    allowed = {"name", "cron_expr", "cron_human", "target_filter", "profile_id", "enabled", "last_run", "next_run"}
    update_fields = {k: v for k, v in fields.items() if k in allowed}
    if not update_fields:
        return get_schedule(db, id)
    set_clause = ", ".join(f"{k} = ?" for k in update_fields)
    values = list(update_fields.values()) + [id]
    db.execute(f"UPDATE schedules SET {set_clause} WHERE id = ?", values)
    db.commit()
    return get_schedule(db, id)


def delete_schedule(db, id: int) -> bool:
    cur = db.execute("DELETE FROM schedules WHERE id = ?", (id,))
    db.commit()
    return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Scope Ranges
# ---------------------------------------------------------------------------

def get_scope_ranges(db) -> List[Dict[str, Any]]:
    cur = db.execute("SELECT * FROM scope_ranges ORDER BY cidr")
    return _rows(cur.fetchall())


def create_scope_range(db, cidr: str, description: str = "", in_scope: int = 1) -> Dict[str, Any]:
    cur = db.execute(
        "INSERT OR REPLACE INTO scope_ranges (cidr, description, in_scope) VALUES (?, ?, ?)",
        (cidr, description, int(in_scope)),
    )
    db.commit()
    row = db.execute("SELECT * FROM scope_ranges WHERE id = ?", (cur.lastrowid,)).fetchone()
    return _row(row)


def delete_scope_range(db, id: int) -> bool:
    cur = db.execute("DELETE FROM scope_ranges WHERE id = ?", (id,))
    db.commit()
    return cur.rowcount > 0


def is_in_scope(db, ip_or_cidr: str) -> bool:
    """Check whether a given IP address is covered by any in-scope range."""
    import ipaddress
    try:
        target_ip = ipaddress.ip_address(ip_or_cidr)
    except ValueError:
        return True  # Can't parse – allow by default (hostname)

    rows = get_scope_ranges(db)
    in_scope_ranges = [r for r in rows if r["in_scope"]]
    excluded_ranges = [r for r in rows if not r["in_scope"]]

    if not in_scope_ranges:
        return True  # No scope defined → everything allowed

    # Check explicit exclusions first
    for r in excluded_ranges:
        try:
            if target_ip in ipaddress.ip_network(r["cidr"], strict=False):
                return False
        except ValueError:
            pass

    # Check inclusions
    for r in in_scope_ranges:
        try:
            if target_ip in ipaddress.ip_network(r["cidr"], strict=False):
                return True
        except ValueError:
            pass

    return False


# ---------------------------------------------------------------------------
# Host Inventory
# ---------------------------------------------------------------------------

def get_host_inventory(db) -> List[Dict[str, Any]]:
    cur = db.execute(
        "SELECT * FROM host_inventory ORDER BY ip_address"
    )
    rows = _rows(cur.fetchall())
    for row in rows:
        for f in ("open_ports",):
            if isinstance(row.get(f), str):
                try:
                    row[f] = json.loads(row[f])
                except Exception:
                    row[f] = []
        if isinstance(row.get("services"), str):
            try:
                row["services"] = json.loads(row["services"])
            except Exception:
                row["services"] = {}
    return rows


def upsert_host_inventory(
    db,
    ip_address: str,
    hostname: str = "",
    mac_address: str = "",
    os_guess: str = "",
    open_ports: Optional[List] = None,
    services: Optional[Dict] = None,
) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    existing = db.execute(
        "SELECT id FROM host_inventory WHERE ip_address = ?", (ip_address,)
    ).fetchone()
    if existing:
        db.execute(
            """
            UPDATE host_inventory
            SET hostname = ?, mac_address = ?, os_guess = ?,
                open_ports = ?, services = ?, last_seen = ?, is_alive = 1
            WHERE ip_address = ?
            """,
            (
                hostname or "",
                mac_address or "",
                os_guess or "",
                json.dumps(open_ports or []),
                json.dumps(services or {}),
                now,
                ip_address,
            ),
        )
    else:
        db.execute(
            """
            INSERT INTO host_inventory
                (ip_address, hostname, mac_address, os_guess, open_ports, services, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ip_address,
                hostname or "",
                mac_address or "",
                os_guess or "",
                json.dumps(open_ports or []),
                json.dumps(services or {}),
                now,
                now,
            ),
        )
    db.commit()
    row = db.execute(
        "SELECT * FROM host_inventory WHERE ip_address = ?", (ip_address,)
    ).fetchone()
    return _row(row)


# ---------------------------------------------------------------------------
# Host Services
# ---------------------------------------------------------------------------

def upsert_host_service(
    db,
    host_ip: str,
    port: int,
    protocol: str = "tcp",
    service_name: str = "",
    service_version: str = "",
    banner: str = "",
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        """
        INSERT INTO host_services (host_ip, port, protocol, service_name, service_version, banner, last_updated)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(host_ip, port, protocol) DO UPDATE SET
            service_name = excluded.service_name,
            service_version = excluded.service_version,
            banner = excluded.banner,
            last_updated = excluded.last_updated
        """,
        (host_ip, port, protocol, service_name, service_version, banner, now),
    )
    db.commit()


def get_host_services(db, host_ip: str) -> List[Dict[str, Any]]:
    cur = db.execute(
        "SELECT * FROM host_services WHERE host_ip = ? ORDER BY port",
        (host_ip,),
    )
    return _rows(cur.fetchall())


# ---------------------------------------------------------------------------
# Host Identities
# ---------------------------------------------------------------------------

def get_host_identities(db, host_ip: str) -> List[Dict[str, Any]]:
    cur = db.execute(
        "SELECT * FROM host_identities WHERE host_ip = ? ORDER BY identity_type, username",
        (host_ip,),
    )
    rows = _rows(cur.fetchall())
    for row in rows:
        if isinstance(row.get("groups"), str):
            try:
                row["groups"] = json.loads(row["groups"])
            except Exception:
                row["groups"] = []
    return rows


def add_host_identity(
    db,
    host_ip: str,
    identity_type: str,
    username: str = "",
    domain: str = "",
    full_name: str = "",
    groups: Optional[List] = None,
    is_active: int = 1,
    is_admin: int = 0,
    source: str = "",
    scan_id: Optional[int] = None,
) -> None:
    db.execute(
        """
        INSERT INTO host_identities
            (host_ip, identity_type, username, domain, full_name, groups, is_active, is_admin, source, scan_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (host_ip, identity_type, username, domain, full_name, json.dumps(groups or []),
         int(is_active), int(is_admin), source, scan_id),
    )
    db.commit()


# ---------------------------------------------------------------------------
# AI Events
# ---------------------------------------------------------------------------

def get_ai_events(db, limit: int = 100) -> List[Dict[str, Any]]:
    cur = db.execute(
        "SELECT * FROM ai_events ORDER BY detected_at DESC LIMIT ?", (limit,)
    )
    return _rows(cur.fetchall())


def add_ai_event(
    db,
    target_host: str,
    event_type: str,
    tool_name: str = "",
    description: str = "",
    scan_id: Optional[int] = None,
    severity: str = "info",
    raw_evidence: str = "",
) -> None:
    db.execute(
        """
        INSERT INTO ai_events
            (target_host, event_type, tool_name, description, scan_id, severity, raw_evidence)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (target_host, event_type, tool_name, description, scan_id, severity, raw_evidence),
    )
    db.commit()
