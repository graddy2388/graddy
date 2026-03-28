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
) -> Dict[str, Any]:
    started_at = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        """
        INSERT INTO scans (started_at, triggered_by, filter_group, filter_tag)
        VALUES (?, ?, ?, ?)
        """,
        (started_at, triggered_by, filter_group, filter_tag),
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
        """
        INSERT INTO host_history (target_id, hostname, ip_address)
        VALUES (?, ?, ?)
        """,
        (target_id, hostname, ip_address),
    )
    db.commit()


def get_host_history(db, target_id: int) -> List[Dict[str, Any]]:
    cur = db.execute(
        "SELECT * FROM host_history WHERE target_id = ? ORDER BY resolved_at DESC",
        (target_id,),
    )
    return _rows(cur.fetchall())


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
