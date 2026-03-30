"""
network_bot.web.app – FastAPI application factory.
"""
from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .db.crud import (
    get_scans, get_targets, get_groups, get_tags, get_scan, get_scan_results,
    get_scan_profiles, get_schedules, get_scope_ranges,
    get_host_inventory, get_host_services, get_host_identities,
    get_ai_events, diff_scans,
)
import json as _json
from .db.schema import get_db
from . import active_scans  # shared dict in web/__init__.py


def _make_db_dep(db_path: str):
    """Return a FastAPI dependency that yields a sqlite3 connection."""
    def dep():
        # check_same_thread=False required when async endpoints use sync deps:
        # FastAPI runs sync generators in a thread pool, but async handlers run
        # in the event loop thread — SQLite's default check would reject this.
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()
    return dep


def _tr(templates: Jinja2Templates, request: Request, name: str, ctx: dict):
    """Compatibility wrapper: tries new API (request first), falls back to old."""
    try:
        return templates.TemplateResponse(request=request, name=name, context=ctx)
    except TypeError:
        ctx = dict(ctx)
        ctx["request"] = request
        return templates.TemplateResponse(name=name, context=ctx)


def create_app(config: Dict[str, Any]) -> FastAPI:
    app = FastAPI(title="Viridis – Security Platform", docs_url="/api/docs")

    db_path = config.get("web", {}).get("db_path", "data/network_bot.db")

    # Jinja2 templates
    templates_dir = Path(__file__).parent / "templates"
    templates = Jinja2Templates(directory=str(templates_dir))

    # DB dependency
    get_db_dep = _make_db_dep(db_path)

    # ── Initialize DB and start scheduler ──────────────────────────────────
    from .db.schema import init_db
    init_db(db_path)

    scheduler = None
    try:
        from .scheduler_service import get_scheduler, reload_all_schedules
        scheduler = get_scheduler(db_path)
        reload_all_schedules(scheduler, db_path, config)
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning("Scheduler not available: %s", exc)

    # ── Register API routers ───────────────────────────────────────────────
    from .api.groups import make_router as groups_router
    from .api.tags import make_router as tags_router
    from .api.targets import make_router as targets_router
    from .api.scans import make_router as scans_router
    from .api.dashboard import make_router as dashboard_router
    from .api.profiles import make_router as profiles_router
    from .api.schedules import make_router as schedules_router
    from .api.scope import make_router as scope_router
    from .api.hosts import make_router as hosts_router
    from .api.export import make_router as export_router

    app.include_router(groups_router(get_db_dep))
    app.include_router(tags_router(get_db_dep))
    app.include_router(targets_router(get_db_dep))
    app.include_router(scans_router(get_db_dep, config, db_path, active_scans))
    app.include_router(dashboard_router(get_db_dep))
    app.include_router(profiles_router(get_db_dep))
    app.include_router(schedules_router(get_db_dep, config, db_path, scheduler))
    app.include_router(scope_router(get_db_dep))
    app.include_router(hosts_router(get_db_dep))
    app.include_router(export_router(get_db_dep))

    # ── Page routes ────────────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        with get_db(db_path) as db:
            scans = get_scans(db, limit=10)
            targets = get_targets(db)
            groups = get_groups(db)
            tags = get_tags(db)
            hosts = get_host_inventory(db)
            last_scan = scans[0] if scans else None

            # Top threats: most severe findings across recent scans
            top_threats = []
            worst_map: dict = {}
            if scans:
                recent_ids = [s["id"] for s in scans[:5]]
                placeholders = ",".join("?" * len(recent_ids))
                cur = db.execute(
                    f"""
                    SELECT sr.target_host, sr.findings
                    FROM scan_results sr
                    WHERE sr.scan_id IN ({placeholders})
                      AND sr.findings != '[]' AND sr.findings IS NOT NULL
                    ORDER BY sr.scan_id DESC
                    LIMIT 200
                    """,
                    recent_ids,
                )
                for row in cur.fetchall():
                    host = row["target_host"]
                    try:
                        findings = _json.loads(row["findings"]) if isinstance(row["findings"], str) else (row["findings"] or [])
                    except Exception:
                        findings = []
                    for f in findings:
                        sev = f.get("severity", "info")
                        top_threats.append({
                            "title": f.get("title", "Unknown"),
                            "severity": sev,
                            "target_host": host,
                        })
                        # Worst offenders aggregation
                        if host not in worst_map:
                            worst_map[host] = {"host": host, "total": 0, "critical": 0, "high": 0, "medium": 0}
                        worst_map[host]["total"] += 1
                        if sev in ("critical", "high", "medium"):
                            worst_map[host][sev] += 1

            # Sort threats by severity
            SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            top_threats.sort(key=lambda x: SEV_ORDER.get(x["severity"], 5))
            top_threats = top_threats[:8]

            worst_offenders = sorted(worst_map.values(), key=lambda x: (x["critical"] * 1000 + x["high"] * 100 + x["medium"]), reverse=True)[:6]

        return _tr(templates, request, "dashboard.html", {
            "active_page": "dashboard",
            "scans": scans,
            "targets": targets,
            "total_targets": len(targets),
            "total_groups": len(groups),
            "total_tags": len(tags),
            "total_hosts": len(hosts),
            "total_scans": len(scans),
            "last_scan": last_scan,
            "top_threats": top_threats,
            "worst_offenders": worst_offenders,
        })

    @app.get("/targets", response_class=HTMLResponse)
    async def targets_page(request: Request):
        with get_db(db_path) as db:
            targets = get_targets(db)
            groups = get_groups(db)
            tags = get_tags(db)

        return _tr(templates, request, "targets.html", {
            "active_page": "targets",
            "targets": targets,
            "groups": groups,
            "tags": tags,
            "checks_list": [
                "port_scan", "ssl", "http", "dns", "vuln",
                "smtp", "exposed_paths", "cipher", "nmap", "subnet_scan",
            ],
        })

    @app.get("/groups", response_class=HTMLResponse)
    async def groups_page(request: Request):
        with get_db(db_path) as db:
            groups = get_groups(db)
            tags = get_tags(db)

        return _tr(templates, request, "groups.html", {
            "active_page": "groups",
            "groups": groups,
            "tags": tags,
        })

    @app.get("/tags", response_class=HTMLResponse)
    async def tags_page(request: Request):
        with get_db(db_path) as db:
            tags = get_tags(db)

        return _tr(templates, request, "tags.html", {
            "active_page": "tags",
            "tags": tags,
        })

    @app.get("/scans", response_class=HTMLResponse)
    async def scan_history(request: Request, page: int = 1):
        page_size = 20
        offset = (page - 1) * page_size
        with get_db(db_path) as db:
            all_scans = get_scans(db, limit=1000)
            total = len(all_scans)
            scans = all_scans[offset: offset + page_size]

        return _tr(templates, request, "scan_history.html", {
            "active_page": "scans",
            "scans": scans,
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": max(1, (total + page_size - 1) // page_size),
        })

    @app.get("/scans/{id}", response_class=HTMLResponse)
    async def scan_detail(request: Request, id: int):
        with get_db(db_path) as db:
            scan = get_scan(db, id)
            if scan is None:
                return HTMLResponse("Scan not found", status_code=404)
            results = get_scan_results(db, id)

        unique_targets = sorted(set(r["target_host"] for r in results))
        unique_checks = sorted(set(r["check_name"] for r in results))

        return _tr(templates, request, "scan_detail.html", {
            "active_page": "scans",
            "scan": scan,
            "results": results,
            "unique_targets": unique_targets,
            "unique_checks": unique_checks,
        })

    @app.get("/scans/{id}/diff", response_class=HTMLResponse)
    async def scan_diff(request: Request, id: int, compare_to: Optional[int] = None):
        with get_db(db_path) as db:
            scan_a = get_scan(db, id)
            if scan_a is None:
                return HTMLResponse("Scan not found", status_code=404)
            # All completed scans except the current one, for the selector
            all_scans = [s for s in get_scans(db, limit=200)
                         if s["id"] != id and s["status"] == "completed"]
            diff = None
            scan_b = None
            if compare_to is not None:
                scan_b = get_scan(db, compare_to)
                if scan_b:
                    diff = diff_scans(db, id, compare_to)

        return _tr(templates, request, "scan_diff.html", {
            "active_page": "scans",
            "scan_a": scan_a,
            "scan_b": scan_b,
            "diff": diff,
            "compare_to": compare_to,
            "all_scans": all_scans,
        })

    @app.get("/hosts", response_class=HTMLResponse)
    async def hosts_page(request: Request):
        with get_db(db_path) as db:
            hosts = get_host_inventory(db)

        return _tr(templates, request, "hosts.html", {
            "active_page": "hosts",
            "hosts": hosts,
        })

    @app.get("/hosts/{ip:path}", response_class=HTMLResponse)
    async def host_detail(request: Request, ip: str):
        with get_db(db_path) as db:
            services = get_host_services(db, ip)
            identities = get_host_identities(db, ip)
            # Pull latest scan results for this host
            cur = db.execute(
                """
                SELECT sr.*, s.started_at AS scan_started_at
                FROM scan_results sr
                JOIN scans s ON s.id = sr.scan_id
                WHERE sr.target_host = ?
                ORDER BY sr.scan_id DESC, sr.id DESC
                LIMIT 100
                """,
                (ip,),
            )
            import json as _json
            raw_results = []
            for row in cur.fetchall():
                r = dict(row)
                for f in ("findings", "metadata"):
                    if isinstance(r.get(f), str):
                        try:
                            r[f] = _json.loads(r[f])
                        except Exception:
                            r[f] = [] if f == "findings" else {}
                raw_results.append(r)

            # Host inventory record
            inv = db.execute(
                "SELECT * FROM host_inventory WHERE ip_address = ?", (ip,)
            ).fetchone()
            host_inv = dict(inv) if inv else {"ip_address": ip}

        all_findings = []
        for r in raw_results:
            for f in r.get("findings") or []:
                all_findings.append({
                    **f,
                    "check": r["check_name"],
                    "scan_id": r["scan_id"],
                    "scan_date": (r.get("scan_started_at") or "")[:10],
                })

        return _tr(templates, request, "host_detail.html", {
            "active_page": "hosts",
            "host": host_inv,
            "ip": ip,
            "services": services,
            "identities": identities,
            "findings": all_findings,
            "results": raw_results,
        })

    @app.get("/profiles", response_class=HTMLResponse)
    async def profiles_page(request: Request):
        with get_db(db_path) as db:
            profiles = get_scan_profiles(db)

        return _tr(templates, request, "profiles.html", {
            "active_page": "profiles",
            "profiles": profiles,
        })

    @app.get("/schedules", response_class=HTMLResponse)
    async def schedules_page(request: Request):
        with get_db(db_path) as db:
            schedules = get_schedules(db)
            profiles = get_scan_profiles(db)
            groups = get_groups(db)
            tags = get_tags(db)

        return _tr(templates, request, "schedules.html", {
            "active_page": "schedules",
            "schedules": schedules,
            "profiles": profiles,
            "groups": groups,
            "tags": tags,
        })

    @app.get("/reports", response_class=HTMLResponse)
    async def reports_page(request: Request):
        with get_db(db_path) as db:
            scans = get_scans(db, limit=200)
        completed = [s for s in scans if s["status"] == "completed"]
        return _tr(templates, request, "reports.html", {
            "active_page": "reports",
            "scans": completed,
        })

    @app.get("/scope", response_class=HTMLResponse)
    async def scope_page(request: Request):
        with get_db(db_path) as db:
            scope_ranges = get_scope_ranges(db)

        return _tr(templates, request, "scope.html", {
            "active_page": "scope",
            "scope_ranges": scope_ranges,
        })

    @app.get("/discovery", response_class=HTMLResponse)
    async def discovery_page(request: Request):
        with get_db(db_path) as db:
            hosts = get_host_inventory(db)
        return _tr(templates, request, "discovery.html", {
            "active_page": "discovery",
            "hosts": hosts,
        })

    @app.get("/logs", response_class=HTMLResponse)
    async def logs_page(request: Request):
        with get_db(db_path) as db:
            all_scans = get_scans(db, limit=200)
        return _tr(templates, request, "logs.html", {
            "active_page": "logs",
            "scans": all_scans,
        })

    @app.get("/tools", response_class=HTMLResponse)
    @app.get("/tools/{tool}", response_class=HTMLResponse)
    async def tools_page(request: Request, tool: str = "nmap"):
        return _tr(templates, request, "tools.html", {
            "active_page": f"tools_{tool}",
            "active_tool": tool,
        })

    # ── Settings pages ────────────────────────────────────────────────────

    @app.get("/settings/{section}", response_class=HTMLResponse)
    async def settings_page(request: Request, section: str):
        valid = {"users", "permissions", "integrations"}
        if section not in valid:
            from fastapi.responses import RedirectResponse
            return RedirectResponse("/settings/users")
        return _tr(templates, request, f"settings_{section}.html", {
            "active_page": f"settings_{section}",
        })

    # ── WebSocket for live scan progress ──────────────────────────────────

    @app.websocket("/ws/scan/{scan_id}")
    async def ws_scan_progress(websocket: WebSocket, scan_id: int):
        await websocket.accept()
        try:
            for _ in range(50):
                if scan_id in active_scans:
                    break
                await asyncio.sleep(0.1)

            queue = active_scans.get(scan_id)
            if queue is None:
                await websocket.send_json({"type": "error", "message": "Scan not found or already finished"})
                await websocket.close()
                return

            # Poll instead of wait_for to avoid Python ≤3.11 queue-item-loss bug
            import time as _time
            last_ping = _time.monotonic()
            while True:
                try:
                    event = queue.get_nowait()
                except asyncio.QueueEmpty:
                    now = _time.monotonic()
                    if now - last_ping >= 20:
                        try:
                            await websocket.send_json({"type": "ping"})
                        except Exception:
                            break
                        last_ping = now
                    await asyncio.sleep(0.05)
                    continue
                await websocket.send_json(event)
                if event.get("type") in ("complete", "error"):
                    break

        except WebSocketDisconnect:
            pass
        except Exception as exc:
            try:
                await websocket.send_json({"type": "error", "message": str(exc)})
            except Exception:
                pass

    return app
