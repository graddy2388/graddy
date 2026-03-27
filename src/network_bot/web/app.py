"""
network_bot.web.app – FastAPI application factory.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .db.crud import get_scans, get_targets, get_groups, get_tags, get_scan, get_scan_results
from .db.schema import get_db


# Global in-memory dict mapping scan_id → asyncio.Queue for WS progress
active_scans: Dict[int, asyncio.Queue] = {}


def _make_db_dep(db_path: str):
    """Return a FastAPI dependency that yields a sqlite3 connection."""
    def dep():
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()
    return dep


def create_app(config: Dict[str, Any]) -> FastAPI:
    app = FastAPI(title="Network Bot", docs_url="/api/docs")

    db_path = config.get("web", {}).get("db_path", "data/network_bot.db")

    # Jinja2 templates
    templates_dir = Path(__file__).parent / "templates"
    templates = Jinja2Templates(directory=str(templates_dir))

    # DB dependency
    get_db_dep = _make_db_dep(db_path)

    # Register API routers
    from .api.groups import make_router as groups_router
    from .api.tags import make_router as tags_router
    from .api.targets import make_router as targets_router
    from .api.scans import make_router as scans_router
    from .api.dashboard import make_router as dashboard_router

    app.include_router(groups_router(get_db_dep))
    app.include_router(tags_router(get_db_dep))
    app.include_router(targets_router(get_db_dep))
    app.include_router(scans_router(get_db_dep, config, db_path, active_scans))
    app.include_router(dashboard_router(get_db_dep))

    # -------------------------------------------------------------------------
    # Page routes
    # -------------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        with get_db(db_path) as db:
            scans = get_scans(db, limit=10)
            targets = get_targets(db)
            groups = get_groups(db)
            tags = get_tags(db)
            last_scan = scans[0] if scans else None

        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "active_page": "dashboard",
                "scans": scans,
                "targets": targets,
                "total_targets": len(targets),
                "total_groups": len(groups),
                "total_tags": len(tags),
                "last_scan": last_scan,
            },
        )

    @app.get("/targets", response_class=HTMLResponse)
    async def targets_page(request: Request):
        with get_db(db_path) as db:
            targets = get_targets(db)
            groups = get_groups(db)
            tags = get_tags(db)

        return templates.TemplateResponse(
            "targets.html",
            {
                "request": request,
                "active_page": "targets",
                "targets": targets,
                "groups": groups,
                "tags": tags,
                "checks_list": ["port_scan", "ssl", "http", "dns", "vuln", "smtp", "exposed_paths", "cipher"],
            },
        )

    @app.get("/groups", response_class=HTMLResponse)
    async def groups_page(request: Request):
        with get_db(db_path) as db:
            groups = get_groups(db)
            tags = get_tags(db)

        return templates.TemplateResponse(
            "groups.html",
            {
                "request": request,
                "active_page": "groups",
                "groups": groups,
                "tags": tags,
            },
        )

    @app.get("/tags", response_class=HTMLResponse)
    async def tags_page(request: Request):
        with get_db(db_path) as db:
            tags = get_tags(db)

        return templates.TemplateResponse(
            "groups.html",
            {
                "request": request,
                "active_page": "tags",
                "groups": [],
                "tags": tags,
            },
        )

    @app.get("/scans", response_class=HTMLResponse)
    async def scan_history(request: Request, page: int = 1):
        page_size = 20
        offset = (page - 1) * page_size
        with get_db(db_path) as db:
            all_scans = get_scans(db, limit=1000)
            total = len(all_scans)
            scans = all_scans[offset: offset + page_size]

        return templates.TemplateResponse(
            "scan_history.html",
            {
                "request": request,
                "active_page": "scans",
                "scans": scans,
                "page": page,
                "page_size": page_size,
                "total": total,
                "total_pages": max(1, (total + page_size - 1) // page_size),
            },
        )

    @app.get("/scans/{id}", response_class=HTMLResponse)
    async def scan_detail(request: Request, id: int):
        with get_db(db_path) as db:
            scan = get_scan(db, id)
            if scan is None:
                return HTMLResponse("Scan not found", status_code=404)
            results = get_scan_results(db, id)

        # Collect unique targets and check names for filter dropdowns
        unique_targets = sorted(set(r["target_host"] for r in results))
        unique_checks = sorted(set(r["check_name"] for r in results))

        return templates.TemplateResponse(
            "scan_detail.html",
            {
                "request": request,
                "active_page": "scans",
                "scan": scan,
                "results": results,
                "unique_targets": unique_targets,
                "unique_checks": unique_checks,
            },
        )

    # -------------------------------------------------------------------------
    # WebSocket for live scan progress
    # -------------------------------------------------------------------------

    @app.websocket("/ws/scan/{scan_id}")
    async def ws_scan_progress(websocket: WebSocket, scan_id: int):
        await websocket.accept()
        try:
            # Poll until queue appears (scan may not have started yet)
            for _ in range(50):
                if scan_id in active_scans:
                    break
                await asyncio.sleep(0.1)

            queue = active_scans.get(scan_id)
            if queue is None:
                await websocket.send_json({"type": "error", "message": "Scan not found or already finished"})
                await websocket.close()
                return

            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30.0)
                    await websocket.send_json(event)
                    if event.get("type") in ("complete", "error"):
                        break
                except asyncio.TimeoutError:
                    # Send keep-alive ping
                    await websocket.send_json({"type": "ping"})

        except WebSocketDisconnect:
            pass
        except Exception as exc:
            try:
                await websocket.send_json({"type": "error", "message": str(exc)})
            except Exception:
                pass

    return app
