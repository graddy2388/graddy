"""
viridis.web.app – FastAPI application factory.
"""
from __future__ import annotations

import asyncio
import logging
import os
import secrets
import sqlite3
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

_log = logging.getLogger(__name__)

from .db.crud import (
    get_scans, get_targets, get_groups, get_tags, get_scan, get_scan_results,
    get_scan_profiles, get_schedules, get_scope_ranges,
    get_host_inventory, get_host_services, get_host_identities,
    get_ai_events, diff_scans,
)
import json as _json
from .db.schema import get_db
from . import active_scans  # shared dict in web/__init__.py
from .validation import MAX_PAGE, validate_host_path_segment


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
    """Compatibility wrapper: injects current_user and tries new API first."""
    ctx = dict(ctx)
    ctx.setdefault("current_user", getattr(request.state, "user", None))
    try:
        return templates.TemplateResponse(request=request, name=name, context=ctx)
    except TypeError:
        ctx["request"] = request
        return templates.TemplateResponse(name=name, context=ctx)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security-related HTTP response headers to every response."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=()"
        )
        # HSTS: tell browsers this site must be HTTPS (browsers ignore for HTTP)
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        # Prevent bfcache from restoring stale Alpine JS state (e.g. open scan modal)
        ct = response.headers.get("content-type", "")
        if "text/html" in ct:
            response.headers["Cache-Control"] = "no-store, must-revalidate"
        # CSP: allow same-origin + known CDNs used for Tailwind/Alpine/D3
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com "
            "https://cdn.jsdelivr.net https://d3js.org; "
            "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "font-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none';"
        )
        return response


def create_app(config: Dict[str, Any]) -> FastAPI:
    from .auth import (
        SessionMiddleware, hash_password, verify_password,
        create_session_token, login_limiter, audit,
        SESSION_COOKIE, SESSION_TTL, ROLES,
    )

    app = FastAPI(title="Viridis – Security Platform", docs_url="/api/docs")
    app.add_middleware(SecurityHeadersMiddleware)

    db_path = config.get("web", {}).get("db_path", "data/viridis.db")

    # ── Session middleware ─────────────────────────────────────────────────
    # Must be added AFTER SecurityHeadersMiddleware so it runs first (innermost)
    app.add_middleware(SessionMiddleware, db_path=db_path)

    # Jinja2 templates
    templates_dir = Path(__file__).parent / "templates"
    templates = Jinja2Templates(directory=str(templates_dir))
    _wiki_url = os.environ.get("VIRIDIS_EXTERNAL_WIKI_URL") or config.get("web", {}).get(
        "external_wiki_url", "https://github.com/graddy2388/graddy/wiki"
    )
    templates.env.globals["external_wiki_url"] = _wiki_url
    _build_sha = os.environ.get("BUILD_SHA", "")
    templates.env.globals["build_sha"] = _build_sha[:7] if _build_sha else "dev"

    # DB dependency
    get_db_dep = _make_db_dep(db_path)

    # ── Initialize DB and start scheduler ──────────────────────────────────
    from .db.schema import init_db
    init_db(db_path)

    # ── Orphan cleanup: any scan still 'running' at startup is unreachable ─
    # The active_scans dict is empty on a fresh start, so these scans will
    # never receive a complete/error event. Mark them failed immediately so
    # the UI does not show a permanently stuck modal.
    try:
        from .db.schema import get_db as _get_db_direct
        from .db.crud import fail_scan as _fail_scan
        with _get_db_direct(db_path) as _db:
            _orphans = _db.execute(
                "SELECT id FROM scans WHERE status = 'running'"
            ).fetchall()
            for _row in _orphans:
                _fail_scan(_db, _row["id"])
                _log.info("Marked orphaned scan #%s as failed on startup", _row["id"])
    except Exception as _exc:
        _log.warning("Orphan scan cleanup failed: %s", _exc)

    # ── Seed default admin user (first-run only) ───────────────────────────
    try:
        with get_db(db_path) as _adb:
            _count = _adb.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if _count == 0:
                _admin_pw = os.environ.get("VIRIDIS_ADMIN_PASSWORD", "")
                if not _admin_pw:
                    _admin_pw = secrets.token_urlsafe(12)
                    _log.warning(
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        "  First-run: no admin password set.\n"
                        "  Generated admin password: %s\n"
                        "  Set VIRIDIS_ADMIN_PASSWORD to use your own.\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                        _admin_pw,
                    )
                else:
                    _log.info("Creating initial admin user from VIRIDIS_ADMIN_PASSWORD")
                _adb.execute(
                    "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?,?,?)",
                    ("admin", hash_password(_admin_pw), "admin"),
                )
    except Exception as _exc:
        _log.warning("Admin user seeding failed: %s", _exc)

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
    from .api.threats import make_router as threats_router
    from .api.users import make_router as users_router

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
    app.include_router(threats_router(get_db_dep))
    app.include_router(users_router(get_db_dep, db_path))

    # ── Background threat feed refresh (every 15 min) ─────────────────────
    try:
        from ..threat_feeds import fetch_all_feeds
        import threading as _threading

        def _bg_feed_refresh():
            import time as _time
            # Initial fetch after 5 seconds (avoid blocking startup)
            _time.sleep(5)
            while True:
                try:
                    fetch_all_feeds()
                except Exception as _exc:
                    _log.warning("Threat feed refresh error: %s", _exc)
                _time.sleep(900)  # 15 minutes

        _feed_thread = _threading.Thread(target=_bg_feed_refresh, daemon=True, name="threat-feed-refresh")
        _feed_thread.start()
        _log.info("Threat intelligence feed refresh thread started")
    except Exception as _exc:
        _log.warning("Could not start threat feed refresh: %s", _exc)

    # ── Page routes ────────────────────────────────────────────────────────

    @app.get("/api/version")
    async def version():
        import time
        return {
            "build_sha": os.environ.get("BUILD_SHA", "dev"),
            "server_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    @app.get("/api/auth/me")
    async def auth_me(request: Request):
        user = getattr(request.state, "user", None)
        if not user:
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "Not authenticated"}, status_code=401)
        return user

    @app.put("/api/auth/me/password")
    async def change_own_password(request: Request):
        from fastapi.responses import JSONResponse
        import json as _json
        user = getattr(request.state, "user", None)
        if not user:
            return JSONResponse({"detail": "Not authenticated"}, status_code=401)
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"detail": "Invalid JSON"}, status_code=400)
        old_pw = body.get("old_password", "")
        new_pw = body.get("new_password", "")
        if len(new_pw) < 8:
            return JSONResponse({"detail": "Password must be at least 8 characters"}, status_code=422)
        with get_db(db_path) as _db:
            row = _db.execute(
                "SELECT password_hash FROM users WHERE id = ?", (user["id"],)
            ).fetchone()
            if not row or not verify_password(old_pw, row["password_hash"]):
                return JSONResponse({"detail": "Current password is incorrect"}, status_code=401)
            _db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (hash_password(new_pw), user["id"]),
            )
            # Invalidate all other sessions
            _db.execute(
                "DELETE FROM sessions WHERE user_id = ?", (user["id"],)
            )
        audit(db_path, user["id"], user["username"], "user.password_change",
              ip=request.client.host if request.client else "")
        return {"ok": True}

    # ── Login / Logout ─────────────────────────────────────────────────────

    def _is_https(req: Request) -> bool:
        """True when the connection (or upstream proxy) is HTTPS."""
        return (
            req.headers.get("X-Forwarded-Proto") == "https"
            or req.url.scheme == "https"
        )

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request, next: str = "/", error: str = ""):
        # If already logged in, redirect away
        user = getattr(request.state, "user", None)
        if user:
            return RedirectResponse(next or "/", status_code=302)
        csrf_token = secrets.token_urlsafe(16)
        secure = _is_https(request)
        resp = _tr(templates, request, "login.html", {
            "error": error,
            "next": next if next != "/" else "",
            "username": "",
            "csrf_token": csrf_token,
        })
        resp.set_cookie(
            "viridis_csrf", csrf_token,
            httponly=True, samesite="strict", max_age=300, secure=secure,
        )
        return resp

    def _set_csrf_cookie(resp, csrf_token: str, secure: bool):
        resp.set_cookie("viridis_csrf", csrf_token, httponly=True, samesite="strict", max_age=300, secure=secure)

    @app.post("/login")
    async def login_submit(request: Request):
        from fastapi.responses import JSONResponse
        form = await request.form()
        username    = str(form.get("username", "")).strip()
        password    = str(form.get("password", ""))
        next_url    = str(form.get("next", "/") or "/")
        csrf_form   = str(form.get("csrf_token", ""))
        csrf_cookie = request.cookies.get("viridis_csrf", "")
        client_ip   = request.client.host if request.client else "unknown"
        secure      = _is_https(request)

        def _login_error(msg: str):
            tok = secrets.token_urlsafe(16)
            r = _tr(templates, request, "login.html", {
                "error": msg, "next": next_url,
                "username": username, "csrf_token": tok,
            })
            _set_csrf_cookie(r, tok, secure)
            return r

        # CSRF check
        if not csrf_form or not secrets.compare_digest(csrf_form, csrf_cookie):
            return _login_error("Invalid request. Please try again.")

        # Rate limiting
        if not login_limiter.is_allowed(client_ip):
            return _login_error("Too many login attempts. Please wait 5 minutes.")

        # Validate credentials
        user_row = None
        try:
            with get_db(db_path) as _db:
                user_row = _db.execute(
                    "SELECT id, username, password_hash, role, is_active FROM users WHERE username = ?",
                    (username,),
                ).fetchone()
        except Exception:
            pass

        if not user_row or not verify_password(password, user_row["password_hash"]):
            audit(db_path, None, username, "auth.fail", ip=client_ip)
            return _login_error("Invalid username or password.")

        if not user_row["is_active"]:
            return _login_error("Your account has been disabled. Contact an administrator.")

        # Create session (clean up expired ones first)
        token = create_session_token()
        import time as _time
        expires_at = _time.strftime(
            "%Y-%m-%d %H:%M:%S",
            _time.gmtime(_time.time() + SESSION_TTL)
        )
        ua = request.headers.get("user-agent", "")[:512]
        try:
            with get_db(db_path) as _db:
                # Prune expired sessions for this user (session hygiene)
                _db.execute(
                    "DELETE FROM sessions WHERE user_id = ? AND expires_at <= datetime('now')",
                    (user_row["id"],),
                )
                _db.execute(
                    "INSERT INTO sessions (user_id, token, expires_at, ip_address, user_agent)"
                    " VALUES (?,?,?,?,?)",
                    (user_row["id"], token, expires_at, client_ip, ua),
                )
                _db.execute(
                    "UPDATE users SET last_login = datetime('now') WHERE id = ?",
                    (user_row["id"],),
                )
        except Exception as _exc:
            _log.error("Session creation failed: %s", _exc)
            return _login_error("Login failed (internal error). Please try again.")

        login_limiter.reset(client_ip)
        audit(db_path, user_row["id"], username, "auth.login", ip=client_ip)

        # Validate next_url is relative to prevent open redirect
        if not next_url.startswith("/") or next_url.startswith("//"):
            next_url = "/"

        resp = RedirectResponse(next_url, status_code=302)
        resp.set_cookie(
            SESSION_COOKIE, token,
            httponly=True, samesite="strict",
            max_age=SESSION_TTL, secure=secure,
        )
        resp.delete_cookie("viridis_csrf")
        return resp

    @app.post("/logout")
    @app.get("/logout")
    async def logout(request: Request):
        token = request.cookies.get(SESSION_COOKIE)
        user  = getattr(request.state, "user", None)
        if token:
            try:
                with get_db(db_path) as _db:
                    _db.execute("DELETE FROM sessions WHERE token = ?", (token,))
            except Exception:
                pass
        if user:
            audit(db_path, user.get("id"), user.get("username", "?"), "auth.logout",
                  ip=request.client.host if request.client else "")
        resp = RedirectResponse("/login", status_code=302)
        resp.delete_cookie(SESSION_COOKIE)
        return resp

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
    async def scan_history(
        request: Request,
        page: int = Query(1, ge=1, le=MAX_PAGE),
    ):
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

    @app.get("/topology", response_class=HTMLResponse)
    async def topology_page(request: Request):
        _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        with get_db(db_path) as db:
            hosts = get_host_inventory(db)

            # Compute worst severity per IP from recent scan results
            cur = db.execute(
                """
                SELECT target_host, findings
                FROM scan_results
                WHERE findings IS NOT NULL AND findings != '[]'
                ORDER BY scan_id DESC
                LIMIT 2000
                """
            )
            worst_sev: dict = {}
            for row in cur.fetchall():
                ip = row["target_host"]
                try:
                    findings = _json.loads(row["findings"]) if isinstance(row["findings"], str) else (row["findings"] or [])
                except Exception:
                    findings = []
                for f in findings:
                    sev = f.get("severity", "info")
                    if _SEV_ORDER.get(sev, 5) < _SEV_ORDER.get(worst_sev.get(ip, "none"), 99):
                        worst_sev[ip] = sev

            # Annotate hosts with worst_severity
            hosts_annotated = []
            for h in hosts:
                hd = dict(h)
                hd["worst_severity"] = worst_sev.get(h["ip_address"], "none")
                hosts_annotated.append(hd)

            # Build edges: hosts that share a scan
            cur = db.execute(
                """
                SELECT scan_id, target_host
                FROM scan_results
                ORDER BY scan_id
                """
            )
            from collections import defaultdict
            scan_hosts: dict = defaultdict(list)
            for row in cur.fetchall():
                scan_hosts[row["scan_id"]].append(row["target_host"])

            edges_set: set = set()
            for scan_id, ips in scan_hosts.items():
                uniq = list(dict.fromkeys(ips))
                for i in range(len(uniq)):
                    for j in range(i + 1, min(i + 4, len(uniq))):
                        a, b = sorted([uniq[i], uniq[j]])
                        edges_set.add((a, b))

            edges = [{"source": a, "target": b} for a, b in edges_set]

        return _tr(templates, request, "topology.html", {
            "active_page": "topology",
            "hosts": hosts_annotated,
            "edges": edges,
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
        try:
            ip = validate_host_path_segment(ip)
        except ValueError:
            return HTMLResponse("Invalid host", status_code=400)
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
    async def ws_scan_progress(websocket: WebSocket, scan_id: int, token: str = ""):
        from . import verify_scan_token
        # Validate the per-scan token before accepting the WebSocket upgrade.
        # The token is returned by POST /api/scans and passed as ?token=...
        if not verify_scan_token(scan_id, token):
            await websocket.close(code=4401)
            return

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
