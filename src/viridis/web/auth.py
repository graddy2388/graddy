"""
viridis.web.auth – Session-based RBAC authentication.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
import time
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

_log = logging.getLogger(__name__)

# ── Role constants ──────────────────────────────────────────────────────────
ROLE_ADMIN   = "admin"
ROLE_ANALYST = "analyst"
ROLE_VIEWER  = "viewer"
ROLES        = (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER)
_ROLE_LEVEL  = {ROLE_ADMIN: 100, ROLE_ANALYST: 50, ROLE_VIEWER: 10}

SESSION_COOKIE = "viridis_session"
SESSION_TTL    = 86400  # 24 hours


# ── Password hashing (PBKDF2-HMAC-SHA256, 260k iterations per OWASP) ────────

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk   = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 260_000)
    return salt.hex() + ":" + dk.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split(":", 1)
        dk_actual   = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 260_000
        )
        return hmac.compare_digest(dk_actual, bytes.fromhex(dk_hex))
    except Exception:
        return False


def create_session_token() -> str:
    return secrets.token_urlsafe(32)


# ── In-memory rate limiter (per IP, login endpoint) ─────────────────────────

class _RateLimiter:
    def __init__(self, max_attempts: int = 10, window: int = 300):
        self._a:   dict[str, list[float]] = {}
        self._max  = max_attempts
        self._win  = window

    def is_allowed(self, key: str) -> bool:
        now = time.monotonic()
        lst = [t for t in self._a.get(key, []) if now - t < self._win]
        if len(lst) >= self._max:
            self._a[key] = lst
            return False
        lst.append(now)
        self._a[key] = lst
        return True

    def reset(self, key: str) -> None:
        self._a.pop(key, None)


login_limiter = _RateLimiter(max_attempts=10, window=300)


# ── Session middleware ──────────────────────────────────────────────────────

class SessionMiddleware(BaseHTTPMiddleware):
    """
    Validates viridis_session cookie against the sessions table.
    Attaches request.state.user = {id, username, role} or None.
    Redirects unauthenticated HTML requests to /login.
    Returns 401 JSON for unauthenticated API requests.
    Enforces role-based access for write operations.
    """

    _EXEMPT        = frozenset(["/login", "/api/version"])
    _EXEMPT_PREFIX = ("/ws/", "/static/")

    # Paths that require analyst or above for writes
    _ANALYST_WRITE = (
        "/api/scans", "/api/targets", "/api/groups", "/api/tags",
        "/api/schedules", "/api/scope", "/api/profiles", "/api/hosts",
        "/api/export", "/api/integrations",
    )

    def __init__(self, app, db_path: str):
        super().__init__(app)
        self._db = db_path

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if path in self._EXEMPT or any(path.startswith(p) for p in self._EXEMPT_PREFIX):
            request.state.user = None
            return await call_next(request)

        user = self._resolve_user(request)
        request.state.user = user

        if user is None:
            if path.startswith("/api/"):
                return JSONResponse({"detail": "Not authenticated"}, status_code=401)
            return RedirectResponse(f"/login?next={path}", status_code=302)

        role = user.get("role", ROLE_VIEWER)

        # Admin-only sections
        _admin_paths = (path.startswith("/api/users") or path.startswith("/api/integrations")
                        or path == "/settings/users" or path == "/settings/integrations")
        if _admin_paths:
            if role != ROLE_ADMIN:
                if path.startswith("/api/"):
                    return JSONResponse({"detail": "Admin access required"}, status_code=403)
                return RedirectResponse("/", status_code=302)

        # Write operations require analyst or above
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            for prefix in self._ANALYST_WRITE:
                if path.startswith(prefix) and _ROLE_LEVEL.get(role, 0) < _ROLE_LEVEL[ROLE_ANALYST]:
                    return JSONResponse({"detail": "Analyst role required to perform this action"}, status_code=403)

        return await call_next(request)

    def _resolve_user(self, request: Request) -> Optional[dict]:
        token = request.cookies.get(SESSION_COOKIE)
        if not token:
            return None
        try:
            conn = sqlite3.connect(self._db)
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """
                SELECT u.id, u.username, u.role, u.is_active
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.token = ? AND s.expires_at > datetime('now')
                """,
                (token,),
            ).fetchone()
            conn.close()
            if row and row["is_active"]:
                return {"id": row["id"], "username": row["username"], "role": row["role"]}
        except Exception:
            pass
        return None


# ── Audit logging helper ────────────────────────────────────────────────────

def audit(db_path: str, user_id: Optional[int], username: str,
          action: str, resource: str = "", details: str = "", ip: str = "") -> None:
    try:
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO audit_log (user_id, username, action, resource, details, ip_address)"
            " VALUES (?,?,?,?,?,?)",
            (user_id, username, action, resource, details, ip),
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        _log.debug("Audit log write failed: %s", exc)
