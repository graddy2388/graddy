"""
viridis.web.api.users – User management REST endpoints (admin-only).
Auth enforcement is handled by SessionMiddleware; these routes add
business-logic validation on top.
"""
from __future__ import annotations

import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ..auth import ROLES, hash_password, audit


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "viewer"


class UserUpdate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{2,64}$")


def _validate_username(u: str) -> None:
    if not _USERNAME_RE.match(u):
        raise HTTPException(status_code=422, detail="Username must be 2–64 alphanumeric/.-_ chars")


def _validate_role(r: str) -> None:
    if r not in ROLES:
        raise HTTPException(status_code=422, detail=f"Role must be one of: {', '.join(ROLES)}")


def _validate_password(p: str) -> None:
    if len(p) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters")


def make_router(get_db_dep, db_path: str) -> APIRouter:
    r = APIRouter(prefix="/api/users", tags=["users"])

    @r.get("")
    def list_users(db=Depends(get_db_dep)):
        rows = db.execute(
            "SELECT id, username, role, is_active, created_at, last_login FROM users ORDER BY id"
        ).fetchall()
        return [dict(row) for row in rows]

    @r.post("", status_code=201)
    def create_user(body: UserCreate, request: Request, db=Depends(get_db_dep)):
        _validate_username(body.username)
        _validate_role(body.role)
        _validate_password(body.password)
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                (body.username, hash_password(body.password), body.role),
            )
        except Exception:
            raise HTTPException(status_code=409, detail="Username already exists")
        row = db.execute(
            "SELECT id, username, role, is_active, created_at FROM users WHERE username = ?",
            (body.username,),
        ).fetchone()
        user = getattr(request.state, "user", None) or {}
        audit(db_path, user.get("id"), user.get("username", "?"),
              "user.create", body.username, f"role={body.role}",
              request.client.host if request.client else "")
        return dict(row)

    @r.put("/{uid}")
    def update_user(uid: int, body: UserUpdate, request: Request, db=Depends(get_db_dep)):
        existing = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="User not found")

        actor = getattr(request.state, "user", None) or {}

        # Prevent demoting the last admin
        if body.role and body.role != "admin" and existing["role"] == "admin":
            count = db.execute(
                "SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1"
            ).fetchone()[0]
            if count <= 1:
                raise HTTPException(status_code=409, detail="Cannot demote the last active admin")

        if body.username is not None:
            _validate_username(body.username)
        if body.role is not None:
            _validate_role(body.role)
        if body.password is not None:
            _validate_password(body.password)

        updates, params = [], []
        if body.username  is not None: updates.append("username = ?");      params.append(body.username)
        if body.role      is not None: updates.append("role = ?");          params.append(body.role)
        if body.is_active is not None: updates.append("is_active = ?");     params.append(int(body.is_active))
        if body.password  is not None: updates.append("password_hash = ?"); params.append(hash_password(body.password))

        if updates:
            params.append(uid)
            db.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)

        audit(db_path, actor.get("id"), actor.get("username", "?"),
              "user.update", str(uid),
              ip=request.client.host if request.client else "")

        row = db.execute(
            "SELECT id, username, role, is_active, created_at, last_login FROM users WHERE id = ?",
            (uid,),
        ).fetchone()
        return dict(row)

    @r.delete("/{uid}", status_code=204)
    def delete_user(uid: int, request: Request, db=Depends(get_db_dep)):
        existing = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="User not found")

        actor = getattr(request.state, "user", None) or {}
        if actor.get("id") == uid:
            raise HTTPException(status_code=409, detail="Cannot delete your own account")

        if existing["role"] == "admin":
            count = db.execute(
                "SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1"
            ).fetchone()[0]
            if count <= 1:
                raise HTTPException(status_code=409, detail="Cannot delete the last active admin")

        db.execute("DELETE FROM users WHERE id = ?", (uid,))
        audit(db_path, actor.get("id"), actor.get("username", "?"),
              "user.delete", str(uid),
              ip=request.client.host if request.client else "")

    @r.get("/audit-log")
    def audit_log(limit: int = 100, db=Depends(get_db_dep)):
        rows = db.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (min(limit, 500),)
        ).fetchall()
        return [dict(row) for row in rows]

    return r
