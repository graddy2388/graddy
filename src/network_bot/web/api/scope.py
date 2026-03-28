"""
network_bot.web.api.scope – REST endpoints for in-scope IP range management.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..db.crud import get_scope_ranges, create_scope_range, delete_scope_range, is_in_scope


class ScopeIn(BaseModel):
    cidr: str
    description: str = ""
    in_scope: bool = True


def make_router(get_db_dep) -> APIRouter:
    r = APIRouter(prefix="/api/scope", tags=["scope"])

    @r.get("")
    def list_ranges(db=Depends(get_db_dep)):
        return get_scope_ranges(db)

    @r.post("", status_code=201)
    def create(body: ScopeIn, db=Depends(get_db_dep)):
        import ipaddress
        try:
            ipaddress.ip_network(body.cidr, strict=False)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid CIDR: {body.cidr}")
        try:
            return create_scope_range(db, body.cidr, body.description, int(body.in_scope))
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @r.delete("/{id}", status_code=204)
    def delete(id: int, db=Depends(get_db_dep)):
        if not delete_scope_range(db, id):
            raise HTTPException(status_code=404, detail="Scope range not found")

    @r.get("/check")
    def check_scope(ip: str, db=Depends(get_db_dep)):
        in_scope = is_in_scope(db, ip)
        return {"ip": ip, "in_scope": in_scope}

    return r
