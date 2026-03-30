"""
network_bot.web.api.scope – REST endpoints for in-scope IP range management.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator, model_validator

from ..db.crud import get_scope_ranges, create_scope_range, delete_scope_range, is_in_scope
from ..validation import MAX_DESC_LEN, MAX_HOST_LEN, validate_host


class ScopeIn(BaseModel):
    cidr: str
    description: str = ""
    in_scope: bool = True

    model_config = {"extra": "ignore"}

    @field_validator("cidr", mode="before")
    @classmethod
    def _strip_cidr(cls, v):
        if isinstance(v, str):
            return v.strip()
        return v

    @model_validator(mode="after")
    def _validate(self) -> ScopeIn:
        validate_host(self.cidr)
        if len(self.description) > MAX_DESC_LEN:
            raise ValueError("description is too long")
        return self


def make_router(get_db_dep) -> APIRouter:
    r = APIRouter(prefix="/api/scope", tags=["scope"])

    @r.get("")
    def list_ranges(db=Depends(get_db_dep)):
        return get_scope_ranges(db)

    @r.post("", status_code=201)
    def create(body: ScopeIn, db=Depends(get_db_dep)):
        try:
            return create_scope_range(db, body.cidr, body.description, int(body.in_scope))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @r.delete("/{id}", status_code=204)
    def delete(id: int, db=Depends(get_db_dep)):
        if not delete_scope_range(db, id):
            raise HTTPException(status_code=404, detail="Scope range not found")

    @r.get("/check")
    def check_scope(
        ip: str = Query(..., min_length=1, max_length=MAX_HOST_LEN),
        db=Depends(get_db_dep),
    ):
        try:
            validate_host(ip.strip())
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        scoped = is_in_scope(db, ip.strip())
        return {"ip": ip.strip(), "in_scope": scoped}

    return r
