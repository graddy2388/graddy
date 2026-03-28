"""
network_bot.web.api.groups – REST endpoints for group management.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..db.crud import (
    get_groups, get_group, create_group, update_group, delete_group,
)

router = APIRouter(prefix="/api/groups", tags=["groups"])


class GroupIn(BaseModel):
    name: str
    description: str = ""
    color: str = "#6366f1"


def make_router(get_db_dep) -> APIRouter:
    r = APIRouter(prefix="/api/groups", tags=["groups"])

    @r.get("")
    def list_groups(db=Depends(get_db_dep)):
        return get_groups(db)

    @r.post("", status_code=201)
    def create(body: GroupIn, db=Depends(get_db_dep)):
        try:
            return create_group(db, body.name, body.description, body.color)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @r.put("/{id}")
    def update(id: int, body: GroupIn, db=Depends(get_db_dep)):
        result = update_group(db, id, body.name, body.description, body.color)
        if result is None:
            raise HTTPException(status_code=404, detail="Group not found")
        return result

    @r.delete("/{id}", status_code=204)
    def delete(id: int, db=Depends(get_db_dep)):
        if not delete_group(db, id):
            raise HTTPException(status_code=404, detail="Group not found")

    return r
