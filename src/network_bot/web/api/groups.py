"""
network_bot.web.api.groups – REST endpoints for group management.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, model_validator

from ..db.crud import (
    get_groups, get_group, create_group, update_group, delete_group,
)
from ..validation import MAX_DESC_LEN, MAX_GROUP_TAG_NAME, validate_color_hex


class GroupIn(BaseModel):
    name: str
    description: str = ""
    color: str = "#6366f1"

    model_config = {"extra": "ignore"}

    @model_validator(mode="after")
    def _validate(self) -> GroupIn:
        if not self.name.strip():
            raise ValueError("name is required")
        if len(self.name) > MAX_GROUP_TAG_NAME:
            raise ValueError("name is too long")
        if len(self.description) > MAX_DESC_LEN:
            raise ValueError("description is too long")
        validate_color_hex(self.color)
        return self


def make_router(get_db_dep) -> APIRouter:
    r = APIRouter(prefix="/api/groups", tags=["groups"])

    @r.get("")
    def list_groups(db=Depends(get_db_dep)):
        return get_groups(db)

    @r.post("", status_code=201)
    def create(body: GroupIn, db=Depends(get_db_dep)):
        try:
            return create_group(db, body.name.strip(), body.description, body.color)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:
            import logging
            logging.getLogger(__name__).exception("Error creating group")
            raise HTTPException(status_code=400, detail="Failed to create group") from exc

    @r.put("/{id}")
    def update(id: int, body: GroupIn, db=Depends(get_db_dep)):
        try:
            result = update_group(db, id, body.name.strip(), body.description, body.color)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if result is None:
            raise HTTPException(status_code=404, detail="Group not found")
        return result

    @r.delete("/{id}", status_code=204)
    def delete(id: int, db=Depends(get_db_dep)):
        if not delete_group(db, id):
            raise HTTPException(status_code=404, detail="Group not found")

    return r
