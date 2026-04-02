"""
network_bot.web.api.tags – REST endpoints for tag management.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, model_validator

from ..db.crud import get_tags, get_tag, create_tag, update_tag, delete_tag
from ..validation import MAX_GROUP_TAG_NAME, validate_color_hex


class TagIn(BaseModel):
    name: str
    color: str = "#10b981"

    model_config = {"extra": "ignore"}

    @model_validator(mode="after")
    def _validate(self) -> TagIn:
        if not self.name.strip():
            raise ValueError("name is required")
        if len(self.name) > MAX_GROUP_TAG_NAME:
            raise ValueError("name is too long")
        validate_color_hex(self.color)
        return self


def make_router(get_db_dep) -> APIRouter:
    r = APIRouter(prefix="/api/tags", tags=["tags"])

    @r.get("")
    def list_tags(db=Depends(get_db_dep)):
        return get_tags(db)

    @r.post("", status_code=201)
    def create(body: TagIn, db=Depends(get_db_dep)):
        try:
            return create_tag(db, body.name.strip(), body.color)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:
            import logging
            logging.getLogger(__name__).exception("Error creating tag")
            raise HTTPException(status_code=400, detail="Failed to create tag") from exc

    @r.put("/{id}")
    def update(id: int, body: TagIn, db=Depends(get_db_dep)):
        try:
            result = update_tag(db, id, body.name.strip(), body.color)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if result is None:
            raise HTTPException(status_code=404, detail="Tag not found")
        return result

    @r.delete("/{id}", status_code=204)
    def delete(id: int, db=Depends(get_db_dep)):
        if not delete_tag(db, id):
            raise HTTPException(status_code=404, detail="Tag not found")

    return r
