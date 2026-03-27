"""
network_bot.web.api.targets – REST endpoints for target management.
"""
from __future__ import annotations

import json
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ..db.crud import (
    get_targets, get_target, create_target, update_target, delete_target,
    set_target_tags, import_from_yaml, add_host_history, get_host_history,
)
from ..resolver import resolve_host


class TargetIn(BaseModel):
    name: str
    host: str
    group_id: Optional[int] = None
    checks: Optional[List[str]] = None
    ports: Optional[List[int]] = None
    smtp_ports: Optional[List[int]] = None
    enabled: int = 1
    notes: str = ""
    tag_ids: List[int] = []


class TargetUpdate(BaseModel):
    name: Optional[str] = None
    host: Optional[str] = None
    group_id: Optional[int] = None
    checks: Optional[List[str]] = None
    ports: Optional[List[int]] = None
    smtp_ports: Optional[List[int]] = None
    enabled: Optional[int] = None
    notes: Optional[str] = None
    tag_ids: Optional[List[int]] = None


class ImportBody(BaseModel):
    targets: List[dict]


def make_router(get_db_dep) -> APIRouter:
    r = APIRouter(prefix="/api/targets", tags=["targets"])

    @r.get("")
    def list_targets(
        group_id: Optional[int] = Query(None),
        tag_id: Optional[int] = Query(None),
        q: Optional[str] = Query(None),
        db=Depends(get_db_dep),
    ):
        targets = get_targets(db, group_id=group_id, tag_id=tag_id)
        if q:
            q_lower = q.lower()
            targets = [
                t for t in targets
                if q_lower in t["name"].lower() or q_lower in t["host"].lower()
            ]
        return targets

    @r.post("", status_code=201)
    def create(body: TargetIn, db=Depends(get_db_dep)):
        try:
            resolved = resolve_host(body.host)
            target = create_target(
                db,
                name=body.name,
                host=body.host,
                group_id=body.group_id,
                checks=body.checks,
                ports=body.ports,
                smtp_ports=body.smtp_ports,
                enabled=body.enabled,
                notes=body.notes,
                hostname=resolved["hostname"],
                last_resolved_ip=resolved["ip_address"],
                last_resolved_at=resolved["resolved_at"],
            )
            if body.tag_ids:
                set_target_tags(db, target["id"], body.tag_ids)
                target = get_target(db, target["id"])
            # Record initial host_history entry
            add_host_history(
                db, target["id"], resolved["hostname"], resolved["ip_address"]
            )
            return target
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    @r.put("/{id}")
    def update(id: int, body: TargetUpdate, db=Depends(get_db_dep)):
        existing = get_target(db, id)
        if existing is None:
            raise HTTPException(status_code=404, detail="Target not found")

        update_data = body.model_dump(exclude_none=True, exclude={"tag_ids"})

        # If host field is being updated, re-resolve
        if "host" in update_data:
            resolved = resolve_host(update_data["host"])
            update_data["hostname"] = resolved["hostname"]
            update_data["last_resolved_ip"] = resolved["ip_address"]
            update_data["last_resolved_at"] = resolved["resolved_at"]
            add_host_history(db, id, resolved["hostname"], resolved["ip_address"])

        if update_data:
            result = update_target(db, id, **update_data)
        else:
            result = existing

        if body.tag_ids is not None:
            set_target_tags(db, id, body.tag_ids)
            result = get_target(db, id)

        return result

    @r.delete("/{id}", status_code=204)
    def delete(id: int, db=Depends(get_db_dep)):
        if not delete_target(db, id):
            raise HTTPException(status_code=404, detail="Target not found")

    @r.post("/import", status_code=201)
    def import_targets(body: ImportBody, db=Depends(get_db_dep)):
        count = import_from_yaml(db, body.targets)
        return {"imported": count}

    @r.get("/{id}/history")
    def target_history(id: int, db=Depends(get_db_dep)):
        existing = get_target(db, id)
        if existing is None:
            raise HTTPException(status_code=404, detail="Target not found")
        return get_host_history(db, id)

    @r.post("/{id}/resolve")
    def resolve_target(id: int, db=Depends(get_db_dep)):
        existing = get_target(db, id)
        if existing is None:
            raise HTTPException(status_code=404, detail="Target not found")
        resolved = resolve_host(existing["host"])
        result = update_target(
            db,
            id,
            hostname=resolved["hostname"],
            last_resolved_ip=resolved["ip_address"],
            last_resolved_at=resolved["resolved_at"],
        )
        add_host_history(db, id, resolved["hostname"], resolved["ip_address"])
        return result

    return r
