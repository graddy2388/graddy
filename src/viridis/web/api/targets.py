"""
viridis.web.api.targets – REST endpoints for target management.
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator, model_validator

from ..db.crud import (
    get_targets, get_target, create_target, update_target, delete_target,
    set_target_tags, import_from_yaml, add_host_history, get_host_history,
)
from ..resolver import resolve_host
from ..validation import (
    MAX_NAME_LEN,
    MAX_NOTES_LEN,
    MAX_TAG_IDS,
    MAX_IMPORT_ROWS,
    MAX_SEARCH_QUERY_LEN,
    MAX_GROUP_TAG_NAME,
    truncate_search_query,
    validate_checks,
    validate_host,
    validate_ports,
)


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

    model_config = {"extra": "ignore"}

    @field_validator("enabled")
    @classmethod
    def _enabled(cls, v: int) -> int:
        if v not in (0, 1):
            raise ValueError("enabled must be 0 or 1")
        return v

    @model_validator(mode="after")
    def _validate(self) -> TargetIn:
        if not self.name or not self.name.strip():
            raise ValueError("name is required")
        if len(self.name) > MAX_NAME_LEN:
            raise ValueError(f"name must be {MAX_NAME_LEN} characters or fewer")
        if not self.host or not self.host.strip():
            raise ValueError("host is required")
        validate_host(self.host)
        if self.notes and len(self.notes) > MAX_NOTES_LEN:
            raise ValueError(f"notes must be {MAX_NOTES_LEN} characters or fewer")
        if self.checks is not None:
            validate_checks(self.checks, allow_empty=False)
        if self.ports is not None:
            validate_ports(self.ports)
        if self.smtp_ports is not None:
            validate_ports(self.smtp_ports)
        if len(self.tag_ids) > MAX_TAG_IDS:
            raise ValueError(f"too many tags (max {MAX_TAG_IDS})")
        return self


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

    model_config = {"extra": "ignore"}

    @field_validator("enabled")
    @classmethod
    def _enabled(cls, v: Optional[int]) -> Optional[int]:
        if v is None:
            return v
        if v not in (0, 1):
            raise ValueError("enabled must be 0 or 1")
        return v

    @model_validator(mode="after")
    def _validate(self) -> TargetUpdate:
        if self.name is not None:
            if not self.name.strip():
                raise ValueError("name cannot be empty")
            if len(self.name) > MAX_NAME_LEN:
                raise ValueError(f"name must be {MAX_NAME_LEN} characters or fewer")
        if self.host is not None:
            validate_host(self.host)
        if self.notes is not None and len(self.notes) > MAX_NOTES_LEN:
            raise ValueError(f"notes must be {MAX_NOTES_LEN} characters or fewer")
        if self.checks is not None:
            validate_checks(self.checks, allow_empty=False)
        if self.ports is not None:
            validate_ports(self.ports)
        if self.smtp_ports is not None:
            validate_ports(self.smtp_ports)
        if self.tag_ids is not None and len(self.tag_ids) > MAX_TAG_IDS:
            raise ValueError(f"too many tags (max {MAX_TAG_IDS})")
        return self


class TargetImportRow(BaseModel):
    host: str
    name: Optional[str] = None
    group: Optional[str] = None
    checks: Optional[List[str]] = None
    ports: Optional[List[int]] = None
    smtp_ports: Optional[List[int]] = None
    enabled: int = 1
    notes: str = ""
    tags: Optional[List[str]] = None

    model_config = {"extra": "ignore"}

    @field_validator("enabled")
    @classmethod
    def _enabled(cls, v: int) -> int:
        if v not in (0, 1):
            raise ValueError("enabled must be 0 or 1")
        return v

    @model_validator(mode="after")
    def _validate(self) -> TargetImportRow:
        validate_host(self.host)
        if self.name is not None and len(self.name) > MAX_NAME_LEN:
            raise ValueError(f"name must be {MAX_NAME_LEN} characters or fewer")
        if self.group is not None and len(self.group) > MAX_GROUP_TAG_NAME:
            raise ValueError("group name too long")
        if self.notes and len(self.notes) > MAX_NOTES_LEN:
            raise ValueError("notes too long")
        if self.checks is not None:
            validate_checks(self.checks, allow_empty=False)
        if self.ports is not None:
            validate_ports(self.ports)
        if self.smtp_ports is not None:
            validate_ports(self.smtp_ports)
        if self.tags is not None:
            if len(self.tags) > MAX_TAG_IDS:
                raise ValueError("too many tag names in import row")
            for tn in self.tags:
                if len(tn) > MAX_GROUP_TAG_NAME:
                    raise ValueError("tag name too long")
        return self


class ImportBody(BaseModel):
    targets: List[TargetImportRow]


def make_router(get_db_dep) -> APIRouter:
    r = APIRouter(prefix="/api/targets", tags=["targets"])

    @r.get("")
    def list_targets(
        group_id: Optional[int] = Query(None),
        tag_id: Optional[int] = Query(None),
        q: Optional[str] = Query(None, max_length=MAX_SEARCH_QUERY_LEN),
        db=Depends(get_db_dep),
    ):
        targets = get_targets(db, group_id=group_id, tag_id=tag_id)
        if q:
            q_lower = truncate_search_query(q).lower()
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
                name=body.name.strip(),
                host=body.host.strip(),
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
            add_host_history(
                db, target["id"], resolved["hostname"], resolved["ip_address"]
            )
            return target
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:
            import logging
            logging.getLogger(__name__).exception("Error creating target")
            raise HTTPException(status_code=400, detail="Failed to create target") from exc

    @r.put("/{id}")
    def update(id: int, body: TargetUpdate, db=Depends(get_db_dep)):
        existing = get_target(db, id)
        if existing is None:
            raise HTTPException(status_code=404, detail="Target not found")

        update_data = body.model_dump(exclude_none=True, exclude={"tag_ids"})

        if "host" in update_data:
            update_data["host"] = update_data["host"].strip()
            resolved = resolve_host(update_data["host"])
            update_data["hostname"] = resolved["hostname"]
            update_data["last_resolved_ip"] = resolved["ip_address"]
            update_data["last_resolved_at"] = resolved["resolved_at"]
            add_host_history(db, id, resolved["hostname"], resolved["ip_address"])

        if "name" in update_data:
            update_data["name"] = update_data["name"].strip()

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
        if len(body.targets) > MAX_IMPORT_ROWS:
            raise HTTPException(
                status_code=422,
                detail=f"too many rows (max {MAX_IMPORT_ROWS})",
            )
        rows = [t.model_dump() for t in body.targets]
        count = import_from_yaml(db, rows)
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
