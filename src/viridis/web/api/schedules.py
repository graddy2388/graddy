"""
viridis.web.api.schedules – REST endpoints for persistent scan scheduling.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, model_validator

from ..db.crud import (
    get_schedules, get_schedule,
    create_schedule, update_schedule, delete_schedule,
)
from ..scheduler_service import (
    cron_human_to_expr, register_schedule, remove_schedule,
)
from ..validation import (
    MAX_CRON_FIELD_LEN,
    MAX_SCHEDULE_NAME,
    validate_target_filter,
)


class ScheduleIn(BaseModel):
    name: str
    cron_human: str = ""
    cron_expr: str = ""
    target_filter: str = "all"
    profile_id: Optional[int] = None
    enabled: bool = True

    model_config = {"extra": "ignore"}

    @model_validator(mode="after")
    def _validate(self) -> ScheduleIn:
        if not self.name.strip():
            raise ValueError("name is required")
        if len(self.name) > MAX_SCHEDULE_NAME:
            raise ValueError("name is too long")
        if len(self.cron_expr) > MAX_CRON_FIELD_LEN or len(self.cron_human) > MAX_CRON_FIELD_LEN:
            raise ValueError("cron field is too long")
        validate_target_filter(self.target_filter)
        return self


def make_router(get_db_dep, config: Dict[str, Any], db_path: str, scheduler) -> APIRouter:
    r = APIRouter(prefix="/api/schedules", tags=["schedules"])

    @r.get("")
    def list_schedules(db=Depends(get_db_dep)):
        return get_schedules(db)

    @r.get("/{id}")
    def get_sched(id: int, db=Depends(get_db_dep)):
        s = get_schedule(db, id)
        if s is None:
            raise HTTPException(status_code=404, detail="Schedule not found")
        return s

    @r.post("", status_code=201)
    def create(body: ScheduleIn, db=Depends(get_db_dep)):
        # Resolve cron expression
        if body.cron_expr:
            cron_expr = body.cron_expr
            cron_human = body.cron_human or body.cron_expr
        elif body.cron_human:
            cron_expr = cron_human_to_expr(body.cron_human)
            cron_human = body.cron_human
        else:
            raise HTTPException(status_code=400, detail="Provide either cron_expr or cron_human")

        try:
            sched = create_schedule(
                db,
                name=body.name,
                cron_expr=cron_expr,
                cron_human=cron_human,
                target_filter=body.target_filter,
                profile_id=body.profile_id,
                enabled=int(body.enabled),
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:
            import logging
            logging.getLogger(__name__).exception("Error creating schedule")
            raise HTTPException(status_code=400, detail="Failed to create schedule") from exc

        if body.enabled and scheduler is not None:
            register_schedule(
                scheduler,
                schedule_id=sched["id"],
                cron_expr=cron_expr,
                db_path=db_path,
                config=config,
                target_filter=body.target_filter,
                profile_id=body.profile_id,
            )

        return sched

    @r.put("/{id}")
    def update(id: int, body: ScheduleIn, db=Depends(get_db_dep)):
        existing = get_schedule(db, id)
        if existing is None:
            raise HTTPException(status_code=404, detail="Schedule not found")

        if body.cron_expr:
            cron_expr = body.cron_expr
            cron_human = body.cron_human or body.cron_expr
        elif body.cron_human:
            cron_expr = cron_human_to_expr(body.cron_human)
            cron_human = body.cron_human
        else:
            cron_expr = existing["cron_expr"]
            cron_human = existing["cron_human"]

        sched = update_schedule(
            db, id,
            name=body.name,
            cron_expr=cron_expr,
            cron_human=cron_human,
            target_filter=body.target_filter,
            profile_id=body.profile_id,
            enabled=int(body.enabled),
        )

        # Re-register or remove job
        remove_schedule(scheduler, id)
        if body.enabled and scheduler is not None:
            register_schedule(
                scheduler,
                schedule_id=id,
                cron_expr=cron_expr,
                db_path=db_path,
                config=config,
                target_filter=body.target_filter,
                profile_id=body.profile_id,
            )

        return sched

    @r.delete("/{id}", status_code=204)
    def delete(id: int, db=Depends(get_db_dep)):
        if not delete_schedule(db, id):
            raise HTTPException(status_code=404, detail="Schedule not found")
        remove_schedule(scheduler, id)

    @r.post("/{id}/toggle")
    def toggle(id: int, db=Depends(get_db_dep)):
        sched = get_schedule(db, id)
        if sched is None:
            raise HTTPException(status_code=404, detail="Schedule not found")
        new_enabled = 0 if sched["enabled"] else 1
        sched = update_schedule(db, id, enabled=new_enabled)
        if new_enabled:
            register_schedule(
                scheduler,
                schedule_id=id,
                cron_expr=sched["cron_expr"],
                db_path=db_path,
                config=config,
                target_filter=sched["target_filter"],
                profile_id=sched.get("profile_id"),
            )
        else:
            remove_schedule(scheduler, id)
        return sched

    return r
