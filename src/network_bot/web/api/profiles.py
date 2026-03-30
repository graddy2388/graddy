"""
network_bot.web.api.profiles – REST endpoints for scan profile management.
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, model_validator

from ..db.crud import (
    get_scan_profiles, get_scan_profile,
    create_scan_profile, update_scan_profile, delete_scan_profile,
)
from ..validation import (
    MAX_DESC_LEN,
    MAX_NAME_LEN,
    VALID_INTENSITIES,
    VALID_PROFILE_TOOLS,
    validate_checks,
    validate_nmap_args,
    validate_ports,
)


class ProfileIn(BaseModel):
    name: str
    description: str = ""
    checks: List[str] = ["port_scan", "ssl", "http", "dns", "vuln", "exposed_paths", "cipher"]
    ports: List[int] = [80, 443, 8080, 8443, 21, 22, 23, 25, 53, 110, 143, 445, 3306, 3389, 5432, 6379, 9200, 27017]
    smtp_ports: List[int] = [25, 587, 465]
    nmap_args: str = "-sV -sC --top-ports 1000 -T4"
    tools: List[str] = ["nmap"]
    intensity: str = "normal"

    model_config = {"extra": "ignore"}

    @model_validator(mode="after")
    def _validate(self) -> ProfileIn:
        if not self.name.strip():
            raise ValueError("name is required")
        if len(self.name) > MAX_NAME_LEN:
            raise ValueError(f"name must be {MAX_NAME_LEN} characters or fewer")
        if len(self.description) > MAX_DESC_LEN:
            raise ValueError(f"description must be {MAX_DESC_LEN} characters or fewer")
        validate_checks(self.checks, allow_empty=False)
        validate_ports(self.ports)
        validate_ports(self.smtp_ports)
        validate_nmap_args(self.nmap_args)
        for t in self.tools:
            if t not in VALID_PROFILE_TOOLS:
                raise ValueError(f"unknown tool: {t!r}")
        if self.intensity not in VALID_INTENSITIES:
            raise ValueError("intensity must be stealth, normal, or aggressive")
        return self


def make_router(get_db_dep) -> APIRouter:
    r = APIRouter(prefix="/api/profiles", tags=["profiles"])

    @r.get("")
    def list_profiles(db=Depends(get_db_dep)):
        return get_scan_profiles(db)

    @r.get("/{id}")
    def get_profile(id: int, db=Depends(get_db_dep)):
        p = get_scan_profile(db, id)
        if p is None:
            raise HTTPException(status_code=404, detail="Profile not found")
        return p

    @r.post("", status_code=201)
    def create(body: ProfileIn, db=Depends(get_db_dep)):
        try:
            return create_scan_profile(
                db,
                name=body.name.strip(),
                description=body.description,
                checks=body.checks,
                ports=body.ports,
                smtp_ports=body.smtp_ports,
                nmap_args=body.nmap_args,
                tools=body.tools,
                intensity=body.intensity,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @r.put("/{id}")
    def update(id: int, body: ProfileIn, db=Depends(get_db_dep)):
        try:
            result = update_scan_profile(
                db, id,
                name=body.name.strip(),
                description=body.description,
                checks=body.checks,
                ports=body.ports,
                smtp_ports=body.smtp_ports,
                nmap_args=body.nmap_args,
                tools=body.tools,
                intensity=body.intensity,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if result is None:
            raise HTTPException(status_code=404, detail="Profile not found")
        return result

    @r.delete("/{id}", status_code=204)
    def delete(id: int, db=Depends(get_db_dep)):
        if not delete_scan_profile(db, id):
            raise HTTPException(status_code=404, detail="Profile not found")

    return r
