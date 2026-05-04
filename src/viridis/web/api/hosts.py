"""
viridis.web.api.hosts – REST endpoints for host inventory and detail data.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..validation import validate_host_path_segment
from ..db.crud import (
    get_host_inventory, get_host_services, get_host_identities,
    get_scan_results, get_host_software,
)


def make_router(get_db_dep) -> APIRouter:
    r = APIRouter(prefix="/api/hosts", tags=["hosts"])

    @r.get("")
    def list_hosts(db=Depends(get_db_dep)):
        return get_host_inventory(db)

    @r.get("/{ip}/services")
    def host_services(ip: str, db=Depends(get_db_dep)):
        try:
            ip = validate_host_path_segment(ip)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return get_host_services(db, ip)

    @r.get("/{ip}/identities")
    def host_identities(ip: str, db=Depends(get_db_dep)):
        try:
            ip = validate_host_path_segment(ip)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return get_host_identities(db, ip)

    @r.get("/{ip}/findings")
    def host_findings(ip: str, db=Depends(get_db_dep)):
        """Return all scan findings for a specific host IP across all scans."""
        try:
            ip = validate_host_path_segment(ip)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        cur = db.execute(
            """
            SELECT sr.*, s.started_at AS scan_started_at, s.status AS scan_status
            FROM scan_results sr
            JOIN scans s ON s.id = sr.scan_id
            WHERE sr.target_host = ?
            ORDER BY sr.scan_id DESC, sr.id DESC
            """,
            (ip,),
        )
        import json
        rows = []
        for row in cur.fetchall():
            r_dict = dict(row)
            for f in ("findings", "metadata"):
                if isinstance(r_dict.get(f), str):
                    try:
                        r_dict[f] = json.loads(r_dict[f])
                    except Exception:
                        r_dict[f] = [] if f == "findings" else {}
            rows.append(r_dict)
        return rows

    @r.get("/{ip}/software")
    def host_software(ip: str, db=Depends(get_db_dep)):
        """Return software inventory with CVE data for a specific host."""
        try:
            ip = validate_host_path_segment(ip)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return get_host_software(db, ip)

    @r.post("/{ip}/promote")
    def promote_host_to_target(ip: str, db=Depends(get_db_dep)):
        """Promote a discovered host to the targets list."""
        try:
            ip = validate_host_path_segment(ip)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        host = db.execute(
            "SELECT * FROM host_inventory WHERE ip_address = ?", (ip,)
        ).fetchone()
        if not host:
            raise HTTPException(status_code=404, detail="Host not found in inventory")

        existing = db.execute(
            "SELECT id FROM targets WHERE host = ?", (ip,)
        ).fetchone()
        if existing:
            return {"id": existing["id"], "created": False, "message": "Already a target"}

        name = host["hostname"] if host["hostname"] else ip
        db.execute(
            "INSERT INTO targets (name, host) VALUES (?, ?)",
            (name, ip),
        )
        row = db.execute("SELECT id FROM targets WHERE host = ?", (ip,)).fetchone()
        return {"id": row["id"], "created": True, "message": f"Added {ip} as target"}

    return r
