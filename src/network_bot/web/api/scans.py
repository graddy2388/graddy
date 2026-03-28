"""
network_bot.web.api.scans – REST endpoints for scan management and triggering.
"""
from __future__ import annotations

import asyncio
import json
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ..db.crud import (
    create_scan, finish_scan, fail_scan,
    get_scans, get_scan, get_scan_results,
    get_targets, add_scan_result,
    get_scan_profile, upsert_host_inventory, upsert_host_service,
    is_in_scope,
)


class ScanIn(BaseModel):
    target_ids: Optional[List[int]] = None
    group_id: Optional[int] = None
    tag_id: Optional[int] = None
    profile_id: Optional[int] = None
    subnet: Optional[str] = None  # CIDR for subnet scanning


# Default checks registry – new checks registered here
_DEFAULT_CHECKS = [
    "port_scan", "ssl", "http", "dns", "vuln", "smtp", "exposed_paths", "cipher"
]


def _load_check_registry():
    from ....checks import PortScanCheck, SSLCheck, HTTPCheck, DNSCheck, VulnCheck, SMTPCheck, ExposedPathsCheck, CipherCheck
    registry = {
        "port_scan": PortScanCheck,
        "ssl": SSLCheck,
        "http": HTTPCheck,
        "dns": DNSCheck,
        "vuln": VulnCheck,
        "smtp": SMTPCheck,
        "exposed_paths": ExposedPathsCheck,
        "cipher": CipherCheck,
    }
    # Attempt to load optional/tool-dependent checks
    try:
        from ....checks.nmap_scan import NmapScanCheck
        registry["nmap"] = NmapScanCheck
    except ImportError:
        pass
    try:
        from ....checks.subnet_scan import SubnetScanCheck
        registry["subnet_scan"] = SubnetScanCheck
    except ImportError:
        pass
    return registry


def run_checks_for_web(
    targets: List[Dict[str, Any]],
    config: Dict[str, Any],
    db_path: str,
    scan_id: int,
    progress_queue: asyncio.Queue,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """
    Run checks synchronously in a background thread, publishing progress events
    to the asyncio queue via loop.call_soon_threadsafe.
    """
    from ..db.schema import get_db

    CHECK_REGISTRY = _load_check_registry()

    def _put(event: dict) -> None:
        loop.call_soon_threadsafe(progress_queue.put_nowait, event)

    sev_counts: Dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    }

    total_checks = sum(
        len(
            t.get("checks")
            if isinstance(t.get("checks"), list)
            else json.loads(t.get("checks", "[]"))
            if isinstance(t.get("checks"), str)
            else _DEFAULT_CHECKS
        )
        for t in targets
    )
    done = 0

    try:
        with get_db(db_path) as db:
            for target in targets:
                host = target["host"]
                name = target.get("name", host)

                # Scope check
                try:
                    resolved_ip = target.get("last_resolved_ip") or host
                    if not is_in_scope(db, resolved_ip):
                        _put({
                            "type": "progress",
                            "target": host,
                            "check": "scope_check",
                            "done": done,
                            "total": total_checks,
                            "skipped": True,
                            "reason": "out_of_scope",
                        })
                        done += len(
                            target.get("checks") if isinstance(target.get("checks"), list)
                            else json.loads(target.get("checks", "[]"))
                            if isinstance(target.get("checks"), str)
                            else _DEFAULT_CHECKS
                        )
                        continue
                except Exception:
                    pass  # allow if scope check fails

                raw_checks = target.get("checks")
                if isinstance(raw_checks, str):
                    try:
                        checks_to_run = json.loads(raw_checks)
                    except Exception:
                        checks_to_run = _DEFAULT_CHECKS
                elif isinstance(raw_checks, list):
                    checks_to_run = raw_checks
                else:
                    checks_to_run = _DEFAULT_CHECKS

                for check_name in checks_to_run:
                    check_class = CHECK_REGISTRY.get(check_name)
                    if check_class is None:
                        done += 1
                        continue

                    _put({
                        "type": "progress",
                        "target": host,
                        "check": check_name,
                        "done": done,
                        "total": total_checks,
                    })

                    checker = check_class(config)
                    try:
                        result = checker.run(target)
                    except Exception as exc:
                        from ....checks.base import CheckResult as CR
                        result = CR(
                            check_name=check_name,
                            target=host,
                            passed=False,
                            error=f"Unexpected error: {exc}",
                        )

                    findings_list = []
                    for f in result.findings:
                        sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                        if sev_val in sev_counts:
                            sev_counts[sev_val] += 1
                        findings_list.append({
                            "title": f.title,
                            "severity": sev_val,
                            "description": f.description,
                            "recommendation": getattr(f, "recommendation", ""),
                            "details": getattr(f, "details", {}),
                        })
                        _put({
                            "type": "finding",
                            "target": host,
                            "severity": sev_val,
                            "title": f.title,
                        })

                    add_scan_result(
                        db,
                        scan_id=scan_id,
                        target_host=host,
                        target_name=name,
                        check_name=check_name,
                        passed=result.passed,
                        findings=findings_list,
                        metadata=result.metadata,
                        error=result.error,
                        timestamp=result.timestamp,
                    )

                    # Persist host inventory data from nmap/subnet scans
                    if check_name in ("nmap", "subnet_scan") and result.metadata:
                        try:
                            _persist_host_data(db, host, result.metadata)
                        except Exception:
                            pass

                    done += 1

        with get_db(db_path) as db:
            finish_scan(db, scan_id, {
                "total_targets": len(targets),
                **sev_counts,
            })

        _put({
            "type": "complete",
            "critical": sev_counts["critical"],
            "high": sev_counts["high"],
            "medium": sev_counts["medium"],
            "low": sev_counts["low"],
            "info": sev_counts["info"],
        })

    except Exception as exc:
        try:
            from ..db.schema import get_db as _get_db
            with _get_db(db_path) as db:
                fail_scan(db, scan_id)
        except Exception:
            pass
        _put({"type": "error", "message": str(exc)})


def _persist_host_data(db, host: str, metadata: Dict) -> None:
    """Save host inventory data discovered via nmap/subnet scan to the DB."""
    if "hosts" in metadata:
        # Subnet scan – multiple hosts
        for h in metadata["hosts"]:
            upsert_host_inventory(
                db,
                ip_address=h["ip"],
                hostname=h.get("hostname", ""),
                mac_address=h.get("mac", ""),
                os_guess=h.get("os_guess", ""),
                open_ports=h.get("open_ports", []),
                services=h.get("services", {}),
            )
            for port, svc in h.get("services", {}).items():
                upsert_host_service(
                    db,
                    host_ip=h["ip"],
                    port=int(port),
                    service_name=svc.get("name", ""),
                    service_version=f"{svc.get('product','')} {svc.get('version','')}".strip(),
                    banner=svc.get("banner", ""),
                )
    elif "open_ports" in metadata:
        # Single-host nmap scan
        os_guesses = metadata.get("os_guesses", [])
        os_guess = max(os_guesses, key=lambda x: x.get("accuracy", 0))["name"] if os_guesses else ""
        upsert_host_inventory(
            db,
            ip_address=host,
            os_guess=os_guess,
            open_ports=metadata.get("open_ports", []),
            services=metadata.get("services", {}),
        )
        for port, svc in metadata.get("services", {}).items():
            upsert_host_service(
                db,
                host_ip=host,
                port=int(port),
                service_name=svc.get("name", ""),
                service_version=f"{svc.get('product','')} {svc.get('version','')}".strip(),
                banner=svc.get("banner", ""),
            )


def make_router(get_db_dep, config: Dict[str, Any], db_path: str, active_scans: Dict[int, asyncio.Queue]) -> APIRouter:
    r = APIRouter(prefix="/api/scans", tags=["scans"])

    @r.get("")
    def list_scans(limit: int = 50, db=Depends(get_db_dep)):
        return get_scans(db, limit=limit)

    @r.get("/{id}")
    def scan_detail(id: int, db=Depends(get_db_dep)):
        scan = get_scan(db, id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        results = get_scan_results(db, id)
        return {**scan, "results": results}

    @r.post("", status_code=201)
    async def trigger_scan(body: ScanIn, db=Depends(get_db_dep)):
        # Load profile if specified
        profile = None
        if body.profile_id:
            profile = get_scan_profile(db, body.profile_id)

        # Subnet scan: create a synthetic target from the CIDR
        if body.subnet:
            import ipaddress
            try:
                ipaddress.ip_network(body.subnet, strict=False)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid subnet CIDR: {body.subnet}")
            targets = [{
                "id": 0,
                "name": f"Subnet {body.subnet}",
                "host": body.subnet,
                "checks": ["subnet_scan"],
                "enabled": 1,
            }]
        elif body.target_ids:
            all_targets = get_targets(db)
            targets = [t for t in all_targets if t["id"] in body.target_ids]
        elif body.group_id is not None:
            targets = get_targets(db, group_id=body.group_id)
        elif body.tag_id is not None:
            targets = get_targets(db, tag_id=body.tag_id)
        else:
            targets = get_targets(db, enabled_only=True)

        if not targets:
            raise HTTPException(status_code=400, detail="No targets match the filter")

        # Apply profile settings to targets if a profile was specified
        if profile:
            updated = []
            for t in targets:
                if profile.get("checks"):
                    t = dict(t)
                    t["checks"] = profile["checks"]
                    t["ports"] = profile.get("ports", t.get("ports", []))
                    t["nmap_args"] = profile.get("nmap_args", "")
                updated.append(t)
            targets = updated

        scan = create_scan(
            db,
            triggered_by="web",
            filter_group=str(body.group_id) if body.group_id else None,
            filter_tag=str(body.tag_id) if body.tag_id else None,
            profile_id=body.profile_id,
        )
        scan_id = scan["id"]

        # Must be called from async context to get the running loop correctly
        loop = asyncio.get_event_loop()
        queue: asyncio.Queue = asyncio.Queue()
        active_scans[scan_id] = queue

        def _run():
            run_checks_for_web(targets, config, db_path, scan_id, queue, loop)
            import time
            time.sleep(2)
            active_scans.pop(scan_id, None)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()

        return {"scan_id": scan_id}

    @r.get("/{id}/export")
    def export_scan(id: int, db=Depends(get_db_dep)):
        scan = get_scan(db, id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        results = get_scan_results(db, id)
        return JSONResponse(
            content={**scan, "results": results},
            headers={"Content-Disposition": f"attachment; filename=scan_{id}.json"},
        )

    return r
