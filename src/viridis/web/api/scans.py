"""
viridis.web.api.scans â€" REST endpoints for scan management and triggering.
"""
from __future__ import annotations

import asyncio
import json
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator, model_validator

from ..db.crud import (
    create_scan, finish_scan, fail_scan,
    get_scans, get_scan, get_scan_results,
    get_targets, add_scan_result,
    get_scan_profile, upsert_host_inventory, upsert_host_service,
    upsert_host_software,
    is_in_scope, update_target_risk, auto_tag_target,
)
from ..validation import (
    MAX_QUERY_LIMIT,
    MAX_TARGET_IDS_PER_SCAN,
    clamp_limit,
    validate_checks,
    validate_host,
)


class ScanIn(BaseModel):
    target_ids: Optional[List[int]] = None
    group_id: Optional[int] = None
    tag_id: Optional[int] = None
    profile_id: Optional[int] = None
    subnet: Optional[str] = None
    is_external: Optional[bool] = False
    scan_name: Optional[str] = None
    adhoc_host: Optional[str] = None        # one-off host without a DB entry
    adhoc_checks: Optional[List[str]] = None  # checks to run for adhoc scan

    model_config = {"extra": "ignore"}

    @field_validator("subnet", "adhoc_host", "scan_name", mode="before")
    @classmethod
    def _strip_opt(cls, v):
        if v is None:
            return v
        if isinstance(v, str):
            return v.strip()
        return v

    @model_validator(mode="after")
    def _validate(self) -> ScanIn:
        if self.scan_name is not None and len(self.scan_name) > 200:
            raise ValueError("scan_name must be 200 characters or fewer")
        if self.target_ids is not None and len(self.target_ids) > MAX_TARGET_IDS_PER_SCAN:
            raise ValueError(f"at most {MAX_TARGET_IDS_PER_SCAN} target_ids allowed")
        if self.subnet and self.adhoc_host:
            raise ValueError("specify only one of subnet or adhoc_host")
        if self.subnet:
            validate_host(self.subnet)
        if self.adhoc_host:
            validate_host(self.adhoc_host)
            if self.adhoc_checks:
                validate_checks(self.adhoc_checks, allow_empty=False)
        return self


# Default checks registry â€" new checks registered here
_DEFAULT_CHECKS = [
    "port_scan", "ssl", "http", "dns", "vuln", "smtp", "exposed_paths", "cipher"
]


def _load_check_registry():
    from ...checks import PortScanCheck, SSLCheck, HTTPCheck, DNSCheck, VulnCheck, SMTPCheck, ExposedPathsCheck, CipherCheck
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
        from ...checks.nmap_scan import NmapScanCheck
        registry["nmap"] = NmapScanCheck
    except ImportError:
        pass
    try:
        from ...checks.subnet_scan import SubnetScanCheck
        registry["subnet_scan"] = SubnetScanCheck
    except ImportError:
        pass
    try:
        from ...checks.masscan_check import MasscanCheck
        registry["masscan"] = MasscanCheck
    except ImportError:
        pass
    try:
        from ...checks.nuclei_check import NucleiCheck
        registry["nuclei"] = NucleiCheck
    except ImportError:
        pass
    try:
        from ...checks.enum4linux_check import Enum4LinuxCheck
        registry["enum4linux"] = Enum4LinuxCheck
    except ImportError:
        pass
    try:
        from ...checks.sqlmap_check import SQLMapCheck
        registry["sqlmap"] = SQLMapCheck
    except ImportError:
        pass
    try:
        from ...checks.gobuster_check import GobusterCheck
        registry["gobuster"] = GobusterCheck
    except ImportError:
        pass
    try:
        from ...checks.hydra_check import HydraCheck
        registry["hydra"] = HydraCheck
    except ImportError:
        pass
    try:
        from ...checks.headers_check import HeadersCheck
        registry["headers"] = HeadersCheck
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

    def _put(event: dict) -> None:
        loop.call_soon_threadsafe(progress_queue.put_nowait, event)

    # Per-check timeout (seconds). Heavy checks get more time.
    _CHECK_TIMEOUTS = {
        "nmap": 300, "subnet_scan": 300,
        "port_scan": 120, "vuln": 120, "exposed_paths": 120,
        "ssl": 90, "cipher": 90, "smtp": 90,
        "http": 60, "dns": 60,
    }
    _DEFAULT_CHECK_TIMEOUT = 90

    try:
        # Load check classes inside try so import failures emit a proper error event
        CHECK_REGISTRY = _load_check_registry()

        sev_counts: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }
        per_target_sev: Dict[str, Dict[str, int]] = {}

        def _count_checks(t):
            c = t.get("checks")
            if isinstance(c, list):
                return len(c)
            if isinstance(c, str):
                try:
                    return len(json.loads(c))
                except Exception:
                    pass
            return len(_DEFAULT_CHECKS)

        total_checks = sum(_count_checks(t) for t in targets)
        done = 0

        for target in targets:
            host = target["host"]
            name = target.get("name", host)

            # Scope check â€" short-lived connection
            try:
                with get_db(db_path) as _db:
                    resolved_ip = target.get("last_resolved_ip") or host
                    if not is_in_scope(_db, resolved_ip):
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
                check_timeout = _CHECK_TIMEOUTS.get(check_name, _DEFAULT_CHECK_TIMEOUT)
                try:
                    _ex = ThreadPoolExecutor(max_workers=1)
                    _fut = _ex.submit(checker.run, target)
                    try:
                        result = _fut.result(timeout=check_timeout)
                    except FuturesTimeout:
                        from ...checks.base import CheckResult as CR
                        result = CR(
                            check_name=check_name,
                            target=host,
                            passed=False,
                            error=f"Check timed out after {check_timeout}s",
                        )
                        _put({
                            "type": "finding",
                            "target": host,
                            "severity": "medium",
                            "title": f"{check_name} timed out after {check_timeout}s",
                        })
                    finally:
                        _ex.shutdown(wait=False)
                except Exception as exc:
                    from ...checks.base import CheckResult as CR
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
                    # Per-target tracking
                    tgt_sev = per_target_sev.setdefault(host, {"critical":0,"high":0,"medium":0,"low":0})
                    if sev_val in tgt_sev:
                        tgt_sev[sev_val] += 1
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

                # Short-lived connection for each result save
                try:
                    with get_db(db_path) as _db:
                        add_scan_result(
                            _db,
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

                        # Persist host inventory + auto-tag from nmap/port scans
                        if check_name in ("nmap", "subnet_scan") and result.metadata:
                            try:
                                _persist_host_data(_db, host, result.metadata)
                                _persist_software_inventory(_db, host, result.metadata)
                            except Exception:
                                pass

                        if check_name in ("nmap", "subnet_scan", "port_scan") and result.metadata:
                            try:
                                open_ports = result.metadata.get("open_ports", [])
                                os_guesses = result.metadata.get("os_guesses", [])
                                os_guess = ""
                                if os_guesses:
                                    best = max(os_guesses, key=lambda x: x.get("accuracy", 0))
                                    os_guess = best.get("name", "")
                                added_tags = auto_tag_target(_db, target.get("id", 0), open_ports, os_guess)
                                if added_tags:
                                    _put({
                                        "type": "finding",
                                        "target": host,
                                        "severity": "info",
                                        "title": f"Auto-tagged: {', '.join(added_tags)}",
                                    })
                            except Exception:
                                pass
                except Exception:
                    pass  # don't let a DB save failure abort the scan

                done += 1

        with get_db(db_path) as _db:
            finish_scan(_db, scan_id, {
                "total_targets": len(targets),
                **sev_counts,
            })

        # Update per-target risk scores
        from datetime import datetime, timezone as _tz
        _now = datetime.now(_tz.utc).isoformat()
        for _host, _tgt_sev in per_target_sev.items():
            _score = min(100,
                _tgt_sev.get("critical", 0) * 40 +
                _tgt_sev.get("high", 0) * 15 +
                _tgt_sev.get("medium", 0) * 5 +
                _tgt_sev.get("low", 0) * 1
            )
            try:
                with get_db(db_path) as _db:
                    update_target_risk(_db, _host, _score, _now)
            except Exception:
                pass

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
            with _get_db(db_path) as _db:
                fail_scan(_db, scan_id)
        except Exception:
            pass
        _put({"type": "error", "message": str(exc)})


def _resolve_hostname(ip: str) -> str:
    """Multi-method hostname resolution: PTR DNS, NetBIOS, mDNS."""
    try:
        from ...hostname_resolver import resolve_hostname
        return resolve_hostname(ip)
    except Exception:
        import socket
        try:
            return socket.gethostbyaddr(ip)[0] or ""
        except Exception:
            return ""


def _persist_host_data(db, host: str, metadata: Dict) -> None:
    """Save host inventory data discovered via nmap/subnet scan to the DB."""
    if "hosts" in metadata:
        # Subnet scan – multiple hosts
        for h in metadata["hosts"]:
            hostname = h.get("hostname", "") or _resolve_hostname(h["ip"])
            upsert_host_inventory(
                db,
                ip_address=h["ip"],
                hostname=hostname,
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
        hostname = metadata.get("hostname", "") or _resolve_hostname(host)
        upsert_host_inventory(
            db,
            ip_address=host,
            hostname=hostname,
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


def _persist_software_inventory(db, host: str, metadata: Dict) -> None:
    """Extract service banners from nmap metadata and enqueue CVE lookups."""
    from ...cve_lookup import lookup_cves

    def _store_service(ip: str, port: int, svc: Dict, source: str = "nmap") -> None:
        product = svc.get("product", "").strip()
        version = svc.get("version", "").strip()
        if not product:
            return
        try:
            cves = lookup_cves(product, version)
        except Exception:
            cves = []
        try:
            upsert_host_software(db, host_ip=ip, name=product, version=version,
                                 source=source, port=port, cves=cves)
        except Exception:
            pass

    if "hosts" in metadata:
        for h in metadata["hosts"]:
            for port_str, svc in h.get("services", {}).items():
                try:
                    _store_service(h["ip"], int(port_str), svc)
                except (ValueError, TypeError):
                    pass
    elif "services" in metadata:
        for port_str, svc in metadata.get("services", {}).items():
            try:
                _store_service(host, int(port_str), svc)
            except (ValueError, TypeError):
                pass


def make_router(get_db_dep, config: Dict[str, Any], db_path: str, active_scans: Dict[int, asyncio.Queue]) -> APIRouter:
    r = APIRouter(prefix="/api/scans", tags=["scans"])

    @r.get("")
    def list_scans(limit: int = 50, db=Depends(get_db_dep)):
        limit = clamp_limit(limit, default=50, cap=MAX_QUERY_LIMIT)
        return get_scans(db, limit=limit)

    @r.get("/{id}")
    def scan_detail(id: int, db=Depends(get_db_dep)):
        scan = get_scan(db, id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        results = get_scan_results(db, id)
        return {**scan, "results": results}

    @r.post("", status_code=201)
    async def trigger_scan(request: Request, body: ScanIn, db=Depends(get_db_dep)):
        # Rate limiting: prevent DoS via excessive scan triggers
        from .. import check_scan_rate_limit
        client_ip = request.client.host if request.client else "unknown"
        if not check_scan_rate_limit(client_ip):
            raise HTTPException(
                status_code=429,
                detail="Too many scan requests. Please wait before triggering another scan.",
            )

        # Load profile if specified
        profile = None
        if body.profile_id:
            profile = get_scan_profile(db, body.profile_id)

        # Subnet scan: create a synthetic target from the CIDR (validated in ScanIn)
        if body.subnet:
            targets = [{
                "id": 0,
                "name": f"Subnet {body.subnet}",
                "host": body.subnet,
                "checks": ["subnet_scan"],
                "enabled": 1,
            }]
        elif body.adhoc_host:
            targets = [{
                "id": 0,
                "name": body.adhoc_host,
                "host": body.adhoc_host,
                "checks": body.adhoc_checks or _DEFAULT_CHECKS,
                "enabled": 1,
                "ports": [80, 443, 22, 25, 8080, 8443, 3306, 3389],
                "smtp_ports": [25, 587, 465],
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
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()
        active_scans[scan_id] = queue

        # Generate a per-scan WebSocket token so only the requester can connect
        from .. import create_scan_token, revoke_scan_token
        ws_token = create_scan_token(scan_id)

        def _run():
            try:
                run_checks_for_web(targets, config, db_path, scan_id, queue, loop)
            except Exception as _exc:
                loop.call_soon_threadsafe(
                    queue.put_nowait,
                    {"type": "error", "message": f"Scan thread crashed: {_exc}"},
                )
            import time
            time.sleep(2)
            active_scans.pop(scan_id, None)
            revoke_scan_token(scan_id)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()

        return {"scan_id": scan_id, "ws_token": ws_token}

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
