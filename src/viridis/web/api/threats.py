"""
viridis.web.api.threats – Threat intelligence feed endpoints.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Query

from ...threat_feeds import get_feed


def make_router(get_db_dep) -> APIRouter:
    r = APIRouter(prefix="/api/threats", tags=["threats"])

    @r.get("/feed")
    def threat_feed(
        limit: int = Query(default=50, ge=1, le=200),
        source: str = Query(default="all"),
        cve_ids: Optional[str] = Query(default=None, description="Comma-separated CVE IDs to filter by"),
    ):
        """Return threat intelligence feed items. Optionally filter by source or CVE IDs."""
        return get_feed(limit=limit, source=source, cve_filter=cve_ids)

    return r
