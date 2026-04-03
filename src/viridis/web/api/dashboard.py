"""
viridis.web.api.dashboard – Dashboard stats endpoint.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends


def make_router(get_db_dep) -> APIRouter:
    router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

    @router.get("/stats")
    def dashboard_stats(db=Depends(get_db_dep)):
        from ..db.crud import get_dashboard_stats
        return get_dashboard_stats(db)

    return router
