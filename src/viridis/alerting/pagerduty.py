"""
viridis.alerting.pagerduty – PagerDuty Events API v2 alerter.

Creates a PagerDuty incident for each qualifying finding using the
Events API v2 (requires a Service Integration Key, not the REST API key).
"""
from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from typing import List

from ..checks.base import CheckResult, Severity
from .base import BaseAlerter

logger = logging.getLogger(__name__)

_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"
_SEV_MAP = {
    "critical": "critical",
    "high":     "error",
    "medium":   "warning",
    "low":      "info",
    "info":     "info",
}
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class PagerDutyAlerter(BaseAlerter):
    @property
    def name(self) -> str:
        return "pagerduty"

    def send(self, results: List[CheckResult], run_timestamp: str) -> None:
        key = self.config.get("integration_key", "")
        if not key:
            logger.error("PagerDutyAlerter: no integration_key configured")
            return

        min_severity = self.config.get("min_severity", "high")
        min_rank = _SEV_RANK.get(min_severity, 3)

        qualifying = [
            (r.target, f)
            for r in results
            for f in r.findings
            if _SEV_RANK.get(f.severity.value, 0) >= min_rank
        ]
        if not qualifying:
            return

        critical = sum(1 for _, f in qualifying if f.severity == Severity.CRITICAL)
        high     = sum(1 for _, f in qualifying if f.severity == Severity.HIGH)

        # Create a single rolled-up event for the scan (avoids alert storm)
        max_sev = max(qualifying, key=lambda x: _SEV_RANK.get(x[1].severity.value, 0))[1].severity.value
        summary = (
            f"Viridis: {critical} Critical, {high} High findings — {run_timestamp}"
        )
        details = {
            "total_findings": len(qualifying),
            "targets": list({t for t, _ in qualifying}),
            "top_findings": [
                {"target": t, "severity": f.severity.value, "title": f.title}
                for t, f in qualifying[:10]
            ],
        }

        payload = {
            "routing_key": key,
            "event_action": "trigger",
            "payload": {
                "summary": summary,
                "severity": _SEV_MAP.get(max_sev, "error"),
                "source": "viridis",
                "timestamp": run_timestamp,
                "custom_details": details,
            },
        }

        data = json.dumps(payload).encode("utf-8")
        try:
            req = urllib.request.Request(
                _EVENTS_URL,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                logger.info("PagerDutyAlerter: incident created (status %s)", resp.status)
        except urllib.error.URLError as exc:
            logger.error("PagerDutyAlerter: request failed: %s", exc)
