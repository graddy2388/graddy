"""
viridis.alerting.webhook – Generic HTTP POST webhook alerter.

POSTs a JSON payload to any HTTP(S) endpoint, with an optional
Authorization header. Useful as a universal SIEM/SOAR integration.
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
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class WebhookAlerter(BaseAlerter):
    @property
    def name(self) -> str:
        return "webhook"

    def send(self, results: List[CheckResult], run_timestamp: str) -> None:
        url = self.config.get("url", "")
        if not url:
            logger.error("WebhookAlerter: no url configured")
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

        payload = {
            "source": "viridis",
            "timestamp": run_timestamp,
            "summary": {
                "total": len(qualifying),
                "critical": sum(1 for _, f in qualifying if f.severity == Severity.CRITICAL),
                "high":     sum(1 for _, f in qualifying if f.severity == Severity.HIGH),
                "medium":   sum(1 for _, f in qualifying if f.severity == Severity.MEDIUM),
            },
            "findings": [
                {
                    "target":       target,
                    "severity":     finding.severity.value,
                    "title":        finding.title,
                    "description":  finding.description,
                    "recommendation": getattr(finding, "recommendation", ""),
                }
                for target, finding in qualifying
            ],
        }

        auth_header = self.config.get("auth_header", "")
        headers = {"Content-Type": "application/json"}
        if auth_header:
            headers["Authorization"] = auth_header

        data = json.dumps(payload).encode("utf-8")
        try:
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=10):
                pass
            logger.info("WebhookAlerter: sent %d findings to %s", len(qualifying), url)
        except urllib.error.URLError as exc:
            logger.error("WebhookAlerter: request failed: %s", exc)
