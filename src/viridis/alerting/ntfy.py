"""
viridis.alerting.ntfy – ntfy.sh push notification alerter.

Sends a push notification via ntfy (self-hosted or ntfy.sh cloud).
Supports topic-based routing, priority mapping, and auth tokens.
"""
from __future__ import annotations

import logging
import urllib.request
import urllib.error
from typing import List

from ..checks.base import CheckResult, Severity
from .base import BaseAlerter

logger = logging.getLogger(__name__)

_NTFY_PRIORITY = {
    "critical": "urgent",
    "high":     "high",
    "medium":   "default",
    "low":      "low",
    "info":     "min",
}
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class NtfyAlerter(BaseAlerter):
    @property
    def name(self) -> str:
        return "ntfy"

    def send(self, results: List[CheckResult], run_timestamp: str) -> None:
        server = self.config.get("server", "https://ntfy.sh").rstrip("/")
        topic  = self.config.get("topic", "")
        token  = self.config.get("token", "")

        if not topic:
            logger.error("NtfyAlerter: no topic configured")
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
        max_sev  = max(qualifying, key=lambda x: _SEV_RANK.get(x[1].severity.value, 0))[1].severity.value

        title   = f"Viridis: {critical} Critical, {high} High"
        lines   = [f"{f.severity.value.upper()} [{t}]: {f.title}" for t, f in qualifying[:8]]
        if len(qualifying) > 8:
            lines.append(f"…and {len(qualifying) - 8} more")
        message = "\n".join(lines)

        url = f"{server}/{topic}"
        headers = {
            "Title":    title,
            "Priority": _NTFY_PRIORITY.get(max_sev, "default"),
            "Tags":     "viridis,security",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            req = urllib.request.Request(
                url,
                data=message.encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10):
                pass
            logger.info("NtfyAlerter: notification sent to %s/%s", server, topic)
        except urllib.error.URLError as exc:
            logger.error("NtfyAlerter: request failed: %s", exc)
