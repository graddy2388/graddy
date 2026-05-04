"""
viridis.alerting.discord – Discord Webhook alerter.

Posts a rich embed to a Discord channel when findings meet or exceed
the configured minimum severity.
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

_SEV_COLOUR = {
    "critical": 0xDC2626,
    "high":     0xEA580C,
    "medium":   0xD97706,
    "low":      0x16A34A,
    "info":     0x2563EB,
}
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class DiscordAlerter(BaseAlerter):
    @property
    def name(self) -> str:
        return "discord"

    def send(self, results: List[CheckResult], run_timestamp: str) -> None:
        webhook_url = self.config.get("webhook_url", "")
        if not webhook_url:
            logger.error("DiscordAlerter: no webhook_url configured")
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

        # Highest severity determines embed colour
        max_sev = max(qualifying, key=lambda x: _SEV_RANK.get(x[1].severity.value, 0))[1].severity.value
        colour = _SEV_COLOUR.get(max_sev, 0x6B7280)

        lines = []
        for target, finding in qualifying[:15]:
            sev_label = finding.severity.value.upper()
            lines.append(f"**[{sev_label}]** `{target}` — {finding.title}")
        if len(qualifying) > 15:
            lines.append(f"*…and {len(qualifying) - 15} more findings*")

        embed = {
            "title": "Viridis Security Alert",
            "description": "\n".join(lines),
            "color": colour,
            "footer": {"text": f"Scan completed at {run_timestamp}"},
            "fields": [
                {"name": "Critical", "value": str(critical), "inline": True},
                {"name": "High",     "value": str(high),     "inline": True},
                {"name": "Total",    "value": str(len(qualifying)), "inline": True},
            ],
        }

        payload = json.dumps({"embeds": [embed]}).encode("utf-8")
        try:
            req = urllib.request.Request(
                webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10):
                pass
            logger.info("DiscordAlerter: sent %d findings", len(qualifying))
        except urllib.error.URLError as exc:
            logger.error("DiscordAlerter: request failed: %s", exc)
