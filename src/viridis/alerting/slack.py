"""
viridis.alerting.slack – Slack Incoming Webhook alerter.

Sends a structured Slack message with Block Kit formatting when findings
meet or exceed the configured minimum severity.
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

_SEV_EMOJI = {
    "critical": ":red_circle:",
    "high":     ":orange_circle:",
    "medium":   ":yellow_circle:",
    "low":      ":green_circle:",
    "info":     ":blue_circle:",
}
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class SlackAlerter(BaseAlerter):
    @property
    def name(self) -> str:
        return "slack"

    def send(self, results: List[CheckResult], run_timestamp: str) -> None:
        webhook_url = self.config.get("webhook_url", "")
        if not webhook_url:
            logger.error("SlackAlerter: no webhook_url configured")
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
        medium   = sum(1 for _, f in qualifying if f.severity == Severity.MEDIUM)

        lines = []
        for target, finding in qualifying[:20]:
            em = _SEV_EMOJI.get(finding.severity.value, ":white_circle:")
            lines.append(f"{em} `{target}` — {finding.title}")
        if len(qualifying) > 20:
            lines.append(f"_…and {len(qualifying) - 20} more findings_")

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "Viridis Security Alert", "emoji": True},
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*{critical} Critical  •  {high} High  •  {medium} Medium*\n"
                        f"Scan completed at {run_timestamp}"
                    ),
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "\n".join(lines)},
            },
        ]

        payload = json.dumps({"blocks": blocks}).encode("utf-8")
        try:
            req = urllib.request.Request(
                webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10):
                pass
            logger.info("SlackAlerter: sent %d findings", len(qualifying))
        except urllib.error.URLError as exc:
            logger.error("SlackAlerter: request failed: %s", exc)
