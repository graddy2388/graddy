import logging
from typing import List

import requests
from requests.exceptions import RequestException

from ..checks.base import CheckResult, Finding, Severity
from .base import BaseAlerter

logger = logging.getLogger(__name__)

_SEVERITY_COLORS = {
    "critical": "attention",
    "high": "warning",
    "medium": "accent",
    "low": "good",
    "info": "default",
}

_THEME_COLORS = {
    "critical": "FF0000",
    "high": "FF8C00",
    "medium": "FFD700",
    "low": "008000",
    "info": "0078D4",
}


class TeamsAlerter(BaseAlerter):
    @property
    def name(self) -> str:
        return "teams"

    def send(self, results: List[CheckResult], run_timestamp: str) -> None:
        webhook_url = self.config.get("webhook_url", "")
        if not webhook_url:
            logger.error("TeamsAlerter: no webhook_url configured")
            return

        min_severity = self.config.get("min_severity", "high")
        min_rank = _severity_rank_value(min_severity)

        # Collect qualifying findings
        qualifying: List[tuple] = []  # (target, finding)
        for result in results:
            for finding in result.findings:
                if _severity_rank_value(finding.severity.value) >= min_rank:
                    qualifying.append((result.target, finding))

        if not qualifying:
            logger.debug("TeamsAlerter: no findings at or above %s; skipping", min_severity)
            return

        # Determine highest severity for theme color
        highest_sev = max(qualifying, key=lambda x: _severity_rank_value(x[1].severity.value))[1].severity.value
        theme_color = _THEME_COLORS.get(highest_sev, "0078D4")

        critical_count = sum(1 for _, f in qualifying if f.severity == Severity.CRITICAL)
        high_count = sum(1 for _, f in qualifying if f.severity == Severity.HIGH)

        # Build facts list for MessageCard sections
        facts = []
        for target, finding in qualifying:
            facts.append({
                "name": finding.severity.value.upper(),
                "value": f"[{target}] {finding.title}",
            })

        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": theme_color,
            "summary": f"Network Bot Alert — {critical_count} Critical, {high_count} High findings",
            "sections": [
                {
                    "activityTitle": f"Network Bot Alert — {run_timestamp}",
                    "activitySubtitle": (
                        f"{critical_count} Critical, {high_count} High findings detected"
                    ),
                    "facts": facts,
                    "markdown": True,
                }
            ],
        }

        try:
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            logger.info("TeamsAlerter: alert sent successfully (%d findings)", len(qualifying))
        except RequestException as exc:
            logger.error("TeamsAlerter: failed to send alert: %s", exc)


def _severity_rank_value(severity_value: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity_value, 0)
