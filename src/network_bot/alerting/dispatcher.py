import logging
from typing import List

from ..checks.base import CheckResult, Severity
from .teams import TeamsAlerter
from .email_alert import EmailAlerter

logger = logging.getLogger(__name__)


class AlertDispatcher:
    def __init__(self, config: dict):
        self._alerters = []
        alerting_cfg = config.get("alerting", {})

        if not alerting_cfg.get("enabled", False):
            logger.debug("AlertDispatcher: alerting is disabled in config")
            return

        global_min_severity = alerting_cfg.get("min_severity", "high")

        # Teams alerter
        teams_cfg = alerting_cfg.get("teams", {})
        if teams_cfg.get("enabled", False) and teams_cfg.get("webhook_url", ""):
            merged_teams_cfg = dict(teams_cfg)
            merged_teams_cfg.setdefault("min_severity", global_min_severity)
            self._alerters.append(TeamsAlerter(merged_teams_cfg))
            logger.debug("AlertDispatcher: Teams alerter enabled")

        # Email alerter
        email_cfg = alerting_cfg.get("email", {})
        if (
            email_cfg.get("enabled", False)
            and email_cfg.get("smtp_host", "")
            and email_cfg.get("from_addr", "")
            and email_cfg.get("to_addrs", [])
        ):
            merged_email_cfg = dict(email_cfg)
            merged_email_cfg.setdefault("min_severity", global_min_severity)
            self._alerters.append(EmailAlerter(merged_email_cfg))
            logger.debug("AlertDispatcher: Email alerter enabled")

    def dispatch(self, results: List[CheckResult], run_timestamp: str) -> None:
        if not self._alerters:
            return

        for alerter in self._alerters:
            try:
                alerter.send(results, run_timestamp)
            except Exception as exc:
                logger.error(
                    "AlertDispatcher: alerter '%s' raised an unexpected error: %s",
                    alerter.name,
                    exc,
                )

    @staticmethod
    def _severity_rank(s: Severity) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[s.value]
