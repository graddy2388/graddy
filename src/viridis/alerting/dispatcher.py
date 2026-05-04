"""
viridis.alerting.dispatcher – Fan-out alert dispatcher.

Loads integration config from the DB (app_settings key='integrations')
and instantiates the appropriate alerters. Falls back to the legacy
YAML config for backwards compatibility.
"""
import json
import logging
from typing import List

from ..checks.base import CheckResult, Severity

logger = logging.getLogger(__name__)

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _load_db_integrations(db_path: str) -> dict:
    """Read the integrations JSON blob from app_settings, or return {}."""
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT value FROM app_settings WHERE key = 'integrations'"
        ).fetchone()
        conn.close()
        if row:
            return json.loads(row["value"])
    except Exception as exc:
        logger.debug("Could not load integrations from DB: %s", exc)
    return {}


class AlertDispatcher:
    def __init__(self, config: dict, db_path: str = ""):
        self._alerters = []

        db_cfg = _load_db_integrations(db_path) if db_path else {}
        alerting_cfg = config.get("alerting", {})
        global_min   = alerting_cfg.get("min_severity", "high")

        def _try_add(alerter_cls, cfg: dict) -> None:
            try:
                self._alerters.append(alerter_cls(cfg))
                logger.debug("AlertDispatcher: loaded %s", alerter_cls.__name__)
            except Exception as exc:
                logger.warning("AlertDispatcher: failed to load %s: %s", alerter_cls.__name__, exc)

        # Slack
        slack_db = db_cfg.get("slack", {})
        if slack_db.get("enabled") and slack_db.get("webhook_url"):
            from .slack import SlackAlerter
            slack_db.setdefault("min_severity", global_min)
            _try_add(SlackAlerter, slack_db)

        # Discord
        discord_db = db_cfg.get("discord", {})
        if discord_db.get("enabled") and discord_db.get("webhook_url"):
            from .discord import DiscordAlerter
            discord_db.setdefault("min_severity", global_min)
            _try_add(DiscordAlerter, discord_db)

        # Microsoft Teams (DB config preferred, YAML fallback)
        teams_db = db_cfg.get("teams", {})
        if teams_db.get("enabled") and teams_db.get("webhook_url"):
            from .teams import TeamsAlerter
            teams_db.setdefault("min_severity", global_min)
            _try_add(TeamsAlerter, teams_db)
        elif alerting_cfg.get("teams", {}).get("enabled") and alerting_cfg["teams"].get("webhook_url"):
            from .teams import TeamsAlerter
            t = dict(alerting_cfg["teams"])
            t.setdefault("min_severity", global_min)
            _try_add(TeamsAlerter, t)

        # Telegram
        tg_db = db_cfg.get("telegram", {})
        if tg_db.get("enabled") and tg_db.get("bot_token") and tg_db.get("chat_id"):
            from .telegram import TelegramAlerter
            tg_db.setdefault("min_severity", global_min)
            _try_add(TelegramAlerter, tg_db)

        # PagerDuty
        pd_db = db_cfg.get("pagerduty", {})
        if pd_db.get("enabled") and pd_db.get("integration_key"):
            from .pagerduty import PagerDutyAlerter
            pd_db.setdefault("min_severity", global_min)
            _try_add(PagerDutyAlerter, pd_db)

        # ntfy
        ntfy_db = db_cfg.get("ntfy", {})
        if ntfy_db.get("enabled") and ntfy_db.get("topic"):
            from .ntfy import NtfyAlerter
            ntfy_db.setdefault("min_severity", global_min)
            _try_add(NtfyAlerter, ntfy_db)

        # Email (DB config preferred, YAML fallback)
        email_db = db_cfg.get("email", {})
        if email_db.get("enabled") and email_db.get("smtp_host") and email_db.get("to"):
            from .email_alert import EmailAlerter
            email_mapped = {
                "smtp_host":     email_db.get("smtp_host", ""),
                "smtp_port":     int(email_db.get("smtp_port", 587)),
                "smtp_user":     email_db.get("smtp_user", ""),
                "smtp_password": email_db.get("smtp_password", ""),
                "from_addr":     email_db.get("from_addr", ""),
                "to_addrs":      [a.strip() for a in email_db.get("to", "").split(",") if a.strip()],
                "use_tls":       email_db.get("use_tls", True),
                "min_severity":  email_db.get("min_severity", global_min),
                "enabled":       True,
            }
            _try_add(EmailAlerter, email_mapped)
        elif (alerting_cfg.get("email", {}).get("enabled")
              and alerting_cfg["email"].get("smtp_host")
              and alerting_cfg["email"].get("from_addr")
              and alerting_cfg["email"].get("to_addrs")):
            from .email_alert import EmailAlerter
            e = dict(alerting_cfg["email"])
            e.setdefault("min_severity", global_min)
            _try_add(EmailAlerter, e)

        # Splunk HEC
        splunk_db = db_cfg.get("splunk", {})
        if splunk_db.get("enabled") and splunk_db.get("hec_url") and splunk_db.get("hec_token"):
            from .splunk import SplunkHECAlerter
            splunk_db.setdefault("min_severity", global_min)
            _try_add(SplunkHECAlerter, splunk_db)

        # Generic Webhook / SIEM
        wh_db = db_cfg.get("webhook", {})
        if wh_db.get("enabled") and wh_db.get("url"):
            from .webhook import WebhookAlerter
            wh_db.setdefault("min_severity", global_min)
            _try_add(WebhookAlerter, wh_db)

        if self._alerters:
            logger.info("AlertDispatcher: %d alerter(s) active", len(self._alerters))
        else:
            logger.debug("AlertDispatcher: no alerters configured")

    def dispatch(self, results: List[CheckResult], run_timestamp: str) -> None:
        if not self._alerters:
            return
        for alerter in self._alerters:
            try:
                alerter.send(results, run_timestamp)
            except Exception as exc:
                logger.error("AlertDispatcher: alerter '%s' raised: %s", alerter.name, exc)

    @staticmethod
    def _severity_rank(s: Severity) -> int:
        return _SEV_RANK.get(s.value, 0)
