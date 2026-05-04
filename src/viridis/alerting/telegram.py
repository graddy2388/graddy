"""
viridis.alerting.telegram – Telegram Bot alerter.

Sends scan alerts via Telegram Bot API using HTML formatting.
Requires a bot token (from @BotFather) and a chat/channel ID.
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

_SEV_ICON = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "🔵",
}
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class TelegramAlerter(BaseAlerter):
    @property
    def name(self) -> str:
        return "telegram"

    def send(self, results: List[CheckResult], run_timestamp: str) -> None:
        bot_token = self.config.get("bot_token", "")
        chat_id   = self.config.get("chat_id", "")

        if not bot_token or not chat_id:
            logger.error("TelegramAlerter: bot_token and chat_id are required")
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

        lines = [
            "<b>🛡 Viridis Security Alert</b>",
            f"<i>{run_timestamp}</i>",
            f"🔴 <b>{critical}</b> Critical  🟠 <b>{high}</b> High  📊 <b>{len(qualifying)}</b> Total",
            "",
        ]
        for target, finding in qualifying[:10]:
            icon = _SEV_ICON.get(finding.severity.value, "⚪")
            lines.append(f"{icon} <code>{target}</code> — {finding.title}")
        if len(qualifying) > 10:
            lines.append(f"<i>…and {len(qualifying) - 10} more findings</i>")

        text = "\n".join(lines)
        url  = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = json.dumps({
            "chat_id":    chat_id,
            "text":       text,
            "parse_mode": "HTML",
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10):
                pass
            logger.info("TelegramAlerter: sent %d findings to chat %s", len(qualifying), chat_id)
        except urllib.error.URLError as exc:
            logger.error("TelegramAlerter: request failed: %s", exc)
