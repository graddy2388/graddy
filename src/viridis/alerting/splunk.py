"""
viridis.alerting.splunk – Splunk HTTP Event Collector (HEC) alerter.

Sends individual finding events to Splunk via the HEC JSON endpoint.
Each finding is a separate event so Splunk can field-extract and alert on them.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.request
import urllib.error
import ssl
from typing import List

from ..checks.base import CheckResult, Severity
from .base import BaseAlerter

logger = logging.getLogger(__name__)
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class SplunkHECAlerter(BaseAlerter):
    @property
    def name(self) -> str:
        return "splunk"

    def send(self, results: List[CheckResult], run_timestamp: str) -> None:
        hec_url  = self.config.get("hec_url", "").rstrip("/")
        hec_token = self.config.get("hec_token", "")
        index    = self.config.get("index", "main")
        source   = self.config.get("source", "viridis")
        verify_ssl = bool(self.config.get("verify_ssl", True))

        if not hec_url or not hec_token:
            logger.error("SplunkHECAlerter: hec_url and hec_token are required")
            return

        min_severity = self.config.get("min_severity", "high")
        min_rank = _SEV_RANK.get(min_severity, 3)

        events = []
        for r in results:
            for f in r.findings:
                if _SEV_RANK.get(f.severity.value, 0) >= min_rank:
                    events.append({
                        "time": time.time(),
                        "host": r.target,
                        "source": source,
                        "sourcetype": "viridis:finding",
                        "index": index,
                        "event": {
                            "target":          r.target,
                            "check":           r.check_name,
                            "severity":        f.severity.value,
                            "title":           f.title,
                            "description":     f.description,
                            "recommendation":  getattr(f, "recommendation", ""),
                            "scan_timestamp":  run_timestamp,
                        },
                    })

        if not events:
            return

        # Splunk HEC accepts newline-delimited JSON events in one request
        payload = "\n".join(json.dumps(e) for e in events).encode("utf-8")

        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        url = f"{hec_url}/services/collector/event"
        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Authorization": f"Splunk {hec_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15, context=ctx):
                pass
            logger.info("SplunkHECAlerter: sent %d events to %s", len(events), hec_url)
        except urllib.error.URLError as exc:
            logger.error("SplunkHECAlerter: request failed: %s", exc)
