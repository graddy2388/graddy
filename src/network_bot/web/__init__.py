# network_bot.web – FastAPI web GUI
from typing import Dict
import asyncio
import time
import threading

# Shared active scans dict so scheduler_service can push progress events
active_scans: Dict[int, asyncio.Queue] = {}

# ---------------------------------------------------------------------------
# Simple in-memory rate limiter for scan triggers
# ---------------------------------------------------------------------------
_scan_rate_lock = threading.Lock()
# Maps client_ip -> list of timestamps of recent scan requests
_scan_rate_buckets: Dict[str, list] = {}
# Allow at most SCAN_RATE_LIMIT scan triggers per SCAN_RATE_WINDOW seconds per IP
SCAN_RATE_LIMIT = 10
SCAN_RATE_WINDOW = 60  # seconds


def check_scan_rate_limit(client_ip: str) -> bool:
    """Return True if the client is within the rate limit, False if exceeded."""
    now = time.monotonic()
    with _scan_rate_lock:
        bucket = _scan_rate_buckets.get(client_ip, [])
        # Keep only timestamps within the window
        bucket = [t for t in bucket if now - t < SCAN_RATE_WINDOW]
        if len(bucket) >= SCAN_RATE_LIMIT:
            _scan_rate_buckets[client_ip] = bucket
            return False
        bucket.append(now)
        _scan_rate_buckets[client_ip] = bucket
        return True
