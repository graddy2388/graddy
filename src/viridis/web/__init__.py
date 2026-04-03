# viridis.web – FastAPI web GUI
from typing import Dict
import asyncio
import secrets
import time
import threading

# Shared active scans dict so scheduler_service can push progress events
active_scans: Dict[int, asyncio.Queue] = {}

# Per-scan WebSocket tokens – generated on scan creation, validated on WS connect
_scan_tokens: Dict[int, str] = {}
_scan_tokens_lock = threading.Lock()


def create_scan_token(scan_id: int) -> str:
    """Generate and store a cryptographic token for WebSocket auth."""
    token = secrets.token_urlsafe(32)
    with _scan_tokens_lock:
        _scan_tokens[scan_id] = token
    return token


def verify_scan_token(scan_id: int, token: str) -> bool:
    """Constant-time comparison of provided token against stored one."""
    with _scan_tokens_lock:
        expected = _scan_tokens.get(scan_id)
    if expected is None:
        return False
    return secrets.compare_digest(expected, token)


def revoke_scan_token(scan_id: int) -> None:
    """Remove the token once the scan is done."""
    with _scan_tokens_lock:
        _scan_tokens.pop(scan_id, None)


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
