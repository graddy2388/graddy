"""
network_bot.web.resolver – Hostname/IP resolution utility.
"""
from __future__ import annotations

import socket
import ipaddress
from datetime import datetime, timezone


def resolve_host(host: str) -> dict:
    """Given a host string (IP or hostname), resolve and return both.

    Returns: {hostname, ip_address, resolved_at}
    """
    result = {
        "hostname": "",
        "ip_address": "",
        "resolved_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        # Check if it's already an IP
        ipaddress.ip_address(host)
        result["ip_address"] = host
        try:
            result["hostname"] = socket.gethostbyaddr(host)[0]
        except Exception:
            result["hostname"] = host
    except ValueError:
        # It's a hostname
        result["hostname"] = host
        try:
            result["ip_address"] = socket.gethostbyname(host)
        except Exception:
            result["ip_address"] = ""
    return result
