"""
Shared input validation for HTTP APIs and subprocess-invoking checks.

Goals: reject out-of-range values, block shell metacharacters in nmap argument
strings, and keep query/body sizes bounded (DoS mitigation).
"""
from __future__ import annotations

import ipaddress
import re
import shlex
from typing import FrozenSet, Iterable, List, Optional, Set

# --- Size / rate limits ---
MAX_HOST_LEN = 253
MAX_NAME_LEN = 120
MAX_NOTES_LEN = 2000
MAX_DESC_LEN = 2000
MAX_NMAP_ARGS_LEN = 512
MAX_TAG_IDS = 50
MAX_QUERY_LIMIT = 500
MAX_EXPORT_LIMIT = 200
MAX_PAGE = 10_000
MAX_GROUP_TAG_NAME = 200
MAX_SCHEDULE_NAME = 200
MAX_CRON_FIELD_LEN = 512
MAX_SEARCH_QUERY_LEN = 200
MAX_IMPORT_ROWS = 2000
MAX_TARGET_IDS_PER_SCAN = 5000
MAX_TAG_NAMES_PER_IMPORT = 50

VALID_CHECKS: FrozenSet[str] = frozenset({
    "port_scan", "ssl", "http", "dns", "vuln", "smtp",
    "exposed_paths", "cipher", "nmap", "subnet_scan",
    "masscan", "nuclei", "enum4linux", "sqlmap", "gobuster", "hydra",
})

VALID_INTENSITIES: FrozenSet[str] = frozenset({
    "stealth", "normal", "aggressive",
})

VALID_PROFILE_TOOLS: FrozenSet[str] = frozenset({
    "nmap", "masscan", "nikto", "nuclei", "sqlmap", "hydra",
})

# nmap argv tokens: letters, numbers, common punctuation; no shell metacharacters
_NMAP_TOKEN_RE = re.compile(r"^[a-zA-Z0-9_.,/+:=!@*\-]+$")

# target_filter: "all" | "group:<id>" | "tag:<id>"
_TARGET_FILTER_RE = re.compile(r"^(all|group:\d+|tag:\d+)$")

# hex color #RGB or #RRGGBB
_COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{3}([0-9A-Fa-f]{3})?$")


def validate_host(host: str) -> str:
    """Accept IPv4/IPv6, CIDR, or a simple hostname (labels)."""
    h = host.strip()
    if not h or len(h) > MAX_HOST_LEN:
        raise ValueError("host must be 1–253 characters")
    if any(ord(c) < 32 for c in h):
        raise ValueError("host contains control characters")
    if "/" in h:
        try:
            ipaddress.ip_network(h, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid CIDR: {exc}") from exc
        return h
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        pass
    hn = h.rstrip(".")
    if not hn:
        raise ValueError("invalid host")
    for label in hn.split("."):
        if not label or len(label) > 63:
            raise ValueError("invalid hostname")
        if label.startswith("-") or label.endswith("-"):
            raise ValueError("invalid hostname label")
        if not re.match(r"^[a-zA-Z0-9_-]+$", label):
            raise ValueError("invalid hostname characters")
    return h


def validate_host_path_segment(ip: str) -> str:
    """Stricter rules for URL path segments (host detail page)."""
    if not ip or len(ip) > MAX_HOST_LEN:
        raise ValueError("invalid host")
    if any(c in ip for c in "/%\\\r\n\x00"):
        raise ValueError("invalid host path")
    if ".." in ip:
        raise ValueError("invalid host path")
    return validate_host(ip)


def validate_checks(checks: Optional[Iterable[str]], *, allow_empty: bool = False) -> Optional[List[str]]:
    if checks is None:
        return None
    lst = list(checks)
    if not lst and not allow_empty:
        raise ValueError("checks cannot be empty")
    invalid = [c for c in lst if c not in VALID_CHECKS]
    if invalid:
        raise ValueError(f"unknown checks: {', '.join(invalid)}")
    return lst


def validate_ports(ports: Optional[Iterable[int]]) -> Optional[List[int]]:
    if ports is None:
        return None
    out: List[int] = []
    for p in ports:
        if not isinstance(p, int) or not (0 < p <= 65535):
            raise ValueError(f"invalid port: {p!r}")
        out.append(p)
    return out


def validate_nmap_args(s: str) -> str:
    """Parse and constrain nmap extra arguments (no shell; argv injection hardening)."""
    if not s:
        return ""
    s = s.strip()
    if len(s) > MAX_NMAP_ARGS_LEN:
        raise ValueError(f"nmap_args must be at most {MAX_NMAP_ARGS_LEN} characters")
    try:
        tokens = shlex.split(s, posix=True)
    except ValueError as exc:
        raise ValueError(f"invalid nmap_args: {exc}") from exc
    for t in tokens:
        if not _NMAP_TOKEN_RE.match(t):
            raise ValueError(f"disallowed nmap argument token: {t!r}")
    return s


def validate_target_filter(s: str) -> str:
    t = s.strip()
    if not t or len(t) > 200:
        raise ValueError("invalid target_filter")
    if not _TARGET_FILTER_RE.match(t):
        raise ValueError("target_filter must be 'all', 'group:<id>', or 'tag:<id>'")
    return t


def validate_color_hex(color: str) -> str:
    c = color.strip()
    if not _COLOR_RE.match(c):
        raise ValueError("color must be a #RGB or #RRGGBB hex value")
    return c


def clamp_limit(value: int, *, default: int, cap: int, minimum: int = 1) -> int:
    if value < minimum:
        return default
    return min(value, cap)


def clamp_page(page: int) -> int:
    if page < 1:
        return 1
    return min(page, MAX_PAGE)


def truncate_search_query(q: str) -> str:
    return q[:MAX_SEARCH_QUERY_LEN] if len(q) > MAX_SEARCH_QUERY_LEN else q
