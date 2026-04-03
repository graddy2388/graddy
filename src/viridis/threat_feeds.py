"""
viridis.threat_feeds – Live threat intelligence aggregator.

Aggregates from:
  - CISA KEV (Known Exploited Vulnerabilities catalog)
  - NVD Recent CVEs
  - Cloudflare Security Blog RSS
  - SANS Internet Storm Center RSS
  - Bleeping Computer Security RSS

Feed items are cached in memory for 15 minutes. Refresh is driven by
APScheduler in app.py. Each item:
  {id, title, source, url, severity, published_at, summary, cve_ids}
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory cache
# ---------------------------------------------------------------------------

_CACHE_LOCK = threading.Lock()
_cached_items: List[Dict] = []
_last_refresh: float = 0.0
_CACHE_TTL = 900  # 15 minutes
_MAX_ITEMS = 100
_MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB cap per feed response

# Only allow http/https URLs from feed items — block javascript: data: etc.
_SAFE_URL_RE = re.compile(r'^https?://', re.IGNORECASE)


def get_cached_feed() -> List[Dict]:
    """Return the latest cached feed items (thread-safe)."""
    with _CACHE_LOCK:
        return list(_cached_items)


def _set_cache(items: List[Dict]) -> None:
    global _cached_items, _last_refresh
    # Sort by published_at descending
    items.sort(key=lambda x: x.get("published_at", ""), reverse=True)
    with _CACHE_LOCK:
        _cached_items = items[:_MAX_ITEMS]
        _last_refresh = time.time()


def is_stale() -> bool:
    with _CACHE_LOCK:
        return time.time() - _last_refresh > _CACHE_TTL


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fetch_url(url: str, timeout: float = 10.0) -> Optional[bytes]:
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Viridis/2.0 Security Scanner"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(_MAX_RESPONSE_BYTES)
    except Exception as exc:
        logger.warning("Threat feed fetch failed for %s: %s", url, exc)
        return None


def _safe_url(url: str) -> str:
    """Return url only if it is a safe http/https URL, otherwise empty string."""
    if url and _SAFE_URL_RE.match(url.strip()):
        return url.strip()
    return ""


def _extract_cves(text: str) -> List[str]:
    return list(set(re.findall(r"CVE-\d{4}-\d{4,}", text)))


def _parse_rfc822_date(date_str: str) -> str:
    """Parse RSS pub date to ISO 8601 string. Returns empty string on failure."""
    if not date_str:
        return ""
    # Try multiple formats
    formats = [
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S %Z",
        "%a, %d %b %Y %H:%M:%S",
    ]
    date_str = date_str.strip()
    # Normalize timezone abbreviations
    date_str = re.sub(r'\s+GMT$', ' +0000', date_str)
    date_str = re.sub(r'\s+UT$', ' +0000', date_str)
    for fmt in formats:
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.isoformat()
        except ValueError:
            continue
    return date_str  # Return as-is if unparseable


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


# ---------------------------------------------------------------------------
# Feed parsers
# ---------------------------------------------------------------------------

def _fetch_cisa_kev() -> List[Dict]:
    """CISA Known Exploited Vulnerabilities catalog (JSON)."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    data = _fetch_url(url, timeout=15.0)
    if not data:
        return []
    try:
        catalog = json.loads(data)
    except Exception:
        return []

    items = []
    for vuln in catalog.get("vulnerabilities", [])[:30]:
        cve_id = vuln.get("cveID", "")
        date_added = vuln.get("dateAdded", "")
        product = vuln.get("product", "")
        vendor = vuln.get("vendorProject", "")
        vuln_name = vuln.get("vulnerabilityName", "")
        description = vuln.get("shortDescription", "")
        due_date = vuln.get("dueDate", "")
        items.append({
            "id": f"cisa-{cve_id}",
            "title": f"[CISA KEV] {cve_id} – {vuln_name}",
            "source": "CISA KEV",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "severity": "critical",  # All CISA KEV are actively exploited
            "published_at": date_added,
            "summary": f"{vendor} {product}: {description} (Remediation due: {due_date})",
            "cve_ids": [cve_id] if cve_id else [],
        })
    return items


def _fetch_nvd_recent() -> List[Dict]:
    """NVD recent CVEs sorted by publish date."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=15"
    data = _fetch_url(url, timeout=15.0)
    if not data:
        return []
    try:
        payload = json.loads(data)
    except Exception:
        return []

    items = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        published = cve.get("published", "")
        descs = cve.get("descriptions", [])
        summary = next((d["value"] for d in descs if d.get("lang") == "en"), "")[:400]

        # CVSS
        cvss = 0.0
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss = float(metrics[key][0].get("cvssData", {}).get("baseScore", 0.0))
                break

        items.append({
            "id": f"nvd-{cve_id}",
            "title": f"{cve_id} (CVSS {cvss:.1f})",
            "source": "NVD",
            "url": f"https://nvd.nist.gov/vuln/detail/{urllib.parse.quote(cve_id, safe='')}",
            "severity": _severity_from_cvss(cvss),
            "published_at": published[:10] if published else "",
            "summary": summary,
            "cve_ids": [cve_id],
        })
    return items


def _fetch_rss(url: str, source_name: str, max_items: int = 15) -> List[Dict]:
    """Generic RSS 2.0 parser."""
    data = _fetch_url(url, timeout=10.0)
    if not data:
        return []
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        logger.warning("RSS parse error for %s: %s", url, exc)
        return []

    items = []
    ns = ""
    # Handle Atom or RSS
    channel = root.find("channel")
    entries = []
    if channel is not None:
        entries = channel.findall("item")
    else:
        # Atom feed
        ns = "{http://www.w3.org/2005/Atom}"
        entries = root.findall(f"{ns}entry")

    for entry in entries[:max_items]:
        if ns:
            title = (entry.findtext(f"{ns}title") or "").strip()
            link = (entry.findtext(f"{ns}link") or "")
            if not link:
                link_elem = entry.find(f"{ns}link")
                link = link_elem.get("href", "") if link_elem is not None else ""
            pub = entry.findtext(f"{ns}published") or entry.findtext(f"{ns}updated") or ""
            summary = (entry.findtext(f"{ns}summary") or entry.findtext(f"{ns}content") or "").strip()
        else:
            title = (entry.findtext("title") or "").strip()
            link = (entry.findtext("link") or "").strip()
            pub = entry.findtext("pubDate") or ""
            desc_elem = entry.find("description")
            summary = (desc_elem.text or "").strip() if desc_elem is not None else ""
            pub = _parse_rfc822_date(pub)

        # Strip HTML tags from summary
        summary = re.sub(r'<[^>]+>', '', summary)[:400]

        cve_ids = _extract_cves(title + " " + summary)

        # Guess severity from title keywords
        title_lower = title.lower()
        if any(w in title_lower for w in ("critical", "rce", "zero-day", "0day", "actively exploited")):
            severity = "critical"
        elif any(w in title_lower for w in ("high", "ransomware", "exploit", "backdoor", "malware")):
            severity = "high"
        elif any(w in title_lower for w in ("medium", "vulnerability", "cve", "patch")):
            severity = "medium"
        else:
            severity = "info"

        items.append({
            "id": f"{source_name.lower().replace(' ', '-')}-{hash(title) & 0xFFFFFFFF}",
            "title": title,
            "source": source_name,
            "url": _safe_url(link),
            "severity": severity,
            "published_at": pub[:10] if pub else "",
            "summary": summary,
            "cve_ids": cve_ids,
        })
    return items


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

FEEDS = [
    ("cisa_kev",    _fetch_cisa_kev,   {}),
    ("nvd_recent",  _fetch_nvd_recent, {}),
    ("cloudflare",  _fetch_rss,        {"url": "https://blog.cloudflare.com/tag/security/rss/", "source_name": "Cloudflare Blog"}),
    ("sans",        _fetch_rss,        {"url": "https://isc.sans.edu/rssfeed_full.xml", "source_name": "SANS ISC"}),
    ("bleeping",    _fetch_rss,        {"url": "https://www.bleepingcomputer.com/feed/", "source_name": "BleepingComputer"}),
]


def fetch_all_feeds() -> List[Dict]:
    """
    Fetch all threat intelligence feeds concurrently.
    Updates the in-memory cache and returns the combined list.
    """
    logger.info("Refreshing threat intelligence feeds...")
    all_items: List[Dict] = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {}
        for name, fn, kwargs in FEEDS:
            futures[executor.submit(fn, **kwargs)] = name

        for future in as_completed(futures, timeout=30):
            feed_name = futures[future]
            try:
                items = future.result()
                logger.debug("Feed '%s' returned %d items", feed_name, len(items))
                all_items.extend(items)
            except Exception as exc:
                logger.warning("Feed '%s' failed: %s", feed_name, exc)

    _set_cache(all_items)
    logger.info("Threat feeds refreshed: %d total items", len(all_items))
    return all_items


def get_feed(limit: int = 50, source: str = "all", cve_filter: Optional[str] = None) -> List[Dict]:
    """
    Return feed items from cache. Triggers refresh if cache is stale.
    """
    if is_stale():
        try:
            fetch_all_feeds()
        except Exception as exc:
            logger.warning("Background feed refresh failed: %s", exc)

    items = get_cached_feed()

    if source and source != "all":
        items = [i for i in items if i.get("source", "").lower() == source.lower()]

    if cve_filter:
        cves = [c.strip().upper() for c in cve_filter.split(",") if c.strip()]
        items = [i for i in items if any(c in i.get("cve_ids", []) for c in cves)]

    return items[:limit]
