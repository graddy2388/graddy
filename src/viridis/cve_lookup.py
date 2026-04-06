"""
viridis.cve_lookup – CVE enrichment for discovered software.

Queries OSV.dev (primary) and NVD (fallback) to find known vulnerabilities
for a given product name and version string.

All results are cached in-memory for 1 hour to avoid hammering public APIs.
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
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Simple in-memory TTL cache
# ---------------------------------------------------------------------------

_CACHE: Dict[str, Tuple[float, List[Dict]]] = {}
_CACHE_LOCK = threading.Lock()
_TTL = 3600  # 1 hour
_MAX_CACHE_ENTRIES = 512   # prevent unbounded memory growth
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MB per API response

# CVE ID must match exactly CVE-YYYY-NNNNN (no arbitrary chars)
_CVE_ID_RE = re.compile(r'^CVE-\d{4}-\d{4,}$')


def _version_tuple(v: str) -> tuple:
    """Convert a version string to a comparable int tuple.
    '2.4.51' -> (2, 4, 51);  '8.9p1' -> (8, 9);  '' -> ().
    """
    if not v:
        return ()
    parts = []
    for seg in re.split(r'[.\-_]', v):
        m = re.match(r'^(\d+)', seg)
        if m:
            parts.append(int(m.group(1)))
    return tuple(parts) if parts else ()


def _version_in_range(version: str, cpe_match: dict) -> bool:
    """Return True if *version* falls within the affected range of one cpeMatch entry."""
    v = _version_tuple(version)
    if not v:
        return True  # can't filter without a parsed version; assume affected
    vsi = cpe_match.get("versionStartIncluding", "")
    vse = cpe_match.get("versionStartExcluding", "")
    vei = cpe_match.get("versionEndIncluding", "")
    vee = cpe_match.get("versionEndExcluding", "")
    if not any([vsi, vse, vei, vee]):
        return True  # no bounds → exact CPE match, treat as affected
    low_ok = True
    if vsi:
        low_ok = v >= _version_tuple(vsi)
    elif vse:
        low_ok = v > _version_tuple(vse)
    high_ok = True
    if vei:
        high_ok = v <= _version_tuple(vei)
    elif vee:
        high_ok = v < _version_tuple(vee)
    return low_ok and high_ok


def _cve_affects_version(cve: dict, version: str) -> bool:
    """Return True if the CVE's configurations indicate *version* is affected.
    Returns True (keep the CVE) when configurations are absent — some CVEs omit this field.
    """
    configurations = cve.get("configurations", [])
    if not configurations:
        return True
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", True):
                    continue
                if _version_in_range(version, cpe_match):
                    return True
    return False


def _cache_get(key: str) -> Optional[List[Dict]]:
    with _CACHE_LOCK:
        entry = _CACHE.get(key)
        if entry and time.time() - entry[0] < _TTL:
            return entry[1]
        if entry:
            del _CACHE[key]
        return None


def _cache_set(key: str, value: List[Dict]) -> None:
    with _CACHE_LOCK:
        # Evict oldest entries when cache is full (simple FIFO eviction)
        if len(_CACHE) >= _MAX_CACHE_ENTRIES:
            oldest = sorted(_CACHE, key=lambda k: _CACHE[k][0])
            for evict_key in oldest[: len(_CACHE) - _MAX_CACHE_ENTRIES + 1]:
                del _CACHE[evict_key]
        _CACHE[key] = (time.time(), value)


# ---------------------------------------------------------------------------
# NVD lookup (primary for product/version combos)
# ---------------------------------------------------------------------------

def _nvd_lookup(product: str, version: str, timeout: float = 5.0) -> List[Dict]:
    """Query NVD CVE 2.0 API by keyword search."""
    keyword = f"{product} {version}".strip()
    if not keyword:
        return []
    params = urllib.parse.urlencode({
        "keywordSearch": keyword,
        "resultsPerPage": 10,
    })
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Viridis/2.0 Security Scanner"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read(_MAX_RESPONSE_BYTES))
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = str(cve.get("id", ""))
            # Validate CVE ID format before using it in a URL
            if not _CVE_ID_RE.match(cve_id):
                continue
            # CVSS score
            cvss = 0.0
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    try:
                        cvss = float(metrics[key][0].get("cvssData", {}).get("baseScore", 0.0))
                    except (TypeError, ValueError):
                        cvss = 0.0
                    break
            # Summary
            descs = cve.get("descriptions", [])
            summary = next((d["value"] for d in descs if d.get("lang") == "en"), "")[:500]
            # Filter out CVEs whose version ranges don't include the detected version
            if version and not _cve_affects_version(cve, version):
                logger.debug("NVD: skipping %s — version %s not in affected range", cve_id, version)
                continue
            results.append({
                "id": cve_id,
                "cvss": cvss,
                "summary": summary,
                "source": "nvd",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
        return results
    except Exception as exc:
        logger.debug("NVD lookup failed for '%s %s': %s", product, version, exc)
        return []


# ---------------------------------------------------------------------------
# OSV.dev lookup (good for open-source packages)
# ---------------------------------------------------------------------------

def _osv_lookup(product: str, version: str, timeout: float = 5.0) -> List[Dict]:
    """Query OSV.dev API for vulnerabilities affecting a package version."""
    if not product or not version:
        return []
    payload = json.dumps({"version": version, "package": {"name": product}}).encode()
    url = "https://api.osv.dev/v1/query"
    try:
        req = urllib.request.Request(
            url,
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "Viridis/2.0 Security Scanner"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read(_MAX_RESPONSE_BYTES))
        results = []
        for vuln in data.get("vulns", []):
            vuln_id = str(vuln.get("id", ""))
            # Extract CVE aliases; validate each against CVE pattern
            aliases = vuln.get("aliases", [])
            cve_ids = [a for a in aliases if isinstance(a, str) and _CVE_ID_RE.match(a)]
            primary_id = cve_ids[0] if cve_ids else vuln_id
            if not primary_id:
                continue
            summary = str(vuln.get("summary", ""))[:500]
            cvss = 0.0
            results.append({
                "id": primary_id,
                "cvss": cvss,
                "summary": summary,
                "source": "osv",
                "url": f"https://osv.dev/vulnerability/{urllib.parse.quote(vuln_id, safe='')}",
            })
        return results
    except Exception as exc:
        logger.debug("OSV lookup failed for '%s %s': %s", product, version, exc)
        return []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lookup_cves(product: str, version: str) -> List[Dict]:
    """
    Return list of CVE dicts for the given product/version.

    Each dict: {id, cvss, summary, source, url}
    Results are cached for 1 hour.
    """
    if not product:
        return []

    key = f"{product.lower().strip()}:{version.lower().strip()}"
    cached = _cache_get(key)
    if cached is not None:
        return cached

    # Try NVD first (broader coverage for binary/system software)
    results = _nvd_lookup(product, version)

    # Supplement with OSV for open-source packages (deduplicate by CVE ID)
    if version:
        osv_results = _osv_lookup(product, version)
        existing_ids = {r["id"] for r in results}
        for r in osv_results:
            if r["id"] not in existing_ids:
                results.append(r)
                existing_ids.add(r["id"])

    # Sort by CVSS descending
    results.sort(key=lambda x: x.get("cvss", 0.0), reverse=True)
    # Limit to top 10 per product
    results = results[:10]

    _cache_set(key, results)
    return results
