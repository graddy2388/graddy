"""
viridis.checks.software_inventory – Non-invasive software detection and CVE enrichment.

Detection methods (passive / single-packet only):
  1. nmap service banners already captured in scan metadata (zero new probes)
  2. HTTP response headers (Server, X-Powered-By, X-AspNet-Version, etc.)
  3. SSH banner grab (single TCP connect, read banner, close) — only if port 22 open

CVE enrichment via viridis.cve_lookup (NVD + OSV.dev, cached 1h).
"""
from __future__ import annotations

import logging
import re
import socket
from typing import Dict, List, Optional, Tuple

from .base import BaseCheck, CheckResult, Finding, Severity
from ..cve_lookup import lookup_cves

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_version(banner: str) -> Tuple[str, str]:
    """
    Extract (product, version) from a banner string like 'Apache httpd 2.4.51'.
    Returns ('', '') if nothing useful found.
    """
    banner = banner.strip()
    if not banner:
        return "", ""

    # Common pattern: "ProductName/version" e.g. nginx/1.24.0, OpenSSH_8.9p1
    m = re.match(r'^([A-Za-z][\w\-\.]+)[/_]v?([\d][\d\.\-\_p]+)', banner)
    if m:
        return m.group(1), m.group(2)

    # "Product version" e.g. "Apache httpd 2.4.51"
    m = re.match(r'^([\w][\w\s\-]+?)\s+v?([\d]+\.[\d][\d\.\-p]*)', banner)
    if m:
        product = m.group(1).strip()
        version = m.group(2).strip()
        return product, version

    # Just return the first word as product, no version
    parts = banner.split()
    return parts[0] if parts else banner, ""


def _grab_ssh_banner(ip: str, port: int = 22, timeout: float = 3.0) -> str:
    """Connect to SSH port and read the banner line. Non-intrusive."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        banner = s.recv(256).decode("utf-8", errors="replace").strip()
        s.close()
        return banner
    except Exception:
        return ""


def _severity_for_cves(cves: List[Dict]) -> Severity:
    if not cves:
        return Severity.INFO
    max_cvss = max((c.get("cvss", 0.0) for c in cves), default=0.0)
    if max_cvss >= 9.0:
        return Severity.CRITICAL
    if max_cvss >= 7.0:
        return Severity.HIGH
    if max_cvss >= 4.0:
        return Severity.MEDIUM
    if max_cvss > 0:
        return Severity.LOW
    return Severity.INFO


# ---------------------------------------------------------------------------
# Check
# ---------------------------------------------------------------------------

class SoftwareInventoryCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "software_inventory"

    def run(self, target: dict) -> CheckResult:
        host = target["host"]
        # Software inventory enriches data from prior scan results — it needs
        # the nmap metadata to be passed in via target["scan_metadata"]
        scan_metadata: Dict = target.get("scan_metadata", {})
        findings: List[Finding] = []
        software_items: List[Dict] = []

        # --- Method 1: nmap service banners from prior scan ---
        services: Dict = scan_metadata.get("services", {})
        open_ports: List[int] = scan_metadata.get("open_ports", [])

        for port_str, svc in services.items():
            port = int(port_str)
            product = svc.get("product", "").strip()
            version = svc.get("version", "").strip()
            banner = svc.get("banner", "").strip()

            if not product and banner:
                product, version = _parse_version(banner)

            if not product:
                continue

            cves = lookup_cves(product, version) if product else []
            item = {
                "name": product,
                "version": version or "unknown",
                "source": "nmap",
                "port": port,
                "cves": cves,
            }
            software_items.append(item)

            if cves:
                sev = _severity_for_cves(cves)
                cve_ids = [c["id"] for c in cves[:5]]
                findings.append(Finding(
                    title=f"{product} {version} — {len(cves)} CVE(s) found",
                    severity=sev,
                    description=f"Software '{product} {version}' on port {port} has {len(cves)} known CVE(s). "
                                f"Top: {', '.join(cve_ids[:3])}",
                    recommendation=f"Update {product} to latest version. Review: {', '.join(cve_ids[:3])}",
                    details={"product": product, "version": version, "port": port, "cves": cves[:5]},
                ))

        # --- Method 2: SSH banner ---
        if 22 in open_ports:
            ssh_banner = _grab_ssh_banner(host, 22, timeout=3.0)
            if ssh_banner:
                # e.g. "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
                product, version = _parse_version(ssh_banner.lstrip("SSH-2.0-").lstrip("SSH-1.99-"))
                if not product:
                    product, version = _parse_version(ssh_banner)
                if product:
                    cves = lookup_cves(product, version)
                    item = {
                        "name": product,
                        "version": version or "unknown",
                        "source": "ssh_banner",
                        "port": 22,
                        "cves": cves,
                    }
                    software_items.append(item)

                    if cves:
                        sev = _severity_for_cves(cves)
                        cve_ids = [c["id"] for c in cves[:5]]
                        findings.append(Finding(
                            title=f"{product} {version} — {len(cves)} CVE(s) found (SSH banner)",
                            severity=sev,
                            description=f"SSH service on {host}:22 identifies as '{product} {version}'. "
                                        f"{len(cves)} CVE(s): {', '.join(cve_ids[:3])}",
                            recommendation=f"Update {product}. Review: {', '.join(cve_ids[:3])}",
                            details={"product": product, "version": version, "port": 22, "cves": cves[:5]},
                        ))

        # --- Method 3: HTTP headers from scan_metadata ---
        http_headers: Dict = scan_metadata.get("http_headers", {})
        header_checks = [
            ("Server", "http_header"),
            ("X-Powered-By", "http_header"),
            ("X-AspNet-Version", "http_header"),
            ("X-Runtime", "http_header"),
        ]
        for header, src in header_checks:
            value = http_headers.get(header, "").strip()
            if value:
                product, version = _parse_version(value)
                if product:
                    cves = lookup_cves(product, version)
                    item = {
                        "name": product,
                        "version": version or "unknown",
                        "source": src,
                        "port": 0,
                        "cves": cves,
                    }
                    software_items.append(item)

        if not software_items:
            findings.append(Finding(
                title="No software fingerprints collected",
                severity=Severity.INFO,
                description="No service banners or headers were available for software identification.",
                recommendation="Run an nmap scan first to collect service version data.",
                details={},
            ))

        passed = not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)

        return CheckResult(
            check_name=self.name,
            target=host,
            passed=passed,
            findings=findings,
            metadata={
                "software": software_items,
                "total_items": len(software_items),
                "items_with_cves": sum(1 for s in software_items if s.get("cves")),
            },
        )
