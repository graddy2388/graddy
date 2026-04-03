"""
viridis.checks.nmap_scan – nmap-powered port and service enumeration check.

Requires nmap to be installed on the system (available in the Docker image).
Falls back gracefully if nmap is not available.
"""
from __future__ import annotations

import logging
import re
import shlex
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

from ..web.validation import validate_nmap_args
from .base import BaseCheck, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)

# Ports that warrant higher severity findings
DANGEROUS_PORTS: Dict[int, Tuple[Severity, str, str]] = {
    23: (Severity.CRITICAL, "Telnet service exposed", "Replace Telnet with SSH immediately."),
    21: (Severity.HIGH, "FTP service exposed", "Use SFTP/FTPS instead of plain FTP."),
    3389: (Severity.HIGH, "RDP exposed", "Restrict RDP access behind VPN or firewall."),
    445: (Severity.HIGH, "SMB exposed", "Block port 445 at perimeter; patch EternalBlue."),
    135: (Severity.HIGH, "Windows RPC exposed", "Block MSRPC at perimeter firewall."),
    139: (Severity.MEDIUM, "NetBIOS exposed", "Disable NetBIOS if not required."),
    3306: (Severity.MEDIUM, "MySQL exposed", "Bind database to localhost; use firewall rules."),
    5432: (Severity.MEDIUM, "PostgreSQL exposed", "Bind database to localhost; use firewall rules."),
    6379: (Severity.HIGH, "Redis exposed (no auth by default)", "Enable Redis auth; bind to private net."),
    27017: (Severity.HIGH, "MongoDB exposed (no auth by default)", "Enable MongoDB auth; restrict access."),
    9200: (Severity.HIGH, "Elasticsearch exposed (no auth by default)", "Enable ES security; restrict access."),
    11211: (Severity.MEDIUM, "Memcached exposed", "Bind Memcached to localhost only."),
    2181: (Severity.HIGH, "ZooKeeper exposed", "Restrict ZooKeeper to private network."),
    4848: (Severity.HIGH, "GlassFish admin console exposed", "Restrict admin console to localhost."),
    8080: (Severity.LOW, "HTTP alternate port exposed", "Verify this is intentional."),
    8443: (Severity.LOW, "HTTPS alternate port exposed", "Verify this is intentional."),
}


def _nmap_available() -> bool:
    return shutil.which("nmap") is not None


def _run_nmap(host: str, nmap_args: str, timeout: int = 120) -> Optional[str]:
    """Run nmap and return XML output, or None on failure."""
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        output_file = f.name

    extra = shlex.split(nmap_args, posix=True) if nmap_args.strip() else []
    cmd = ["nmap"] + extra + ["-oX", output_file, host]
    logger.info("Running nmap: %s", " ".join(cmd))
    try:
        subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        with open(output_file) as fh:
            return fh.read()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.warning("nmap failed for %s: %s", host, exc)
        return None
    finally:
        import os
        try:
            os.unlink(output_file)
        except OSError:
            pass


def _parse_nmap_xml(xml_text: str) -> Dict:
    """Parse nmap XML output into a structured dict."""
    result: Dict = {
        "hosts": [],
        "hostname": "",
        "os_guesses": [],
        "open_ports": [],
        "services": {},
        "scripts": {},
        "vulnerabilities": [],
    }
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.warning("Failed to parse nmap XML: %s", exc)
        return result

    for host_elem in root.findall("host"):
        status = host_elem.find("status")
        if status is not None and status.get("state") != "up":
            continue

        # Addresses
        for addr in host_elem.findall("address"):
            if addr.get("addrtype") == "ipv4":
                result["hosts"].append(addr.get("addr", ""))

        # Hostname (PTR / user record from nmap's own DNS resolution)
        if not result["hostname"]:
            for hn in host_elem.findall(".//hostname"):
                name = hn.get("name", "").strip()
                if name:
                    result["hostname"] = name
                    break

        # OS detection
        for os_elem in host_elem.findall(".//osmatch"):
            name = os_elem.get("name", "")
            accuracy = os_elem.get("accuracy", "0")
            result["os_guesses"].append({"name": name, "accuracy": int(accuracy)})

        # Ports
        for port_elem in host_elem.findall(".//port"):
            state = port_elem.find("state")
            if state is None or state.get("state") != "open":
                continue

            portid = int(port_elem.get("portid", 0))
            protocol = port_elem.get("protocol", "tcp")
            service = port_elem.find("service")
            svc_name = ""
            svc_product = ""
            svc_version = ""
            svc_extra = ""
            if service is not None:
                svc_name = service.get("name", "")
                svc_product = service.get("product", "")
                svc_version = service.get("version", "")
                svc_extra = service.get("extrainfo", "")

            result["open_ports"].append(portid)
            result["services"][portid] = {
                "protocol": protocol,
                "name": svc_name,
                "product": svc_product,
                "version": svc_version,
                "extra": svc_extra,
                "banner": f"{svc_product} {svc_version} {svc_extra}".strip(),
            }

            # Script output (NSE)
            for script in port_elem.findall("script"):
                script_id = script.get("id", "")
                script_out = script.get("output", "")
                result["scripts"].setdefault(portid, {})[script_id] = script_out

                # Detect vuln scripts
                if "vuln" in script_id.lower() or "CVE" in script_out:
                    cves = re.findall(r"CVE-\d{4}-\d+", script_out)
                    result["vulnerabilities"].append({
                        "port": portid,
                        "script": script_id,
                        "output": script_out[:500],
                        "cves": cves,
                    })

    return result


class NmapScanCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "nmap"

    def run(self, target: dict) -> CheckResult:
        host = target["host"]

        if not _nmap_available():
            return CheckResult(
                check_name=self.name,
                target=host,
                passed=True,
                findings=[],
                metadata={"skipped": "nmap not installed"},
                error="nmap binary not found – install nmap in the container",
            )

        raw_args = target.get("nmap_args") or self.config.get("nmap", {}).get("args", "-sV -sC --top-ports 1000 -T4")
        try:
            nmap_args = validate_nmap_args(str(raw_args))
        except ValueError as exc:
            return CheckResult(
                check_name=self.name,
                target=host,
                passed=False,
                error=f"Invalid nmap arguments: {exc}",
            )
        timeout = int(self.config.get("nmap", {}).get("timeout", 180))

        xml_out = _run_nmap(host, nmap_args, timeout=timeout)
        if not xml_out:
            return CheckResult(
                check_name=self.name,
                target=host,
                passed=False,
                error="nmap returned no output",
            )

        parsed = _parse_nmap_xml(xml_out)
        findings: List[Finding] = []

        # OS info finding
        if parsed["os_guesses"]:
            best = max(parsed["os_guesses"], key=lambda x: x["accuracy"])
            findings.append(Finding(
                title=f"OS detected: {best['name']} ({best['accuracy']}% confidence)",
                severity=Severity.INFO,
                description=f"nmap OS detection identified {best['name']} with {best['accuracy']}% confidence.",
                recommendation="Verify OS is up to date and patched.",
                details={"os_guesses": parsed["os_guesses"]},
            ))

        # Per-port findings
        for port in sorted(parsed["open_ports"]):
            svc = parsed["services"].get(port, {})
            svc_label = svc.get("name") or "unknown"
            version_str = f"{svc.get('product', '')} {svc.get('version', '')}".strip()

            # Basic open port INFO
            findings.append(Finding(
                title=f"Open port {port}/{svc_label}",
                severity=Severity.INFO,
                description=f"Port {port} ({svc_label}) is open on {host}. {version_str}",
                recommendation="Verify this port should be publicly accessible.",
                details={"port": port, "service": svc},
            ))

            # Dangerous port severity
            if port in DANGEROUS_PORTS:
                sev, title, rec = DANGEROUS_PORTS[port]
                findings.append(Finding(
                    title=title,
                    severity=sev,
                    description=f"Port {port} ({svc_label}) is open on {host}. {title}",
                    recommendation=rec,
                    details={"port": port, "service": svc},
                ))

            # Version disclosure
            if version_str:
                findings.append(Finding(
                    title=f"Service version disclosed on port {port}",
                    severity=Severity.MEDIUM,
                    description=f"Service on port {port} exposes version: {version_str}",
                    recommendation="Suppress version banners in service configuration.",
                    details={"port": port, "version": version_str},
                ))

            # NSE script findings
            for script_id, script_out in parsed["scripts"].get(port, {}).items():
                if "VULNERABLE" in script_out or "vuln" in script_id:
                    cves = re.findall(r"CVE-\d{4}-\d+", script_out)
                    sev = Severity.CRITICAL if cves else Severity.HIGH
                    findings.append(Finding(
                        title=f"Vulnerability detected by {script_id} on port {port}",
                        severity=sev,
                        description=script_out[:1000],
                        recommendation="Apply vendor patches immediately. Check CVEs: " + ", ".join(cves) if cves else "Investigate and remediate.",
                        details={"port": port, "script": script_id, "cves": cves},
                    ))

        # Explicit vuln scan results
        for vuln in parsed["vulnerabilities"]:
            if not any(
                f.details.get("script") == vuln["script"] for f in findings
                if hasattr(f, "details") and isinstance(f.details, dict)
            ):
                findings.append(Finding(
                    title=f"NSE vuln script hit: {vuln['script']}",
                    severity=Severity.HIGH,
                    description=vuln["output"],
                    recommendation="Investigate and apply patches. CVEs: " + ", ".join(vuln["cves"]) if vuln["cves"] else "Investigate.",
                    details=vuln,
                ))

        passed = not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)

        return CheckResult(
            check_name=self.name,
            target=host,
            passed=passed,
            findings=findings,
            metadata={
                "open_ports": parsed["open_ports"],
                "services": parsed["services"],
                "os_guesses": parsed["os_guesses"],
                "nmap_args": nmap_args,
            },
        )
