"""
viridis.checks.masscan_check – Masscan high-speed port scanner.

Falls back gracefully when masscan is not installed.
"""
from __future__ import annotations

import logging
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from .base import BaseCheck, CheckResult, Finding, Severity
from .nmap_scan import DANGEROUS_PORTS

logger = logging.getLogger(__name__)


class MasscanCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "masscan"

    def run(self, target: dict) -> CheckResult:
        import shutil
        host = target["host"]

        if shutil.which("masscan") is None:
            return CheckResult(
                check_name=self.name, target=host, passed=True,
                error="masscan not installed",
                findings=[Finding(
                    title="masscan binary not found",
                    severity=Severity.INFO,
                    description="masscan is not installed on this system.",
                    recommendation="Install masscan: apt install masscan",
                )],
            )

        rate = str(self.config.get("masscan", {}).get("rate", 1000))
        timeout = int(self.config.get("masscan", {}).get("timeout", 180))

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
            output_file = f.name

        cmd = [
            "masscan", host,
            "--ports", "0-65535",
            "--rate", rate,
            "-oX", output_file,
        ]
        logger.info("Running masscan: %s", " ".join(cmd))

        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return CheckResult(check_name=self.name, target=host, passed=False,
                               error=f"masscan timed out after {timeout}s")
        except Exception as exc:
            return CheckResult(check_name=self.name, target=host, passed=False,
                               error=str(exc))

        open_ports: list[int] = []
        try:
            with open(output_file) as fh:
                xml_text = fh.read()
            root = ET.fromstring(xml_text)
            for host_elem in root.findall("host"):
                for port_elem in host_elem.findall(".//port"):
                    state = port_elem.find("state")
                    if state is not None and state.get("state") == "open":
                        portid = int(port_elem.get("portid", 0))
                        if portid:
                            open_ports.append(portid)
        except Exception:
            pass
        finally:
            try:
                os.unlink(output_file)
            except OSError:
                pass

        findings: list[Finding] = []

        if open_ports:
            findings.append(Finding(
                title=f"Masscan found {len(open_ports)} open port(s)",
                severity=Severity.INFO,
                description=(
                    f"Full port sweep (0-65535) of {host} found {len(open_ports)} open ports: "
                    f"{sorted(open_ports)[:30]}"
                ),
                recommendation="Review all open ports and disable unnecessary services.",
                details={"open_ports": sorted(open_ports)},
            ))
            for port in open_ports:
                if port in DANGEROUS_PORTS:
                    sev, title, rec = DANGEROUS_PORTS[port]
                    findings.append(Finding(
                        title=title, severity=sev,
                        description=f"Port {port} is open on {host}. {title}",
                        recommendation=rec,
                        details={"port": port},
                    ))
        else:
            findings.append(Finding(
                title="No open ports found by masscan",
                severity=Severity.INFO,
                description="masscan found no open ports across the full range 0-65535.",
                recommendation=(
                    "Verify the target is reachable. Note: masscan may require root privileges."
                ),
            ))

        passed = not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
        return CheckResult(
            check_name=self.name, target=host, passed=passed,
            findings=findings,
            metadata={"open_ports": sorted(open_ports)},
        )
