"""
viridis.checks.subnet_scan – Subnet / CIDR ping sweep and host discovery.

Accepts a CIDR range (e.g., 192.168.1.0/24) as the target "host" field.
1. Runs nmap -sn (ping sweep) to find live hosts
2. Optionally runs a quick nmap port scan on each live host
3. Stores discovered hosts in the host_inventory table
"""
from __future__ import annotations

import ipaddress
import logging
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from .base import BaseCheck, CheckResult, Finding, Severity
from .nmap_scan import _parse_nmap_xml

logger = logging.getLogger(__name__)


def _nmap_ping_sweep(cidr: str, timeout: int = 120) -> List[Dict]:
    """Return list of {ip, hostname, mac} dicts for live hosts."""
    if shutil.which("nmap") is None:
        return _socket_ping_sweep(cidr)

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        output_file = f.name

    cmd = ["nmap", "-sn", "-T4", "--open", "-oX", output_file, cidr]
    logger.info("Subnet ping sweep: %s", " ".join(cmd))
    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
        with open(output_file) as fh:
            xml_text = fh.read()
        return _parse_ping_sweep_xml(xml_text)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.warning("nmap ping sweep failed: %s", exc)
        return _socket_ping_sweep(cidr)
    finally:
        import os
        try:
            os.unlink(output_file)
        except OSError:
            pass


def _parse_ping_sweep_xml(xml_text: str) -> List[Dict]:
    """Parse nmap ping sweep XML into list of host dicts."""
    hosts = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts

    for host_elem in root.findall("host"):
        status = host_elem.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = ""
        mac = ""
        hostname = ""

        for addr in host_elem.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr", "")

        for hn in host_elem.findall(".//hostname"):
            hostname = hn.get("name", "")
            break

        if ip:
            hosts.append({"ip": ip, "hostname": hostname, "mac": mac})

    return hosts


def _socket_ping_sweep(cidr: str) -> List[Dict]:
    """
    Fallback: attempt socket connection on port 80 or ICMP if nmap unavailable.
    This is a very lightweight check – only tests TCP/80 reachability.
    """
    import socket
    hosts = []
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return hosts

    # Limit scan to /24 or smaller without nmap to avoid excessive runtime
    if network.prefixlen < 24:
        logger.warning("Socket fallback: limiting subnet scan to /24 subnet")
        return hosts

    for ip in network.hosts():
        ip_str = str(ip)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip_str, 80))
            sock.close()
            if result == 0:
                try:
                    from ...hostname_resolver import resolve_hostname
                    hn = resolve_hostname(ip_str, timeout=1.0)
                except Exception:
                    hn = ""
                hosts.append({"ip": ip_str, "hostname": hn, "mac": ""})
        except OSError:
            pass

    return hosts


def _quick_port_scan(ip: str, timeout: int = 60) -> Dict:
    """Run a quick nmap scan on a single host; return parsed result."""
    if shutil.which("nmap") is None:
        return {"open_ports": [], "services": {}, "os_guesses": []}

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        output_file = f.name

    cmd = ["nmap", "-sV", "--top-ports", "100", "-T4", "-oX", output_file, ip]
    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
        with open(output_file) as fh:
            xml_text = fh.read()
        return _parse_nmap_xml(xml_text)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return {"open_ports": [], "services": {}, "os_guesses": []}
    finally:
        import os
        try:
            os.unlink(output_file)
        except OSError:
            pass


class SubnetScanCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "subnet_scan"

    def run(self, target: dict) -> CheckResult:
        cidr = target["host"]

        # Validate CIDR
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return CheckResult(
                check_name=self.name,
                target=cidr,
                passed=False,
                error=f"Invalid CIDR/IP: {cidr}",
            )

        timeout_sweep = int(self.config.get("subnet_scan", {}).get("sweep_timeout", 120))
        do_port_scan = bool(self.config.get("subnet_scan", {}).get("port_scan", True))

        logger.info("Starting subnet scan of %s", cidr)
        live_hosts = _nmap_ping_sweep(cidr, timeout=timeout_sweep)

        findings: List[Finding] = []

        if not live_hosts:
            findings.append(Finding(
                title=f"No live hosts found in {cidr}",
                severity=Severity.INFO,
                description="Ping sweep returned no active hosts.",
                recommendation="Verify the subnet range and network connectivity.",
                details={"cidr": cidr},
            ))
        else:
            findings.append(Finding(
                title=f"Discovered {len(live_hosts)} live host(s) in {cidr}",
                severity=Severity.INFO,
                description=f"Ping sweep of {cidr} found {len(live_hosts)} active host(s).",
                recommendation="Review discovered hosts and ensure all are expected/authorized.",
                details={"hosts": live_hosts, "cidr": cidr},
            ))

        host_details = []
        for h in live_hosts:
            ip = h["ip"]
            port_data = {}
            if do_port_scan:
                port_scan_timeout = int(self.config.get("subnet_scan", {}).get("port_timeout", 60))
                port_data = _quick_port_scan(ip, timeout=port_scan_timeout)

            entry = {
                "ip": ip,
                "hostname": h.get("hostname", ""),
                "mac": h.get("mac", ""),
                "open_ports": port_data.get("open_ports", []),
                "services": port_data.get("services", {}),
                "os_guess": "",
            }
            if port_data.get("os_guesses"):
                best = max(port_data["os_guesses"], key=lambda x: x.get("accuracy", 0))
                entry["os_guess"] = best.get("name", "")

            host_details.append(entry)

            # Flag interesting open ports
            for port in port_data.get("open_ports", []):
                from .nmap_scan import DANGEROUS_PORTS
                if port in DANGEROUS_PORTS:
                    sev, title, rec = DANGEROUS_PORTS[port]
                    findings.append(Finding(
                        title=f"{ip}: {title}",
                        severity=sev,
                        description=f"Discovered host {ip} ({h.get('hostname', '')}) has port {port} open. {title}",
                        recommendation=rec,
                        details={"ip": ip, "port": port},
                    ))

        passed = not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)

        return CheckResult(
            check_name=self.name,
            target=cidr,
            passed=passed,
            findings=findings,
            metadata={
                "cidr": cidr,
                "live_host_count": len(live_hosts),
                "hosts": host_details,
            },
        )
