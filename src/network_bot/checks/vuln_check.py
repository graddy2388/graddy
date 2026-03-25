import ftplib
import logging
import re
import socket
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseCheck, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)

# Vulnerability signature database
VULN_SIGNATURES: Dict[str, List[Dict[str, Any]]] = {
    "OpenSSH": [
        {
            "pattern": r"OpenSSH[_ ]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
            "check": lambda v: tuple(int(x) for x in v.split(".")[:2]) < (8, 5),
            "cve": "CVE-2023-38408",
            "severity": Severity.HIGH,
            "title": "OpenSSH < 8.5 - Multiple vulnerabilities",
            "recommendation": "Upgrade OpenSSH to 9.x or latest stable release.",
        },
    ],
    "Apache": [
        {
            "pattern": r"Apache/([0-9]+\.[0-9]+\.[0-9]+)",
            "check": lambda v: tuple(int(x) for x in v.split(".")[:3]) < (2, 4, 57),
            "cve": "CVE-2023-25690",
            "severity": Severity.HIGH,
            "title": "Apache HTTP Server < 2.4.57 - HTTP Request Splitting",
            "recommendation": "Upgrade Apache to 2.4.57 or later.",
        },
    ],
    "nginx": [
        {
            "pattern": r"nginx/([0-9]+\.[0-9]+\.[0-9]+)",
            "check": lambda v: tuple(int(x) for x in v.split(".")[:3]) < (1, 25, 0),
            "cve": "CVE-2022-41741",
            "severity": Severity.MEDIUM,
            "title": "nginx < 1.25.0 - Memory corruption vulnerability",
            "recommendation": "Upgrade nginx to 1.25.0 or later.",
        },
    ],
    "OpenSSL": [
        {
            "pattern": r"OpenSSL/([0-9]+\.[0-9]+\.[0-9]+[a-z]?)",
            "check": lambda v: v.startswith("1."),
            "cve": "CVE-2023-0286",
            "severity": Severity.HIGH,
            "title": "OpenSSL 1.x - Multiple critical vulnerabilities (EOL)",
            "recommendation": "Upgrade to OpenSSL 3.x immediately.",
        },
    ],
    "vsftpd": [
        {
            "pattern": r"vsftpd ([0-9]+\.[0-9]+\.[0-9]+)",
            "check": lambda v: tuple(int(x) for x in v.split(".")[:3]) <= (2, 3, 4),
            "cve": "CVE-2011-2523",
            "severity": Severity.CRITICAL,
            "title": "vsftpd 2.3.4 - Backdoor command execution",
            "recommendation": "Upgrade vsftpd immediately; version 2.3.4 contains a backdoor.",
        },
    ],
    "ProFTPD": [
        {
            "pattern": r"ProFTPD ([0-9]+\.[0-9]+\.[0-9]+)",
            "check": lambda v: tuple(int(x) for x in v.split(".")[:3]) < (1, 3, 8),
            "cve": "CVE-2023-51713",
            "severity": Severity.HIGH,
            "title": "ProFTPD < 1.3.8 - SQL injection vulnerability",
            "recommendation": "Upgrade ProFTPD to 1.3.8 or later.",
        },
    ],
    "Exim": [
        {
            "pattern": r"Exim ([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
            "check": lambda v: tuple(int(x) for x in (v.split(".")[:2] + ["0"])[:2]) < (4, 97),
            "cve": "CVE-2023-42115",
            "severity": Severity.CRITICAL,
            "title": "Exim < 4.97 - Remote code execution vulnerability",
            "recommendation": "Upgrade Exim to 4.97 or later.",
        },
    ],
}

# Default credential indicators in banners
DEFAULT_CRED_INDICATORS = [
    "default password",
    "admin/admin",
    "root/root",
    "test/test",
    "default credentials",
]

# Open proxy detection ports
PROXY_PORTS = {3128, 8080}


def _grab_banner(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """Attempt to grab a service banner from a port."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                if port in (80, 8080, 3128):
                    sock.sendall(
                        b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n"
                    )
                data = sock.recv(1024)
                banner = data.decode("utf-8", errors="replace").strip()
                return banner if banner else None
            except (socket.timeout, OSError):
                return None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def _check_vuln_signatures(banner: str, port: int, host: str) -> List[Finding]:
    """Check a banner against known vulnerability signatures."""
    findings: List[Finding] = []
    for service_name, signatures in VULN_SIGNATURES.items():
        for sig in signatures:
            match = re.search(sig["pattern"], banner, re.IGNORECASE)
            if match:
                version = match.group(1)
                try:
                    is_vulnerable = sig["check"](version)
                except (ValueError, IndexError, TypeError):
                    is_vulnerable = False

                if is_vulnerable:
                    findings.append(
                        Finding(
                            title=f"{sig['title']} (port {port})",
                            severity=sig["severity"],
                            description=(
                                f"Detected {service_name} version {version} on {host}:{port}. "
                                f"This version is affected by {sig['cve']}."
                            ),
                            recommendation=sig["recommendation"],
                            details={
                                "host": host,
                                "port": port,
                                "service": service_name,
                                "version": version,
                                "cve": sig["cve"],
                                "banner_excerpt": banner[:200],
                            },
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            title=f"{service_name} version {version} detected (port {port})",
                            severity=Severity.INFO,
                            description=(
                                f"Detected {service_name} version {version} on {host}:{port}. "
                                "No known critical vulnerabilities matched for this version."
                            ),
                            details={
                                "host": host,
                                "port": port,
                                "service": service_name,
                                "version": version,
                            },
                        )
                    )
    return findings


def _check_anonymous_ftp(host: str, port: int = 21, timeout: float = 5.0) -> Optional[Finding]:
    """Attempt anonymous FTP login."""
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=timeout)
        ftp.login("anonymous", "anonymous@example.com")
        # If we get here, anonymous login succeeded
        try:
            listing = ftp.nlst()[:10]
        except ftplib.error_perm:
            listing = []
        ftp.quit()
        return Finding(
            title="Anonymous FTP access allowed",
            severity=Severity.HIGH,
            description=(
                f"The FTP server on {host}:{port} allows anonymous login. "
                "This may expose sensitive files to unauthenticated users."
            ),
            recommendation=(
                "Disable anonymous FTP access unless explicitly required. "
                "If needed, restrict anonymous access to a read-only public directory."
            ),
            details={
                "host": host,
                "port": port,
                "sample_files": listing,
            },
        )
    except ftplib.error_perm:
        return None  # Anonymous login rejected
    except (ftplib.Error, OSError, socket.timeout, ConnectionRefusedError) as exc:
        logger.debug("Anonymous FTP check failed for %s:%d - %s", host, port, exc)
        return None


def _check_open_proxy(host: str, port: int, timeout: float = 5.0) -> Optional[Finding]:
    """Check if a port acts as an open HTTP proxy."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # Send CONNECT request to an external host
            request = b"CONNECT example.com:443 HTTP/1.0\r\n\r\n"
            sock.sendall(request)
            response = sock.recv(512).decode("utf-8", errors="replace")
            if "200" in response and "established" in response.lower():
                return Finding(
                    title=f"Open HTTP proxy detected on port {port}",
                    severity=Severity.HIGH,
                    description=(
                        f"Port {port} on {host} appears to be an open HTTP proxy. "
                        "Open proxies can be used to relay attacks and bypass access controls."
                    ),
                    recommendation=(
                        "Disable the proxy service if not needed, or restrict access to authorized users only. "
                        "Ensure the proxy requires authentication."
                    ),
                    details={"host": host, "port": port, "response_excerpt": response[:200]},
                )
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        logger.debug("Open proxy check failed for %s:%d - %s", host, port, exc)
    return None


class VulnCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "vuln"

    def run(self, target: dict) -> CheckResult:
        host = target["host"]
        ports: List[int] = target.get("ports", [])
        # Use banners from port scan metadata if available
        existing_banners: Dict[str, str] = target.get("metadata", {}).get("banners", {})

        findings: List[Finding] = []
        checked_banners: Dict[int, str] = {}

        # Collect banners: use cached ones or re-grab
        if not ports:
            from .port_scan import PORT_SERVICE_MAP
            ports = list(PORT_SERVICE_MAP.keys())

        for port in ports:
            banner = existing_banners.get(str(port))
            if not banner:
                banner = _grab_banner(host, port)
            if banner:
                checked_banners[port] = banner

        # Check banners against vulnerability signatures
        for port, banner in checked_banners.items():
            vuln_findings = _check_vuln_signatures(banner, port, host)
            findings.extend(vuln_findings)

            # Check for default credential indicators in banner
            banner_lower = banner.lower()
            for indicator in DEFAULT_CRED_INDICATORS:
                if indicator in banner_lower:
                    findings.append(
                        Finding(
                            title=f"Default credential indicator in banner (port {port})",
                            severity=Severity.CRITICAL,
                            description=(
                                f"The service banner on {host}:{port} contains a reference to default credentials: "
                                f"'{indicator}'. This strongly suggests the service is using default credentials."
                            ),
                            recommendation="Change all default credentials immediately.",
                            details={"host": host, "port": port, "indicator": indicator},
                        )
                    )

        # Anonymous FTP check
        if 21 in ports:
            anon_ftp = _check_anonymous_ftp(host, 21)
            if anon_ftp:
                findings.append(anon_ftp)
            else:
                findings.append(
                    Finding(
                        title="Anonymous FTP access denied",
                        severity=Severity.INFO,
                        description=f"Anonymous FTP login to {host}:21 was rejected.",
                    )
                )

        # Open proxy checks
        for proxy_port in PROXY_PORTS:
            if proxy_port in ports:
                proxy_finding = _check_open_proxy(host, proxy_port)
                if proxy_finding:
                    findings.append(proxy_finding)

        if not findings:
            findings.append(
                Finding(
                    title="No known vulnerabilities detected",
                    severity=Severity.INFO,
                    description=(
                        f"No vulnerability signatures matched for {host}. "
                        "This does not guarantee the absence of vulnerabilities."
                    ),
                )
            )

        passed = not any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)

        return CheckResult(
            check_name=self.name,
            target=host,
            passed=passed,
            findings=findings,
            metadata={
                "banners_checked": len(checked_banners),
                "ports_checked": list(checked_banners.keys()),
            },
        )
