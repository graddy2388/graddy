import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

from .base import BaseCheck, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)

PORT_SERVICE_MAP: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
    3128: "Proxy",
    8888: "HTTP-Alt",
    9200: "Elasticsearch",
    11211: "Memcached",
}

DANGEROUS_PORTS: Dict[int, Tuple[Severity, str, str]] = {
    23: (
        Severity.CRITICAL,
        "Telnet service exposed",
        "Telnet transmits data including credentials in plaintext. "
        "Disable Telnet and use SSH instead.",
    ),
    21: (
        Severity.HIGH,
        "FTP service exposed",
        "FTP transmits credentials in plaintext unless FTPS/SFTP is used. "
        "Replace with SFTP (SSH File Transfer Protocol) or FTPS.",
    ),
    3389: (
        Severity.HIGH,
        "RDP service exposed to internet",
        "RDP has a history of critical vulnerabilities (BlueKeep, DejaBlue). "
        "Restrict RDP access via VPN or firewall rules.",
    ),
    445: (
        Severity.HIGH,
        "SMB service exposed",
        "SMB has been exploited by WannaCry and other ransomware. "
        "Block port 445 at the perimeter firewall if not required.",
    ),
    3306: (
        Severity.MEDIUM,
        "MySQL database port exposed",
        "Database ports should not be publicly accessible. "
        "Restrict access to application servers only.",
    ),
    5432: (
        Severity.MEDIUM,
        "PostgreSQL database port exposed",
        "Database ports should not be publicly accessible. "
        "Restrict access to application servers only.",
    ),
    6379: (
        Severity.HIGH,
        "Redis port exposed (no auth by default)",
        "Redis instances without authentication are frequently compromised. "
        "Enable authentication and bind to localhost or private network only.",
    ),
    27017: (
        Severity.HIGH,
        "MongoDB port exposed (no auth by default)",
        "MongoDB instances without authentication expose all data. "
        "Enable authentication and restrict network access.",
    ),
    11211: (
        Severity.MEDIUM,
        "Memcached port exposed",
        "Exposed Memcached can be used for DDoS amplification attacks. "
        "Bind Memcached to localhost only.",
    ),
    9200: (
        Severity.HIGH,
        "Elasticsearch port exposed (no auth by default)",
        "Elasticsearch does not require authentication by default. "
        "Enable security features and restrict network access.",
    ),
}


def _grab_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """Attempt to grab a service banner from an open port."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                # Send HTTP request for web-like ports to elicit a response
                if port in (80, 8080, 8888, 3128):
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                data = sock.recv(1024)
                banner = data.decode("utf-8", errors="replace").strip()
                return banner if banner else None
            except (socket.timeout, OSError):
                return None
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def _scan_port(host: str, port: int, timeout: float) -> Tuple[int, bool, Optional[str]]:
    """Scan a single port. Returns (port, is_open, banner)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            banner = _grab_banner(host, port)
            return port, True, banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False, None


class PortScanCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "port_scan"

    def run(self, target: dict) -> CheckResult:
        host = target["host"]
        config_scanning = self.config.get("scanning", {})
        timeout = float(config_scanning.get("port_timeout", 3))
        max_workers = int(config_scanning.get("max_workers", 50))

        # Determine ports to scan
        ports: List[int] = target.get("ports", config_scanning.get("common_ports", []))
        if not ports:
            ports = config_scanning.get("common_ports", [])

        findings: List[Finding] = []
        open_ports: Dict[int, Optional[str]] = {}

        logger.info("Scanning %d ports on %s", len(ports), host)

        with ThreadPoolExecutor(max_workers=min(max_workers, len(ports) or 1)) as executor:
            future_to_port = {
                executor.submit(_scan_port, host, port, timeout): port for port in ports
            }
            for future in as_completed(future_to_port):
                port, is_open, banner = future.result()
                if is_open:
                    open_ports[port] = banner
                    logger.debug("Port %d open on %s (banner: %s)", port, host, banner)

        # Generate findings for open ports
        for port, banner in sorted(open_ports.items()):
            service = PORT_SERVICE_MAP.get(port, "Unknown")

            # INFO finding for every open port
            findings.append(
                Finding(
                    title=f"Open port {port}/{service}",
                    severity=Severity.INFO,
                    description=f"Port {port} ({service}) is open on {host}.",
                    recommendation="Verify this port should be publicly accessible.",
                    details={"port": port, "service": service, "banner": banner},
                )
            )

            # Flag dangerous ports
            if port in DANGEROUS_PORTS:
                sev, title, recommendation = DANGEROUS_PORTS[port]
                findings.append(
                    Finding(
                        title=title,
                        severity=sev,
                        description=(
                            f"Port {port} ({service}) is open on {host}. "
                            f"{title}"
                        ),
                        recommendation=recommendation,
                        details={"port": port, "service": service},
                    )
                )

            # Banner reveals version information (information disclosure)
            if banner and any(
                keyword in banner
                for keyword in ["version", "Version", "OpenSSH", "Apache", "nginx", "IIS", "vsftpd"]
            ):
                findings.append(
                    Finding(
                        title=f"Service version disclosure on port {port}",
                        severity=Severity.MEDIUM,
                        description=(
                            f"The service on port {port} ({service}) exposes version "
                            f"information in its banner, which aids attackers in targeting "
                            f"known vulnerabilities."
                        ),
                        recommendation=(
                            "Configure the service to suppress version information in banners. "
                            "For SSH: set 'DebannerVersion no' equivalent. "
                            "For web servers: disable server tokens/signature."
                        ),
                        details={"port": port, "service": service, "banner": banner},
                    )
                )

        passed = not any(
            f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings
        )

        return CheckResult(
            check_name=self.name,
            target=host,
            passed=passed,
            findings=findings,
            metadata={
                "open_ports": list(open_ports.keys()),
                "banners": {str(p): b for p, b in open_ports.items() if b},
                "scanned_ports": ports,
            },
        )
