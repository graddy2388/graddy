import logging
import socket
import ssl
from typing import List

from .base import BaseCheck, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)

WEAK_CIPHER_TESTS = [
    ("NULL",    "eNULL",   Severity.CRITICAL, "NULL encryption cipher supported — no encryption"),
    ("EXPORT",  "EXPORT",  Severity.CRITICAL, "EXPORT-grade cipher supported — trivially broken"),
    ("RC4",     "RC4",     Severity.CRITICAL, "RC4 cipher supported — cryptographically broken"),
    ("DES",     "DES:!3DES", Severity.HIGH,   "DES cipher supported — 56-bit key, easily brute-forced"),
    ("3DES",    "3DES",    Severity.HIGH,     "3DES cipher supported — vulnerable to SWEET32 attack"),
    ("MD5 MAC", "MD5",     Severity.HIGH,     "MD5-based MAC cipher supported — collision attacks possible"),
    ("aNULL",   "aNULL",   Severity.CRITICAL, "Anonymous DH cipher supported — no authentication, MITM trivial"),
]


def _try_cipher(host: str, port: int, cipher_string: str, timeout: int) -> bool:
    """Return True if the server accepts a connection with the given cipher string."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers(cipher_string)
        with ctx.wrap_socket(
            socket.create_connection((host, port), timeout=timeout),
            server_hostname=host,
        ):
            return True
    except ssl.SSLError:
        return False
    except Exception as exc:
        logger.debug("CipherCheck: error testing cipher '%s' on %s:%d: %s", cipher_string, host, port, exc)
        return False


def _check_tls_version_support(
    host: str, port: int, version_const: ssl.TLSVersion, version_name: str, timeout: int
) -> bool:
    """Return True if the server supports a specific TLS version."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version_const
        ctx.maximum_version = version_const
        with ctx.wrap_socket(
            socket.create_connection((host, port), timeout=timeout),
            server_hostname=host,
        ):
            return True
    except ssl.SSLError:
        return False
    except Exception as exc:
        logger.debug(
            "CipherCheck: error testing %s on %s:%d: %s", version_name, host, port, exc
        )
        return False


class CipherCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "cipher"

    def run(self, target: dict) -> CheckResult:
        host = target["host"]
        ports: List[int] = target.get("ports", [443])
        cipher_config = self.config.get("cipher", {})
        timeout = int(cipher_config.get("timeout", 5))

        # Determine SSL port (prefer 443/8443)
        ssl_port = 443
        for p in ports:
            if p in (443, 8443):
                ssl_port = p
                break

        findings: List[Finding] = []

        # First verify the port is open and speaks TLS
        port_open = False
        try:
            sock = socket.create_connection((host, ssl_port), timeout=timeout)
            sock.close()
            port_open = True
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            logger.debug("CipherCheck: port %d on %s not reachable: %s", ssl_port, host, exc)

        if not port_open:
            return CheckResult(
                check_name=self.name,
                target=host,
                passed=False,
                findings=[],
                error=f"SSL port {ssl_port} is not reachable on {host}",
            )

        # Test weak cipher categories
        for category_name, cipher_string, severity, description in WEAK_CIPHER_TESTS:
            try:
                supported = _try_cipher(host, ssl_port, cipher_string, timeout)
            except Exception as exc:
                logger.debug(
                    "CipherCheck: skipping cipher test '%s' on %s:%d (invalid on this build): %s",
                    cipher_string, host, ssl_port, exc,
                )
                continue

            if supported:
                findings.append(
                    Finding(
                        title=f"{category_name} cipher suite supported on port {ssl_port}",
                        severity=severity,
                        description=(
                            f"{description} — {host}:{ssl_port} accepted a connection "
                            f"using cipher string '{cipher_string}'."
                        ),
                        recommendation=(
                            f"Disable {category_name} cipher suites in the server TLS configuration. "
                            "Use only TLS 1.2+ with strong AEAD ciphers (AES-GCM, ChaCha20-Poly1305)."
                        ),
                        details={
                            "host": host,
                            "port": ssl_port,
                            "cipher_category": category_name,
                            "cipher_string": cipher_string,
                        },
                    )
                )

        # Enumerate supported TLS versions (informational)
        tls_version_tests = [
            (ssl.TLSVersion.TLSv1_2, "TLS 1.2"),
            (ssl.TLSVersion.TLSv1_3, "TLS 1.3"),
        ]

        supported_versions = []
        for version_const, version_name in tls_version_tests:
            try:
                if _check_tls_version_support(host, ssl_port, version_const, version_name, timeout):
                    supported_versions.append(version_name)
            except AttributeError:
                logger.debug("CipherCheck: TLS version constant %s not available", version_name)

        if supported_versions:
            findings.append(
                Finding(
                    title=f"Supported TLS versions on port {ssl_port}",
                    severity=Severity.INFO,
                    description=f"TLS versions supported: {', '.join(supported_versions)}.",
                    details={"port": ssl_port, "supported_versions": supported_versions},
                )
            )

        passed = not any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)

        return CheckResult(
            check_name=self.name,
            target=host,
            passed=passed,
            findings=findings,
            metadata={"ssl_port": ssl_port},
        )
