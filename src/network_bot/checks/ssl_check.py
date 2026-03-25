import ssl
import socket
import logging
from datetime import datetime, timezone
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.x509.oid import ExtensionOID, NameOID

from .base import BaseCheck, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)


def _get_certificate(host: str, port: int = 443, timeout: float = 10.0) -> Optional[x509.Certificate]:
    """Retrieve the SSL certificate from a host."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(
            socket.create_connection((host, port), timeout=timeout),
            server_hostname=host,
        ) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            if der_cert:
                return x509.load_der_x509_certificate(der_cert)
    except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError) as exc:
        logger.debug("Could not retrieve certificate from %s:%d - %s", host, port, exc)
    return None


def _check_weak_protocol(host: str, port: int, protocol_name: str, min_version: ssl.TLSVersion, max_version: ssl.TLSVersion, timeout: float = 5.0) -> bool:
    """Return True if the host accepts connections with the given protocol version."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = min_version
        ctx.maximum_version = max_version
        with ctx.wrap_socket(
            socket.create_connection((host, port), timeout=timeout),
            server_hostname=host,
        ):
            return True
    except ssl.SSLError:
        return False
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        logger.debug("Could not connect to %s:%d for %s check: %s", host, port, protocol_name, exc)
        return False


class SSLCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "ssl"

    def run(self, target: dict) -> CheckResult:
        host = target["host"]
        # Determine SSL port (prefer 443, fall back to first HTTPS-like port in target)
        ports: List[int] = target.get("ports", [443])
        ssl_port = 443
        for p in ports:
            if p in (443, 8443):
                ssl_port = p
                break
        else:
            # Try 443 regardless
            ssl_port = 443

        ssl_config = self.config.get("ssl", {})
        warn_expiry_days = int(ssl_config.get("warn_expiry_days", 30))
        check_weak_ciphers = bool(ssl_config.get("check_weak_ciphers", True))

        findings: List[Finding] = []

        cert = _get_certificate(host, ssl_port)
        if cert is None:
            return CheckResult(
                check_name=self.name,
                target=host,
                passed=False,
                findings=[],
                error=f"Could not retrieve SSL certificate from {host}:{ssl_port}",
            )

        now = datetime.now(timezone.utc)

        # --- Certificate expiry ---
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
        not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
        days_remaining = (not_after - now).days

        if days_remaining < 0:
            findings.append(
                Finding(
                    title="SSL certificate has expired",
                    severity=Severity.CRITICAL,
                    description=f"The SSL certificate for {host} expired {abs(days_remaining)} days ago.",
                    recommendation="Renew the SSL certificate immediately.",
                    details={"expired_at": not_after.isoformat(), "days_overdue": abs(days_remaining)},
                )
            )
        elif days_remaining <= warn_expiry_days:
            findings.append(
                Finding(
                    title=f"SSL certificate expiring soon ({days_remaining} days)",
                    severity=Severity.HIGH,
                    description=(
                        f"The SSL certificate for {host} will expire in {days_remaining} days "
                        f"(on {not_after.date().isoformat()})."
                    ),
                    recommendation="Renew the SSL certificate before it expires.",
                    details={"expires_at": not_after.isoformat(), "days_remaining": days_remaining},
                )
            )
        else:
            findings.append(
                Finding(
                    title="SSL certificate validity",
                    severity=Severity.INFO,
                    description=f"Certificate is valid for {days_remaining} more days (expires {not_after.date().isoformat()}).",
                    details={"expires_at": not_after.isoformat(), "days_remaining": days_remaining},
                )
            )

        # --- Self-signed detection ---
        issuer = cert.issuer
        subject = cert.subject
        if issuer == subject:
            findings.append(
                Finding(
                    title="Self-signed SSL certificate detected",
                    severity=Severity.HIGH,
                    description=(
                        f"The certificate for {host} is self-signed. "
                        "Clients will receive browser warnings and the certificate provides no trust assurance."
                    ),
                    recommendation="Obtain a certificate from a trusted Certificate Authority (e.g., Let's Encrypt).",
                    details={
                        "issuer": issuer.rfc4514_string(),
                        "subject": subject.rfc4514_string(),
                    },
                )
            )

        # --- Subject / SAN validation ---
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_names = san_ext.value.get_values_for_type(x509.DNSName)
            findings.append(
                Finding(
                    title="Subject Alternative Names present",
                    severity=Severity.INFO,
                    description=f"Certificate covers: {', '.join(san_names)}",
                    details={"san": san_names},
                )
            )
        except x509.ExtensionNotFound:
            findings.append(
                Finding(
                    title="No Subject Alternative Names in certificate",
                    severity=Severity.MEDIUM,
                    description=(
                        "The certificate does not contain a Subject Alternative Name (SAN) extension. "
                        "Modern browsers require SANs and may reject certificates without them."
                    ),
                    recommendation="Reissue the certificate with SAN extension including all intended hostnames.",
                    details={},
                )
            )

        # --- Key size ---
        pub_key = cert.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            key_size = pub_key.key_size
            if key_size < 2048:
                findings.append(
                    Finding(
                        title=f"Weak RSA key size ({key_size} bits)",
                        severity=Severity.HIGH,
                        description=(
                            f"The certificate uses a {key_size}-bit RSA key, which is considered insecure. "
                            "NIST recommends a minimum of 2048 bits."
                        ),
                        recommendation="Reissue the certificate with at least a 2048-bit RSA key (4096 recommended).",
                        details={"key_type": "RSA", "key_size": key_size},
                    )
                )
            elif key_size < 4096:
                findings.append(
                    Finding(
                        title=f"RSA key size acceptable but not optimal ({key_size} bits)",
                        severity=Severity.LOW,
                        description=(
                            f"The certificate uses a {key_size}-bit RSA key. "
                            "While currently acceptable, 4096-bit keys provide stronger long-term security."
                        ),
                        recommendation="Consider reissuing with a 4096-bit RSA key for improved security.",
                        details={"key_type": "RSA", "key_size": key_size},
                    )
                )
            else:
                findings.append(
                    Finding(
                        title=f"Strong RSA key size ({key_size} bits)",
                        severity=Severity.INFO,
                        description=f"Certificate uses a {key_size}-bit RSA key.",
                        details={"key_type": "RSA", "key_size": key_size},
                    )
                )
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_size = pub_key.key_size
            findings.append(
                Finding(
                    title=f"EC key detected ({key_size} bits)",
                    severity=Severity.INFO,
                    description=f"Certificate uses an Elliptic Curve key ({pub_key.curve.name}) with {key_size}-bit key size.",
                    details={"key_type": "EC", "curve": pub_key.curve.name, "key_size": key_size},
                )
            )

        # --- Weak protocol version checks ---
        if check_weak_ciphers:
            weak_protocols = []

            # TLS 1.0
            try:
                if _check_weak_protocol(
                    host, ssl_port,
                    "TLS 1.0",
                    ssl.TLSVersion.TLSv1,
                    ssl.TLSVersion.TLSv1,
                ):
                    weak_protocols.append("TLS 1.0")
                    findings.append(
                        Finding(
                            title="TLS 1.0 supported (deprecated)",
                            severity=Severity.HIGH,
                            description=(
                                f"{host}:{ssl_port} accepts TLS 1.0 connections. "
                                "TLS 1.0 is deprecated (RFC 8996) and vulnerable to BEAST and other attacks."
                            ),
                            recommendation="Disable TLS 1.0 and TLS 1.1. Only enable TLS 1.2 and TLS 1.3.",
                            details={"protocol": "TLS 1.0"},
                        )
                    )
            except AttributeError:
                logger.debug("TLS 1.0 version constant not available on this Python build")

            # TLS 1.1
            try:
                if _check_weak_protocol(
                    host, ssl_port,
                    "TLS 1.1",
                    ssl.TLSVersion.TLSv1_1,
                    ssl.TLSVersion.TLSv1_1,
                ):
                    weak_protocols.append("TLS 1.1")
                    findings.append(
                        Finding(
                            title="TLS 1.1 supported (deprecated)",
                            severity=Severity.HIGH,
                            description=(
                                f"{host}:{ssl_port} accepts TLS 1.1 connections. "
                                "TLS 1.1 is deprecated (RFC 8996)."
                            ),
                            recommendation="Disable TLS 1.0 and TLS 1.1. Only enable TLS 1.2 and TLS 1.3.",
                            details={"protocol": "TLS 1.1"},
                        )
                    )
            except AttributeError:
                logger.debug("TLS 1.1 version constant not available on this Python build")

            if not weak_protocols:
                findings.append(
                    Finding(
                        title="No deprecated TLS versions supported",
                        severity=Severity.INFO,
                        description=f"{host} does not accept TLS 1.0 or TLS 1.1 connections.",
                    )
                )

        # --- Certificate chain (basic) ---
        try:
            ctx_verify = ssl.create_default_context()
            with ctx_verify.wrap_socket(
                socket.create_connection((host, ssl_port), timeout=10),
                server_hostname=host,
            ):
                findings.append(
                    Finding(
                        title="Certificate chain validates successfully",
                        severity=Severity.INFO,
                        description=f"The certificate chain for {host} is trusted by the system CA store.",
                    )
                )
        except ssl.SSLCertVerificationError as exc:
            findings.append(
                Finding(
                    title="Certificate chain validation failed",
                    severity=Severity.HIGH,
                    description=(
                        f"The certificate chain for {host} could not be validated: {exc}. "
                        "Clients may see security warnings."
                    ),
                    recommendation="Ensure the full certificate chain (including intermediate CAs) is correctly configured.",
                    details={"error": str(exc)},
                )
            )
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError) as exc:
            logger.debug("Chain validation check skipped for %s: %s", host, exc)

        passed = not any(
            f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings
        )

        return CheckResult(
            check_name=self.name,
            target=host,
            passed=passed,
            findings=findings,
            metadata={
                "port": ssl_port,
                "subject": subject.rfc4514_string(),
                "issuer": issuer.rfc4514_string(),
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "days_remaining": days_remaining,
            },
        )
