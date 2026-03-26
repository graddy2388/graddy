import logging
import smtplib
import ssl
import socket
from typing import List, Optional, Tuple

from .base import BaseCheck, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)


def _parse_ehlo_response(ehlo_resp: bytes) -> dict:
    """Parse EHLO response into a dict of capabilities."""
    capabilities = {}
    if not ehlo_resp:
        return capabilities
    lines = ehlo_resp.decode("utf-8", errors="replace").splitlines()
    for line in lines[1:]:
        # Lines are like "250-CAPABILITY" or "250 CAPABILITY"
        if len(line) >= 4:
            cap_part = line[4:].strip()
            parts = cap_part.split()
            if parts:
                cap_name = parts[0].upper()
                cap_args = parts[1:] if len(parts) > 1 else []
                capabilities[cap_name] = cap_args
    return capabilities


class SMTPCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "smtp"

    def run(self, target: dict) -> CheckResult:
        host = target["host"]
        smtp_ports: List[int] = target.get("smtp_ports", [25, 587, 465])
        smtp_config = self.config.get("smtp", {})
        timeout = int(smtp_config.get("timeout", 10))
        test_relay = bool(smtp_config.get("test_relay", False))

        findings: List[Finding] = []
        metadata: dict = {"ports_checked": smtp_ports, "port_results": {}}

        for port in smtp_ports:
            port_findings = self._check_port(host, port, timeout, test_relay)
            findings.extend(port_findings)
            metadata["port_results"][port] = len(port_findings)

        passed = not any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)

        return CheckResult(
            check_name=self.name,
            target=host,
            passed=passed,
            findings=findings,
            metadata=metadata,
        )

    def _check_port(
        self, host: str, port: int, timeout: int, test_relay: bool
    ) -> List[Finding]:
        findings: List[Finding] = []

        # First check if the port is open at all
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            logger.debug("SMTPCheck: port %d on %s not reachable: %s", port, host, exc)
            return findings

        # Port 465 uses implicit TLS (SMTPS)
        if port == 465:
            findings.extend(self._check_smtps(host, port, timeout))
            return findings

        # Ports 25 and 587 use plain SMTP with optional STARTTLS
        try:
            smtp = smtplib.SMTP(host, port, timeout=timeout)
        except smtplib.SMTPException as exc:
            logger.warning("SMTPCheck: failed to connect to %s:%d: %s", host, port, exc)
            return findings
        except OSError as exc:
            logger.warning("SMTPCheck: OS error connecting to %s:%d: %s", host, port, exc)
            return findings

        try:
            # 1. Banner grabbing
            banner = getattr(smtp, "_get_socket", lambda *a, **k: None)
            # The banner is accessible after connection — smtp.sock already connected
            # smtplib already read the banner during __init__; we can read from ehlo
            code, msg = smtp.ehlo("networkbot.local")
            ehlo_resp = msg if isinstance(msg, bytes) else msg.encode("utf-8", errors="replace")

            # Check banner for version disclosure via the welcome message
            welcome = getattr(smtp, "ehlo_resp", b"") or b""
            self._check_banner_version(host, port, welcome, findings)

            # 2. Parse EHLO capabilities
            capabilities = _parse_ehlo_response(ehlo_resp)
            logger.debug("SMTPCheck: %s:%d capabilities: %s", host, port, list(capabilities.keys()))

            has_starttls = "STARTTLS" in capabilities
            auth_methods = capabilities.get("AUTH", [])

            # 3. STARTTLS support check
            if port in (25, 587) and not has_starttls:
                findings.append(
                    Finding(
                        title=f"STARTTLS not advertised on port {port}",
                        severity=Severity.HIGH,
                        description=(
                            f"The SMTP server at {host}:{port} does not advertise STARTTLS support. "
                            "Email traffic on this port is sent in cleartext."
                        ),
                        recommendation="Configure the SMTP server to support and advertise STARTTLS.",
                        details={"port": port, "capabilities": list(capabilities.keys())},
                    )
                )

            # 4. AUTH methods without STARTTLS check
            if not has_starttls and auth_methods:
                cleartext_auth = [m for m in auth_methods if m.upper() in ("PLAIN", "LOGIN")]
                if cleartext_auth:
                    findings.append(
                        Finding(
                            title=f"AUTH {'/'.join(cleartext_auth)} advertised without STARTTLS on port {port}",
                            severity=Severity.HIGH,
                            description=(
                                f"The SMTP server at {host}:{port} advertises AUTH {' and '.join(cleartext_auth)} "
                                "without STARTTLS. Credentials would be transmitted in cleartext (base64-encoded)."
                            ),
                            recommendation=(
                                "Enable STARTTLS before advertising AUTH PLAIN/LOGIN, "
                                "or require clients to use STARTTLS before authenticating."
                            ),
                            details={"port": port, "auth_methods": auth_methods},
                        )
                    )

            # 5. STARTTLS enforcement test — try to AUTH before STARTTLS
            if has_starttls:
                self._check_starttls_enforcement(host, port, timeout, auth_methods, findings)

            # 6. Open relay test
            if test_relay:
                self._check_open_relay(smtp, host, port, findings)

            # 7. TLS quality check after STARTTLS
            if has_starttls:
                self._check_tls_quality_starttls(host, port, timeout, findings)

            # INFO: advertised AUTH methods
            if auth_methods:
                findings.append(
                    Finding(
                        title=f"SMTP AUTH methods advertised on port {port}",
                        severity=Severity.INFO,
                        description=f"Advertised AUTH methods: {', '.join(auth_methods)}",
                        details={"port": port, "auth_methods": auth_methods},
                    )
                )

        except smtplib.SMTPException as exc:
            logger.warning("SMTPCheck: SMTP error checking %s:%d: %s", host, port, exc)
        except OSError as exc:
            logger.warning("SMTPCheck: OS error checking %s:%d: %s", host, port, exc)
        finally:
            try:
                smtp.quit()
            except Exception:
                pass

        return findings

    def _check_banner_version(
        self, host: str, port: int, banner: bytes, findings: List[Finding]
    ) -> None:
        """Check if the SMTP banner discloses server version information."""
        if not banner:
            return
        banner_str = banner.decode("utf-8", errors="replace")
        # Look for version strings like "Postfix 3.5.1", "Exim 4.96", "sendmail 8.15"
        import re
        version_pattern = re.compile(
            r"\b(postfix|exim|sendmail|microsoft|exchange|dovecot|qmail|zimbra)\s+[\d.]+",
            re.IGNORECASE,
        )
        if version_pattern.search(banner_str):
            findings.append(
                Finding(
                    title=f"SMTP banner discloses server version on port {port}",
                    severity=Severity.LOW,
                    description=(
                        f"The SMTP banner at {host}:{port} discloses the MTA software version. "
                        f"Banner snippet: {banner_str[:200]}"
                    ),
                    recommendation="Configure the SMTP server to hide version information in the banner.",
                    details={"port": port, "banner": banner_str[:500]},
                )
            )

    def _check_starttls_enforcement(
        self,
        host: str,
        port: int,
        timeout: int,
        auth_methods: List[str],
        findings: List[Finding],
    ) -> None:
        """Check if server allows AUTH commands before STARTTLS is negotiated."""
        if not auth_methods:
            return
        try:
            test_smtp = smtplib.SMTP(host, port, timeout=timeout)
            try:
                test_smtp.ehlo("networkbot.local")
                # Attempt AUTH LOGIN before STARTTLS
                code, resp = test_smtp.docmd("AUTH", "LOGIN")
                # If server responds with 334 (challenge) or 235 (success), it's proceeding
                # A well-configured server should respond 530 (Must issue STARTTLS first)
                if code not in (530, 538):
                    findings.append(
                        Finding(
                            title=f"SMTP server allows AUTH before STARTTLS on port {port}",
                            severity=Severity.HIGH,
                            description=(
                                f"The SMTP server at {host}:{port} does not enforce STARTTLS before "
                                f"accepting AUTH commands (server responded {code} to AUTH LOGIN). "
                                "Credentials may be transmitted without encryption."
                            ),
                            recommendation=(
                                "Configure the SMTP server to require STARTTLS before accepting AUTH commands. "
                                "Set 'smtpd_tls_auth_only = yes' in Postfix or equivalent."
                            ),
                            details={"port": port, "auth_response_code": code},
                        )
                    )
            finally:
                try:
                    test_smtp.quit()
                except Exception:
                    pass
        except (smtplib.SMTPException, OSError) as exc:
            logger.debug("SMTPCheck: STARTTLS enforcement test failed for %s:%d: %s", host, port, exc)

    def _check_open_relay(
        self, smtp: smtplib.SMTP, host: str, port: int, findings: List[Finding]
    ) -> None:
        """Test for open mail relay."""
        try:
            # Issue RSET to clean up any prior state
            smtp.rset()
            code_mail, _ = smtp.docmd("MAIL", "FROM:<test@networkbot.invalid>")
            if code_mail == 250:
                code_rcpt, _ = smtp.docmd("RCPT", "TO:<relay-test@external.invalid>")
                if code_rcpt == 250:
                    findings.append(
                        Finding(
                            title=f"Open mail relay detected on port {port}",
                            severity=Severity.CRITICAL,
                            description=(
                                f"The SMTP server at {host}:{port} accepted both MAIL FROM and RCPT TO "
                                "for an external address without authentication. "
                                "This server can be used to send spam or phishing emails."
                            ),
                            recommendation=(
                                "Configure the SMTP server to reject relaying from unauthenticated senders "
                                "to non-local recipients. Enable 'smtpd_relay_restrictions' in Postfix."
                            ),
                            details={"port": port, "mail_code": code_mail, "rcpt_code": code_rcpt},
                        )
                    )
            # Reset the connection
            smtp.rset()
        except smtplib.SMTPException as exc:
            logger.debug("SMTPCheck: open relay test error on %s:%d: %s", host, port, exc)

    def _check_tls_quality_starttls(
        self, host: str, port: int, timeout: int, findings: List[Finding]
    ) -> None:
        """Check TLS protocol version and cipher after STARTTLS."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            smtp = smtplib.SMTP(host, port, timeout=timeout)
            try:
                smtp.ehlo("networkbot.local")
                smtp.starttls(context=ctx)
                smtp.ehlo("networkbot.local")

                # Get TLS info from the underlying socket
                tls_sock = smtp.sock
                if hasattr(tls_sock, "version"):
                    tls_version = tls_sock.version()
                    cipher_info = tls_sock.cipher()

                    details: dict = {
                        "port": port,
                        "tls_version": tls_version,
                        "cipher": cipher_info[0] if cipher_info else None,
                    }

                    if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                        findings.append(
                            Finding(
                                title=f"Weak TLS version {tls_version} negotiated on port {port}",
                                severity=Severity.HIGH,
                                description=(
                                    f"STARTTLS on {host}:{port} negotiated deprecated {tls_version}. "
                                    "This version is considered insecure."
                                ),
                                recommendation="Configure the SMTP server to use TLS 1.2 or TLS 1.3 only.",
                                details=details,
                            )
                        )
                    else:
                        findings.append(
                            Finding(
                                title=f"STARTTLS TLS quality on port {port}",
                                severity=Severity.INFO,
                                description=(
                                    f"STARTTLS on {host}:{port} negotiated {tls_version} "
                                    f"with cipher {cipher_info[0] if cipher_info else 'unknown'}."
                                ),
                                details=details,
                            )
                        )
            finally:
                try:
                    smtp.quit()
                except Exception:
                    pass
        except (smtplib.SMTPException, ssl.SSLError, OSError) as exc:
            logger.debug("SMTPCheck: TLS quality check failed for %s:%d: %s", host, port, exc)

    def _check_smtps(
        self, host: str, port: int, timeout: int
    ) -> List[Finding]:
        """Check an SMTPS (implicit TLS) port."""
        findings: List[Finding] = []
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            smtp = smtplib.SMTP_SSL(host, port, context=ctx, timeout=timeout)
            try:
                code, msg = smtp.ehlo("networkbot.local")
                ehlo_resp = msg if isinstance(msg, bytes) else msg.encode("utf-8", errors="replace")
                capabilities = _parse_ehlo_response(ehlo_resp)
                auth_methods = capabilities.get("AUTH", [])

                tls_sock = smtp.sock
                tls_version = tls_sock.version() if hasattr(tls_sock, "version") else None
                cipher_info = tls_sock.cipher() if hasattr(tls_sock, "cipher") else None

                findings.append(
                    Finding(
                        title=f"SMTPS (implicit TLS) active on port {port}",
                        severity=Severity.INFO,
                        description=(
                            f"SMTPS on {host}:{port} is using {tls_version or 'unknown TLS'} "
                            f"with cipher {cipher_info[0] if cipher_info else 'unknown'}."
                        ),
                        details={
                            "port": port,
                            "tls_version": tls_version,
                            "cipher": cipher_info[0] if cipher_info else None,
                            "auth_methods": auth_methods,
                        },
                    )
                )
            finally:
                try:
                    smtp.quit()
                except Exception:
                    pass
        except (smtplib.SMTPException, ssl.SSLError, OSError) as exc:
            logger.debug("SMTPCheck: SMTPS check failed for %s:%d: %s", host, port, exc)

        return findings
