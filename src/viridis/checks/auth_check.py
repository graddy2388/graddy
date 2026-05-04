"""
viridis.checks.auth_check – Authentication weakness detection.

Red-team perspective: weak/default credentials and unauthenticated services
are among the fastest paths to initial access. This check probes for:

  1. FTP anonymous login (unauthenticated file access)
  2. Telnet banner exposure (cleartext protocol still alive)
  3. HTTP Basic Auth with default credentials on common management paths
  4. LDAP null bind (unauthenticated directory enumeration)
  5. Redis without authentication (unauthenticated DB access)

All probes are non-destructive, read-only, and use short timeouts.
"""
from __future__ import annotations

import ftplib
import logging
import socket
import urllib.request
import urllib.error
import ssl
from typing import List, Optional, Tuple

from .base import BaseCheck, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)

# Common default credentials for HTTP Basic Auth panels
_HTTP_DEFAULT_CREDS: List[Tuple[str, str]] = [
    ("admin",    "admin"),
    ("admin",    "password"),
    ("admin",    "1234"),
    ("admin",    ""),
    ("root",     "root"),
    ("root",     ""),
    ("user",     "user"),
    ("guest",    "guest"),
]

# Paths that often require HTTP Basic Auth
_AUTH_PATHS = [
    "/admin", "/administrator", "/manager", "/console",
    "/phpmyadmin", "/pma", "/wp-admin", "/wp-login.php",
    "/login", "/auth", "/_cat/health",  # Elasticsearch
]

_TIMEOUT = 4.0


def _check_ftp_anon(host: str, port: int = 21) -> Optional[Finding]:
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=_TIMEOUT)
        ftp.login("anonymous", "viridis@scan.local")
        listing = []
        try:
            ftp.retrlines("LIST", listing.append)
        except Exception:
            pass
        ftp.quit()
        return Finding(
            title="FTP anonymous login allowed",
            severity=Severity.HIGH,
            description=(
                f"{host}:{port} accepts anonymous FTP login. "
                "An unauthenticated attacker can browse directory listings and potentially "
                "download or upload files. FTP is also cleartext — credentials and data "
                "transferred are visible to network observers."
            ),
            recommendation=(
                "Disable anonymous FTP access. "
                "Replace FTP with SFTP or FTPS. "
                "If FTP is required, restrict anonymous access to read-only public directories "
                "and enforce strong filesystem permissions."
            ),
            details={"port": port, "listing_sample": listing[:5]},
        )
    except ftplib.error_perm:
        return None  # Login rejected — anonymous not allowed
    except Exception:
        return None  # Port closed or timed out


def _check_telnet(host: str, port: int = 23) -> Optional[Finding]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(_TIMEOUT)
        s.connect((host, port))
        banner = b""
        try:
            banner = s.recv(256)
        except OSError:
            pass
        s.close()
        banner_str = banner[:120].decode("ascii", errors="replace").strip()
        return Finding(
            title="Telnet service exposed (cleartext protocol)",
            severity=Severity.HIGH,
            description=(
                f"{host}:{port} has an active Telnet service. "
                "Telnet transmits all data — including credentials — in cleartext. "
                "Any network observer (or attacker with MITM position) can capture "
                "login credentials instantly. Telnet has no encryption, no integrity, "
                "and no authentication of the server."
            ),
            recommendation=(
                "Disable Telnet immediately. Replace with SSH (OpenSSH 8+). "
                "If Telnet is required for legacy hardware, restrict access by firewall "
                "to specific management IPs only."
            ),
            details={"port": port, "banner": banner_str},
        )
    except OSError:
        return None


def _check_redis_noauth(host: str, port: int = 6379) -> Optional[Finding]:
    """Try a Redis PING without credentials."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(_TIMEOUT)
        s.connect((host, port))
        s.sendall(b"*1\r\n$4\r\nPING\r\n")
        resp = s.recv(64)
        s.close()
        if resp.startswith(b"+PONG") or resp.startswith(b"$4\r\nPONG"):
            return Finding(
                title="Redis unauthenticated access (no AUTH required)",
                severity=Severity.CRITICAL,
                description=(
                    f"{host}:{port} is a Redis server that responds to commands without "
                    "any authentication. An attacker can read/write all data, execute "
                    "Lua scripts, write files (config rewrite → SSH authorized_keys), "
                    "or achieve RCE via module load on some versions."
                ),
                recommendation=(
                    "Set 'requirepass <strong-password>' in redis.conf. "
                    "Bind Redis to 127.0.0.1 or a private interface only. "
                    "Firewall port 6379 from any untrusted network. "
                    "Consider Redis ACL (Redis 6+) for fine-grained access control."
                ),
                details={"port": port, "response": resp[:20].decode("ascii", errors="replace")},
            )
    except OSError:
        pass
    return None


def _check_ldap_null_bind(host: str, port: int = 389) -> Optional[Finding]:
    """Send a minimal LDAP simple bind with empty DN and password."""
    # Minimal LDAP bind request: version=3, DN='', password=''
    bind_req = (
        b"\x30\x0c"          # SEQUENCE
        b"\x02\x01\x01"      # MessageID = 1
        b"\x60\x07"          # BindRequest
        b"\x02\x01\x03"      # version = 3
        b"\x04\x00"          # DN = '' (empty)
        b"\x80\x00"          # simple password = ''
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(_TIMEOUT)
        s.connect((host, port))
        s.sendall(bind_req)
        resp = s.recv(64)
        s.close()
        # Look for a BindResponse with resultCode=0 (success)
        if len(resp) >= 14 and resp[7:9] == b"\x61\x07":
            result_code = resp[13] if len(resp) > 13 else 0xFF
            if result_code == 0x00:
                return Finding(
                    title="LDAP null bind accepted (unauthenticated directory access)",
                    severity=Severity.HIGH,
                    description=(
                        f"{host}:{port} accepted an LDAP null bind (empty credentials). "
                        "An attacker can enumerate Active Directory objects, users, groups, "
                        "password policies, and GPO paths without any credentials. "
                        "This is a classic reconnaissance step before pass-the-hash or "
                        "Kerberoasting attacks."
                    ),
                    recommendation=(
                        "Disable anonymous LDAP binds. "
                        "Windows AD: Computer Configuration → Windows Settings → Security Settings → "
                        "Local Policies → Security Options → "
                        "Network access: Do not allow anonymous enumeration of SAM accounts and shares. "
                        "For OpenLDAP: set 'disallow bind_anon' in slapd.conf."
                    ),
                    details={"port": port},
                )
    except OSError:
        pass
    return None


def _check_http_default_creds(host: str, ports: List[int]) -> List[Finding]:
    """Try common default credentials against HTTP Basic Auth on management paths."""
    findings: List[Finding] = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for port in ports:
        scheme = "https" if port in (443, 8443, 4443) else "http"
        for path in _AUTH_PATHS:
            url = f"{scheme}://{host}:{port}{path}"
            try:
                req = urllib.request.Request(url)
                try:
                    urllib.request.urlopen(req, timeout=2.0, context=ctx if scheme == "https" else None)
                except urllib.error.HTTPError as e:
                    if e.code != 401:
                        continue
                    # Path requires Basic Auth — try default creds
                    for username, password in _HTTP_DEFAULT_CREDS:
                        import base64
                        cred = base64.b64encode(f"{username}:{password}".encode()).decode()
                        req2 = urllib.request.Request(url)
                        req2.add_header("Authorization", f"Basic {cred}")
                        try:
                            resp = urllib.request.urlopen(req2, timeout=2.0,
                                                          context=ctx if scheme == "https" else None)
                            if resp.getcode() in (200, 301, 302):
                                findings.append(Finding(
                                    title=f"Default credentials accepted: {username}/{password or '(empty)'}",
                                    severity=Severity.CRITICAL,
                                    description=(
                                        f"{url} accepted default HTTP Basic Auth credentials "
                                        f"({username}/{password or 'empty password'}). "
                                        "Default credentials are the most trivial form of "
                                        "initial access — no exploitation required. "
                                        "This is frequently the first thing a red team tests."
                                    ),
                                    recommendation=(
                                        f"Change the default password for {username} immediately. "
                                        "Use a strong, unique password (20+ chars). "
                                        "Prefer token/certificate authentication over Basic Auth. "
                                        "Restrict administrative interfaces by IP/network."
                                    ),
                                    details={"url": url, "username": username},
                                ))
                                return findings  # one hit is enough evidence
                        except Exception:
                            pass
                except Exception:
                    pass
            except Exception:
                pass
    return findings


class AuthCheck(BaseCheck):
    """
    Authentication weakness checker from a red-team perspective.
    Probes for unauthenticated services, cleartext protocols, and default credentials.
    """

    @property
    def name(self) -> str:
        return "auth"

    def run(self, target: dict) -> CheckResult:
        host = target["host"]
        findings: List[Finding] = []

        # FTP anonymous login
        f = _check_ftp_anon(host)
        if f:
            findings.append(f)

        # Telnet exposure
        f = _check_telnet(host)
        if f:
            findings.append(f)

        # Redis unauthenticated
        f = _check_redis_noauth(host)
        if f:
            findings.append(f)

        # LDAP null bind
        f = _check_ldap_null_bind(host)
        if f:
            findings.append(f)

        # HTTP default credentials
        ports_raw = target.get("ports") or [80, 443, 8080, 8443]
        if isinstance(ports_raw, str):
            import json
            try:
                ports_raw = json.loads(ports_raw)
            except Exception:
                ports_raw = [80, 443]
        http_findings = _check_http_default_creds(host, list(ports_raw)[:6])
        findings.extend(http_findings)

        if not findings:
            findings.append(Finding(
                title="No obvious authentication weaknesses found",
                severity=Severity.INFO,
                description=(
                    "No anonymous FTP, Telnet exposure, unauthenticated Redis, "
                    "LDAP null bind, or default HTTP credentials were detected. "
                    "This does not rule out all authentication issues — "
                    "deep credential auditing requires tool-assisted testing."
                ),
                recommendation=(
                    "Periodically re-run credential checks after configuration changes. "
                    "Consider running Hydra (available in the Tools section) "
                    "against specific services with a custom wordlist."
                ),
                details={},
            ))

        passed = not any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings
        )
        return CheckResult(
            check_name=self.name,
            target=host,
            passed=passed,
            findings=findings,
            metadata={},
        )
