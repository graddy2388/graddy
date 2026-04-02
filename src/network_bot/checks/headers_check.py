"""
network_bot.checks.headers_check - HTTP security header analyzer.

Fetches HTTP response headers and audits them for:
- Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
- Information disclosure headers (Server, X-Powered-By, etc.)
- Misconfigured CORS policies
"""
from __future__ import annotations

import logging
import urllib.request
import urllib.error
import ssl
from typing import Any, Dict, List

from .base import BaseCheck, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)

# Security headers that should be present
_REQUIRED_HEADERS: List[Dict[str, Any]] = [
    {
        "header": "strict-transport-security",
        "display": "Strict-Transport-Security",
        "severity": Severity.HIGH,
        "title": "Missing HSTS Header",
        "description": (
            "The Strict-Transport-Security (HSTS) header is absent. Without it, browsers "
            "may connect over plain HTTP and users are vulnerable to SSL stripping attacks."
        ),
        "recommendation": (
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        ),
    },
    {
        "header": "content-security-policy",
        "display": "Content-Security-Policy",
        "severity": Severity.MEDIUM,
        "title": "Missing Content-Security-Policy Header",
        "description": (
            "No Content-Security-Policy header was found. CSP is the primary defence against "
            "Cross-Site Scripting (XSS) and data injection attacks."
        ),
        "recommendation": (
            "Define a restrictive CSP. Start with: "
            "Content-Security-Policy: default-src 'self'"
        ),
    },
    {
        "header": "x-frame-options",
        "display": "X-Frame-Options",
        "severity": Severity.MEDIUM,
        "title": "Missing X-Frame-Options Header",
        "description": (
            "X-Frame-Options is not set. The page may be embedded in an iframe by an "
            "attacker, enabling clickjacking attacks."
        ),
        "recommendation": "Add: X-Frame-Options: DENY (or SAMEORIGIN if framing is required internally)",
    },
    {
        "header": "x-content-type-options",
        "display": "X-Content-Type-Options",
        "severity": Severity.LOW,
        "title": "Missing X-Content-Type-Options Header",
        "description": (
            "X-Content-Type-Options: nosniff is not set. Browsers may MIME-sniff responses "
            "and execute content as a different type than declared."
        ),
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    {
        "header": "referrer-policy",
        "display": "Referrer-Policy",
        "severity": Severity.LOW,
        "title": "Missing Referrer-Policy Header",
        "description": (
            "Referrer-Policy is not configured. The browser may send the full URL as a "
            "Referer header to third-party sites, leaking sensitive path or query information."
        ),
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
        "header": "permissions-policy",
        "display": "Permissions-Policy",
        "severity": Severity.LOW,
        "title": "Missing Permissions-Policy Header",
        "description": (
            "Permissions-Policy (formerly Feature-Policy) is absent. Browser features such "
            "as camera, microphone, and geolocation are unrestricted for this origin."
        ),
        "recommendation": (
            "Add: Permissions-Policy: camera=(), microphone=(), geolocation=(), "
            "payment=(), usb=()"
        ),
    },
]

# Headers that disclose server technology
_DISCLOSURE_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-wordpress-cache",
]

# Weak/insecure header value patterns
_WEAK_CSP_PATTERNS = ["unsafe-inline", "unsafe-eval", "*"]


def _target_url(host: str) -> str:
    host = host.strip()
    if host.startswith("http://") or host.startswith("https://"):
        return host
    return f"http://{host}"


def _fetch_headers(url: str, timeout: int = 10) -> Dict[str, str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, method="HEAD")
    req.add_header("User-Agent", "Viridis-HeaderAnalyzer/1.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        # HTTPError is a valid response with headers
        return {k.lower(): v for k, v in e.headers.items()}


class HeadersCheck(BaseCheck):
    """Audit HTTP response headers for security misconfigurations."""

    def run(self, target: Dict[str, Any]) -> CheckResult:
        host = target.get("host", "")
        url = _target_url(host)
        findings: List[Finding] = []

        try:
            headers = _fetch_headers(url)
        except Exception as exc:
            # Try HTTPS fallback if HTTP failed
            try:
                url_https = url.replace("http://", "https://")
                headers = _fetch_headers(url_https)
                url = url_https
            except Exception:
                logger.debug("headers_check: could not reach %s: %s", url, exc)
                return CheckResult(
                    check_name="headers",
                    target=host,
                    passed=False,
                    error=f"Could not connect to {url}: {exc}",
                )

        # --- Check required security headers ---
        for spec in _REQUIRED_HEADERS:
            if spec["header"] not in headers:
                findings.append(Finding(
                    title=spec["title"],
                    severity=spec["severity"],
                    description=spec["description"],
                    recommendation=spec["recommendation"],
                    details={"missing_header": spec["display"], "url": url},
                ))

        # --- Check for weak CSP ---
        csp = headers.get("content-security-policy", "")
        if csp:
            weak = [p for p in _WEAK_CSP_PATTERNS if p in csp]
            if weak:
                findings.append(Finding(
                    title="Weak Content-Security-Policy",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Content-Security-Policy contains unsafe directives: {', '.join(weak)}. "
                        "These directives effectively disable XSS protection for those contexts."
                    ),
                    recommendation=(
                        "Remove 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes "
                        "for inline scripts instead."
                    ),
                    details={"csp_value": csp[:300], "weak_directives": weak, "url": url},
                ))

        # --- Check for information disclosure ---
        disclosed = {}
        for dh in _DISCLOSURE_HEADERS:
            if dh in headers:
                disclosed[dh] = headers[dh]

        if disclosed:
            findings.append(Finding(
                title="Server Technology Disclosure",
                severity=Severity.LOW,
                description=(
                    "The server is leaking technology stack information via response headers. "
                    "This aids attackers in targeting known vulnerabilities for the disclosed software."
                ),
                recommendation=(
                    "Remove or suppress disclosure headers. Configure your web server to omit "
                    "the Server header, and disable X-Powered-By in your application framework."
                ),
                details={"disclosed_headers": disclosed, "url": url},
            ))

        # --- Check CORS misconfiguration ---
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        if acao == "*" and acac.lower() == "true":
            findings.append(Finding(
                title="CORS Wildcard with Credentials Allowed",
                severity=Severity.HIGH,
                description=(
                    "Access-Control-Allow-Origin: * is set alongside "
                    "Access-Control-Allow-Credentials: true. This combination allows any "
                    "origin to make credentialed cross-origin requests, which is a critical "
                    "CORS misconfiguration."
                ),
                recommendation=(
                    "Specify an explicit origin whitelist instead of '*' when credentials "
                    "are permitted. Never use wildcard with credentials."
                ),
                details={"acao": acao, "acac": acac, "url": url},
            ))
        elif acao == "*":
            findings.append(Finding(
                title="CORS Wildcard Origin Allowed",
                severity=Severity.MEDIUM,
                description=(
                    "Access-Control-Allow-Origin: * permits any website to read responses "
                    "from this server. For public APIs this may be intentional, but verify "
                    "that no sensitive data is exposed."
                ),
                recommendation=(
                    "Restrict CORS to known trusted origins unless this is an intentional "
                    "public API endpoint."
                ),
                details={"acao": acao, "url": url},
            ))

        # --- Emit passing info finding with full header summary ---
        findings.append(Finding(
            title="HTTP Headers Analyzed",
            severity=Severity.INFO,
            description=f"Analyzed {len(headers)} response headers from {url}.",
            recommendation="Review findings above for any required remediation.",
            details={
                "url": url,
                "headers_present": sorted(headers.keys()),
                "security_issues_found": len([f for f in findings if f.severity != Severity.INFO]),
            },
        ))

        passed = not any(
            f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
            for f in findings
        )

        return CheckResult(
            check_name="headers",
            target=host,
            passed=passed,
            findings=findings,
        )
