import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

from .base import BaseCheck, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)

# Security headers: (header_name, severity_if_missing, description, recommendation)
SECURITY_HEADERS: List[Tuple[str, Severity, str, str]] = [
    (
        "Strict-Transport-Security",
        Severity.HIGH,
        "HSTS header missing. Without HSTS, browsers may allow insecure HTTP connections, "
        "making the site vulnerable to protocol downgrade attacks.",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header to all HTTPS responses.",
    ),
    (
        "Content-Security-Policy",
        Severity.MEDIUM,
        "Content-Security-Policy (CSP) header missing. Without CSP, the site is more vulnerable "
        "to Cross-Site Scripting (XSS) attacks.",
        "Implement a Content-Security-Policy header to restrict resource loading. "
        "Start with 'Content-Security-Policy: default-src \\'self\\'' and refine as needed.",
    ),
    (
        "X-Frame-Options",
        Severity.MEDIUM,
        "X-Frame-Options header missing. The site may be vulnerable to clickjacking attacks "
        "where it is embedded in a malicious iframe.",
        "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to prevent framing.",
    ),
    (
        "X-Content-Type-Options",
        Severity.LOW,
        "X-Content-Type-Options header missing. Without this header, browsers may sniff "
        "the content type, potentially executing non-script content as scripts.",
        "Add 'X-Content-Type-Options: nosniff' to all responses.",
    ),
    (
        "Referrer-Policy",
        Severity.LOW,
        "Referrer-Policy header missing. Referrer information may be leaked to third parties.",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'Referrer-Policy: no-referrer'.",
    ),
    (
        "Permissions-Policy",
        Severity.INFO,
        "Permissions-Policy header missing. Browser feature access is not explicitly restricted.",
        "Add a Permissions-Policy header to restrict access to browser features "
        "(e.g., camera, microphone, geolocation).",
    ),
]


def _check_xss_protection(headers: Dict[str, str]) -> Optional[Finding]:
    """Check X-XSS-Protection header value."""
    value = headers.get("X-XSS-Protection", "").strip()
    if value and value not in ("0", "1; mode=block"):
        return Finding(
            title="X-XSS-Protection header has non-standard value",
            severity=Severity.LOW,
            description=(
                f"The X-XSS-Protection header is set to '{value}'. "
                "This header is deprecated in modern browsers. Setting it incorrectly may cause issues."
            ),
            recommendation="Either set 'X-XSS-Protection: 0' (to disable the outdated XSS filter) "
                           "or rely on Content-Security-Policy for XSS protection instead.",
            details={"header_value": value},
        )
    return None


def _check_server_header(headers: Dict[str, str], host: str) -> Optional[Finding]:
    """Check if Server header reveals version information."""
    server = headers.get("Server", "").strip()
    if not server:
        return None
    # Check if it contains version numbers or detailed technology info
    version_pattern = re.compile(r"[\d.]+|Apache|nginx|IIS|Tomcat|Jetty|LiteSpeed|OpenSSL", re.IGNORECASE)
    if version_pattern.search(server):
        return Finding(
            title="Server header reveals technology information",
            severity=Severity.MEDIUM,
            description=(
                f"The Server header discloses software details: '{server}'. "
                "This information helps attackers identify known vulnerabilities for targeted exploitation."
            ),
            recommendation=(
                "Configure the web server to suppress or minimize the Server header. "
                "For Apache: 'ServerTokens Prod'. For nginx: 'server_tokens off'. "
                "For IIS: remove the Server header via URL Rewrite or custom headers."
            ),
            details={"server_header": server},
        )
    return None


def _check_http_redirect(host: str, http_config: dict) -> Optional[Finding]:
    """Check if HTTP redirects to HTTPS."""
    timeout = http_config.get("timeout", 10)
    user_agent = http_config.get("user_agent", "Viridis/2.0")
    headers = {"User-Agent": user_agent}

    try:
        resp = requests.get(
            f"http://{host}/",
            timeout=timeout,
            headers=headers,
            allow_redirects=False,
            verify=False,
        )
        if resp.status_code in (301, 302, 307, 308):
            location = resp.headers.get("Location", "")
            if location.startswith("https://"):
                return None  # Good redirect
            else:
                return Finding(
                    title="HTTP redirects to non-HTTPS location",
                    severity=Severity.HIGH,
                    description=(
                        f"HTTP requests to {host} redirect to '{location}' instead of an HTTPS URL. "
                        "Users accessing the site over HTTP are not automatically protected."
                    ),
                    recommendation="Configure HTTP to HTTPS redirects for all traffic.",
                    details={"redirect_location": location, "status_code": resp.status_code},
                )
        else:
            return Finding(
                title="HTTP site does not redirect to HTTPS",
                severity=Severity.HIGH,
                description=(
                    f"HTTP requests to {host} return status {resp.status_code} without redirecting to HTTPS. "
                    "All web traffic should be served over HTTPS."
                ),
                recommendation="Configure the web server to redirect all HTTP traffic to HTTPS.",
                details={"status_code": resp.status_code},
            )
    except RequestException as exc:
        logger.debug("HTTP redirect check failed for %s: %s", host, exc)
        return None


def _check_cookies(response: requests.Response) -> List[Finding]:
    """Check cookies for Secure and HttpOnly flags."""
    findings: List[Finding] = []
    for cookie in response.cookies:
        if not cookie.secure:
            findings.append(
                Finding(
                    title=f"Cookie '{cookie.name}' missing Secure flag",
                    severity=Severity.HIGH,
                    description=(
                        f"The cookie '{cookie.name}' is set without the Secure flag. "
                        "This allows the cookie to be transmitted over unencrypted HTTP connections."
                    ),
                    recommendation=f"Set the Secure flag on cookie '{cookie.name}' to ensure it is only sent over HTTPS.",
                    details={"cookie_name": cookie.name},
                )
            )
        if not cookie.has_nonstandard_attr("HttpOnly"):
            findings.append(
                Finding(
                    title=f"Cookie '{cookie.name}' missing HttpOnly flag",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The cookie '{cookie.name}' is set without the HttpOnly flag. "
                        "This allows JavaScript to access the cookie, enabling theft via XSS attacks."
                    ),
                    recommendation=f"Set the HttpOnly flag on cookie '{cookie.name}' to prevent JavaScript access.",
                    details={"cookie_name": cookie.name},
                )
            )
    return findings


class HTTPCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "http"

    def run(self, target: dict) -> CheckResult:
        host = target["host"]
        http_config = self.config.get("http", {})
        timeout = http_config.get("timeout", 10)
        follow_redirects = http_config.get("follow_redirects", True)
        user_agent = http_config.get("user_agent", "Viridis/2.0 Security Scanner")

        findings: List[Finding] = []
        ports: List[int] = target.get("ports", [80, 443])
        metadata: dict = {}

        # Determine if we should check HTTPS
        https_ports = [p for p in ports if p in (443, 8443)]
        http_ports = [p for p in ports if p in (80, 8080)]
        is_https = bool(https_ports) or 443 in ports or 8443 in ports

        # Primary URL to check
        if https_ports:
            port = https_ports[0]
            base_url = f"https://{host}" if port == 443 else f"https://{host}:{port}"
        elif http_ports:
            port = http_ports[0]
            base_url = f"http://{host}" if port == 80 else f"http://{host}:{port}"
        else:
            base_url = f"https://{host}"
            is_https = True

        session = requests.Session()
        session.headers["User-Agent"] = user_agent

        try:
            response = session.get(
                base_url,
                timeout=timeout,
                allow_redirects=follow_redirects,
                verify=False,
            )
        except RequestException as exc:
            logger.warning("HTTP check failed for %s: %s", host, exc)
            return CheckResult(
                check_name=self.name,
                target=host,
                passed=False,
                error=f"Could not connect to {base_url}: {exc}",
            )

        resp_headers_lower = {k.lower(): v for k, v in response.headers.items()}
        resp_headers_original = dict(response.headers)

        metadata["url"] = base_url
        metadata["status_code"] = response.status_code
        metadata["final_url"] = response.url

        # --- Security headers ---
        for header_name, severity, description, recommendation in SECURITY_HEADERS:
            # HSTS only applies to HTTPS
            if header_name == "Strict-Transport-Security" and not is_https:
                continue
            if header_name.lower() not in resp_headers_lower:
                findings.append(
                    Finding(
                        title=f"Missing security header: {header_name}",
                        severity=severity,
                        description=description,
                        recommendation=recommendation,
                        details={"header": header_name},
                    )
                )
            else:
                findings.append(
                    Finding(
                        title=f"Security header present: {header_name}",
                        severity=Severity.INFO,
                        description=f"Response includes '{header_name}': {resp_headers_lower[header_name.lower()]}",
                        details={
                            "header": header_name,
                            "value": resp_headers_lower[header_name.lower()],
                        },
                    )
                )

        # --- X-XSS-Protection ---
        xss_finding = _check_xss_protection(resp_headers_original)
        if xss_finding:
            findings.append(xss_finding)

        # --- Server header ---
        server_finding = _check_server_header(resp_headers_original, host)
        if server_finding:
            findings.append(server_finding)

        # --- HTTP to HTTPS redirect (only for HTTPS targets) ---
        if is_https:
            redirect_finding = _check_http_redirect(host, http_config)
            if redirect_finding:
                findings.append(redirect_finding)
            else:
                # Only add positive finding if we could actually check
                if http_ports or 80 in ports:
                    findings.append(
                        Finding(
                            title="HTTP correctly redirects to HTTPS",
                            severity=Severity.INFO,
                            description=f"HTTP requests to {host} are redirected to HTTPS.",
                        )
                    )

        # --- Cookie checks ---
        cookie_findings = _check_cookies(response)
        findings.extend(cookie_findings)

        passed = not any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)

        return CheckResult(
            check_name=self.name,
            target=host,
            passed=passed,
            findings=findings,
            metadata=metadata,
        )
