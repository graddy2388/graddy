import logging
from typing import List, Optional, Tuple
from urllib.parse import urljoin

import requests
from requests.exceptions import RequestException

from .base import BaseCheck, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)

SENSITIVE_PATHS: List[Tuple[str, Severity, str]] = [
    ("/.env",                        Severity.CRITICAL, "Environment file exposed"),
    ("/.env.backup",                 Severity.CRITICAL, "Environment backup file exposed"),
    ("/.git/HEAD",                   Severity.CRITICAL, "Git repository exposed"),
    ("/.git/config",                 Severity.CRITICAL, "Git config exposed"),
    ("/.svn/entries",                Severity.HIGH,     "SVN repository exposed"),
    ("/phpinfo.php",                 Severity.HIGH,     "PHP info page exposed"),
    ("/info.php",                    Severity.HIGH,     "PHP info page exposed"),
    ("/.htaccess",                   Severity.HIGH,     "Apache config exposed"),
    ("/web.config",                  Severity.HIGH,     "IIS config exposed"),
    ("/config.php",                  Severity.HIGH,     "Config file exposed"),
    ("/wp-config.php",               Severity.CRITICAL, "WordPress config exposed"),
    ("/config/database.yml",         Severity.HIGH,     "Database config exposed"),
    ("/server-status",               Severity.MEDIUM,   "Apache server-status exposed"),
    ("/server-info",                 Severity.MEDIUM,   "Apache server-info exposed"),
    ("/admin",                       Severity.MEDIUM,   "Admin panel exposed"),
    ("/admin/",                      Severity.MEDIUM,   "Admin panel exposed"),
    ("/wp-admin/",                   Severity.MEDIUM,   "WordPress admin exposed"),
    ("/phpmyadmin/",                 Severity.HIGH,     "phpMyAdmin exposed"),
    ("/adminer.php",                 Severity.HIGH,     "Adminer DB admin exposed"),
    ("/.DS_Store",                   Severity.LOW,      "macOS DS_Store file exposed"),
    ("/robots.txt",                  Severity.INFO,     "Robots.txt found"),
    ("/.well-known/security.txt",    Severity.INFO,     "Security.txt present"),
    ("/backup.sql",                  Severity.CRITICAL, "SQL backup exposed"),
    ("/dump.sql",                    Severity.CRITICAL, "SQL dump exposed"),
    ("/backup.zip",                  Severity.CRITICAL, "Backup archive exposed"),
    ("/backup.tar.gz",               Severity.CRITICAL, "Backup archive exposed"),
    ("/crossdomain.xml",             Severity.MEDIUM,   "Flash crossdomain policy exposed"),
]


def _parse_robots_disallow(body: str) -> List[str]:
    """Extract Disallow paths from robots.txt content."""
    admin_paths = []
    for line in body.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and any(
                keyword in path.lower()
                for keyword in ("admin", "login", "panel", "manage", "dashboard", "private", "secret")
            ):
                admin_paths.append(path)
    return admin_paths


class ExposedPathsCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "exposed_paths"

    def run(self, target: dict) -> CheckResult:
        host = target["host"]
        ports: List[int] = target.get("ports", [80, 443])
        ep_config = self.config.get("exposed_paths", {})
        timeout = int(ep_config.get("timeout", 5))
        max_paths = int(ep_config.get("max_paths", 50))

        # Determine scheme: use HTTPS if port 443 is in target ports
        use_https = 443 in ports or 8443 in ports
        scheme = "https" if use_https else "http"
        base_url = f"{scheme}://{host}"

        findings: List[Finding] = []
        paths_to_check = SENSITIVE_PATHS[:max_paths]

        session = requests.Session()
        session.headers["User-Agent"] = "Viridis/2.0 Security Scanner"

        for path, severity, title in paths_to_check:
            url = base_url + path
            try:
                resp = session.get(url, timeout=timeout, verify=False, allow_redirects=False)
            except RequestException as exc:
                logger.debug("ExposedPathsCheck: error fetching %s: %s", url, exc)
                continue

            status = resp.status_code

            if status == 200:
                if path == "/robots.txt":
                    # Always add INFO finding for robots.txt
                    findings.append(
                        Finding(
                            title=title,
                            severity=severity,
                            description=f"robots.txt is publicly accessible at {url}",
                            details={"url": url, "status_code": status},
                        )
                    )
                    # Check for admin-revealing Disallow entries
                    admin_paths = _parse_robots_disallow(resp.text)
                    if admin_paths:
                        findings.append(
                            Finding(
                                title="robots.txt reveals admin/private paths",
                                severity=Severity.LOW,
                                description=(
                                    f"robots.txt at {host} contains Disallow entries that reveal "
                                    f"sensitive paths: {', '.join(admin_paths)}"
                                ),
                                recommendation=(
                                    "Avoid listing sensitive admin paths in robots.txt. "
                                    "Protect them with authentication instead."
                                ),
                                details={"url": url, "admin_paths": admin_paths},
                            )
                        )
                elif path == "/.well-known/security.txt":
                    findings.append(
                        Finding(
                            title=title,
                            severity=severity,
                            description=(
                                f"security.txt is present at {url}. "
                                "A security contact is configured — this is a positive finding."
                            ),
                            details={"url": url, "status_code": status},
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            title=title,
                            severity=severity,
                            description=(
                                f"Sensitive path '{path}' returned HTTP 200 at {url}. "
                                "This file/directory should not be publicly accessible."
                            ),
                            recommendation=(
                                f"Restrict access to '{path}' or remove it from the web root. "
                                "Ensure server configuration blocks access to sensitive files."
                            ),
                            details={"url": url, "status_code": status, "path": path},
                        )
                    )
            elif status == 403:
                # Path exists but is protected — informational only
                findings.append(
                    Finding(
                        title=f"Path exists but is access-protected: {path}",
                        severity=Severity.INFO,
                        description=(
                            f"'{path}' returned HTTP 403 at {url}. "
                            "The path exists on the server but access is denied."
                        ),
                        details={"url": url, "status_code": status, "path": path},
                    )
                )
            # 404 or other statuses: skip (not present)

        passed = not any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)

        return CheckResult(
            check_name=self.name,
            target=host,
            passed=passed,
            findings=findings,
            metadata={"base_url": base_url, "paths_checked": len(paths_to_check)},
        )
