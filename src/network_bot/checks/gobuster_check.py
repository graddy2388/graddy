"""
network_bot.checks.gobuster_check – Directory and path enumeration via gobuster.

Falls back gracefully when gobuster or wordlists are not installed.
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
from typing import List

from .base import BaseCheck, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)

_WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
]

# Paths that warrant elevated findings
_SENSITIVE: list[tuple[str, Severity, str, str]] = [
    (r"/\.git(/|$)",        Severity.HIGH,   "Git repository exposed",
     "Remove the .git directory from the webroot immediately."),
    (r"/\.env($|\?)",       Severity.HIGH,   ".env file exposed",
     "Move .env outside the webroot and restrict access."),
    (r"/phpmyadmin",        Severity.HIGH,   "phpMyAdmin interface exposed",
     "Restrict phpMyAdmin to localhost or VPN-only access."),
    (r"/adminer",           Severity.HIGH,   "Adminer DB interface exposed",
     "Restrict Adminer to localhost or remove it from production."),
    (r"/(admin|administrator)(/|$)", Severity.MEDIUM, "Admin panel discovered",
     "Restrict admin panel access via IP allowlist or VPN."),
    (r"/(backup|backups)(/|$)", Severity.MEDIUM, "Backup directory discovered",
     "Remove backups from the webroot and store offline."),
    (r"/(config|configuration)(/|$)", Severity.MEDIUM, "Config directory exposed",
     "Move configuration files outside the webroot."),
    (r"/wp-admin(/|$)",     Severity.MEDIUM, "WordPress admin panel found",
     "Restrict /wp-admin to known IP addresses."),
    (r"/\.htaccess($|\?)",  Severity.LOW,    ".htaccess file readable",
     "Block direct access to .htaccess via server config."),
    (r"/(api|v\d+)/",       Severity.LOW,    "API endpoint discovered",
     "Ensure API endpoints require authentication."),
]


class GobusterCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "gobuster"

    def run(self, target: dict) -> CheckResult:
        import shutil
        host = target["host"]

        if shutil.which("gobuster") is None:
            return CheckResult(
                check_name=self.name, target=host, passed=True,
                error="gobuster not installed",
                findings=[Finding(
                    title="gobuster binary not found",
                    severity=Severity.INFO,
                    description="gobuster is not installed on this system.",
                    recommendation="Install gobuster: apt install gobuster",
                )],
            )

        wordlist = next((w for w in _WORDLISTS if os.path.exists(w)), None)
        if wordlist is None:
            return CheckResult(
                check_name=self.name, target=host, passed=True,
                findings=[Finding(
                    title="No wordlist available for gobuster",
                    severity=Severity.INFO,
                    description="Could not find a wordlist. Install wordlists: apt install wordlists",
                    recommendation="Install the wordlists or dirb package.",
                )],
            )

        timeout = int(self.config.get("gobuster", {}).get("timeout", 120))
        url = host if host.startswith(("http://", "https://")) else f"http://{host}"

        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-q",
            "--no-error",
            "-t", "10",
            "-s", "200,204,301,302,307,401,403",
        ]
        logger.info("Running gobuster: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False,
            )
            output = proc.stdout
        except subprocess.TimeoutExpired:
            return CheckResult(check_name=self.name, target=host, passed=False,
                               error=f"gobuster timed out after {timeout}s")
        except Exception as exc:
            return CheckResult(check_name=self.name, target=host, passed=False, error=str(exc))

        discovered: list[dict] = []
        for line in output.splitlines():
            m = re.match(r"^(/\S*)\s+\(Status:\s*(\d+)\)", line.strip())
            if m:
                discovered.append({"path": m.group(1), "status": int(m.group(2))})

        findings: list[Finding] = []

        if discovered:
            findings.append(Finding(
                title=f"Discovered {len(discovered)} path(s) via directory scan",
                severity=Severity.INFO,
                description=(
                    f"gobuster found {len(discovered)} accessible path(s) on {url}."
                ),
                recommendation=(
                    "Review all discovered paths and ensure no sensitive content is accessible."
                ),
                details={"paths": [d["path"] for d in discovered[:50]]},
            ))

            flagged_titles: set[str] = set()
            for d in discovered:
                for pattern, sev, title, rec in _SENSITIVE:
                    if title not in flagged_titles and re.search(pattern, d["path"], re.IGNORECASE):
                        findings.append(Finding(
                            title=f"{title}: {d['path']}",
                            severity=sev,
                            description=(
                                f"Sensitive path accessible at {url}{d['path']} "
                                f"(HTTP {d['status']})"
                            ),
                            recommendation=rec,
                            details={"path": d["path"], "status": d["status"], "url": url},
                        ))
                        flagged_titles.add(title)
        else:
            findings.append(Finding(
                title="No paths discovered by gobuster",
                severity=Severity.INFO,
                description="gobuster found no accessible paths with the current wordlist.",
                recommendation="Try a larger wordlist or test the URL manually.",
            ))

        passed = not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
        return CheckResult(
            check_name=self.name, target=host, passed=passed,
            findings=findings,
            metadata={"discovered_paths": [d["path"] for d in discovered], "url": url},
        )
