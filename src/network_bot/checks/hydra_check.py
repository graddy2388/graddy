"""
network_bot.checks.hydra_check – Default-credential testing via Hydra.

Only tests a small built-in list of common default credentials
(admin/admin, root/root, etc.) against SSH and FTP by default.
This is intentionally conservative to avoid lockouts.
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile

from .base import BaseCheck, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)

# Minimal built-in list: vendor defaults only, not a full wordlist
_DEFAULT_CREDS = [
    ("admin",         "admin"),
    ("admin",         "password"),
    ("admin",         ""),
    ("admin",         "1234"),
    ("admin",         "admin123"),
    ("root",          "root"),
    ("root",          ""),
    ("root",          "toor"),
    ("root",          "password"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("guest",         "guest"),
    ("user",          "user"),
    ("test",          "test"),
    ("pi",            "raspberry"),
    ("cisco",         "cisco"),
    ("ubnt",          "ubnt"),
]


class HydraCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "hydra"

    def run(self, target: dict) -> CheckResult:
        import shutil
        host = target["host"]

        if shutil.which("hydra") is None:
            return CheckResult(
                check_name=self.name, target=host, passed=True,
                error="hydra not installed",
                findings=[Finding(
                    title="hydra binary not found",
                    severity=Severity.INFO,
                    description="hydra is not installed on this system.",
                    recommendation="Install hydra: apt install hydra",
                )],
            )

        timeout_per_svc = int(self.config.get("hydra", {}).get("timeout", 45))
        services: list[str] = list(
            self.config.get("hydra", {}).get("services", ["ssh", "ftp"])
        )

        # Write credentials to temp file
        cred_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False,
        )
        for user, passwd in _DEFAULT_CREDS:
            cred_file.write(f"{user}:{passwd}\n")
        cred_file.close()

        all_hits: list[dict] = []
        findings: list[Finding] = []

        try:
            for service in services:
                cmd = [
                    "hydra",
                    "-C", cred_file.name,   # combined user:pass file
                    "-t", "4",              # 4 threads max (conservative)
                    "-W", "3",              # 3 second wait between retries
                    "-I",                   # ignore restore
                    f"{service}://{host}",
                ]
                logger.info("Running hydra against %s://%s", service, host)

                try:
                    proc = subprocess.run(
                        cmd, capture_output=True, text=True,
                        timeout=timeout_per_svc, check=False,
                    )
                    output = proc.stdout + proc.stderr

                    hits = re.findall(
                        r"\[\d+\]\[(\w[\w-]*)\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s*(\S*)",
                        output,
                    )
                    for svc, login, password in hits:
                        display_pass = password if password else "(empty)"
                        all_hits.append({"service": svc, "login": login, "password": display_pass})
                        findings.append(Finding(
                            title=f"Default credentials accepted: {svc} — {login}:{display_pass}",
                            severity=Severity.CRITICAL,
                            description=(
                                f"Hydra found valid default credentials on {svc} "
                                f"service: username '{login}', password '{display_pass}'."
                            ),
                            recommendation=(
                                "Change default credentials immediately. "
                                "Enforce a strong password policy and consider disabling "
                                f"{svc} access from untrusted networks."
                            ),
                            details={
                                "service": svc, "login": login,
                                "password": display_pass, "host": host,
                            },
                        ))

                except subprocess.TimeoutExpired:
                    logger.warning("hydra timed out for service %s on %s", service, host)
                except Exception as exc:
                    logger.warning("hydra error for %s on %s: %s", service, host, exc)
        finally:
            try:
                os.unlink(cred_file.name)
            except OSError:
                pass

        if not all_hits:
            findings.append(Finding(
                title="No default credentials accepted",
                severity=Severity.INFO,
                description=(
                    f"Hydra found no default credentials on tested service(s): "
                    f"{', '.join(services)}."
                ),
                recommendation="Continue enforcing strong password policies and MFA where possible.",
            ))

        passed = len(all_hits) == 0
        return CheckResult(
            check_name=self.name, target=host, passed=passed,
            findings=findings,
            metadata={"hits": all_hits, "services_tested": services},
        )
