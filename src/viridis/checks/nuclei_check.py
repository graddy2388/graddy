"""
viridis.checks.nuclei_check – Nuclei template-based vulnerability scanner.

Falls back gracefully when nuclei is not installed.
"""
from __future__ import annotations

import json
import logging
import subprocess

from .base import BaseCheck, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)

_SEV_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFO,
    "unknown":  Severity.LOW,
}


class NucleiCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "nuclei"

    def run(self, target: dict) -> CheckResult:
        import shutil
        host = target["host"]

        if shutil.which("nuclei") is None:
            return CheckResult(
                check_name=self.name, target=host, passed=True,
                error="nuclei not installed",
                findings=[Finding(
                    title="nuclei binary not found",
                    severity=Severity.INFO,
                    description="nuclei is not installed on this system.",
                    recommendation=(
                        "Install nuclei: go install "
                        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
                    ),
                )],
            )

        timeout = int(self.config.get("nuclei", {}).get("timeout", 180))
        severity = self.config.get("nuclei", {}).get("severity", "critical,high,medium")

        target_url = host if host.startswith(("http://", "https://")) else f"http://{host}"

        cmd = [
            "nuclei",
            "-target", target_url,
            "-severity", severity,
            "-silent",
            "-json",
            "-no-color",
            "-timeout", "10",
        ]
        logger.info("Running nuclei: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            return CheckResult(check_name=self.name, target=host, passed=False,
                               error=f"nuclei timed out after {timeout}s")
        except Exception as exc:
            return CheckResult(check_name=self.name, target=host, passed=False, error=str(exc))

        findings: list[Finding] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = item.get("info", {})
            sev_str = (info.get("severity") or "info").lower()
            sev = _SEV_MAP.get(sev_str, Severity.INFO)
            name = info.get("name") or item.get("template-id", "Unknown")
            matched = item.get("matched-at", target_url)
            description = info.get("description", "")
            remediation = info.get("remediation", "Review and remediate the finding.")

            findings.append(Finding(
                title=name,
                severity=sev,
                description=(
                    description
                    or f"Nuclei template '{item.get('template-id','')}' matched at {matched}"
                ),
                recommendation=remediation,
                details={
                    "template_id": item.get("template-id", ""),
                    "matched_at":  matched,
                    "tags":        info.get("tags", []),
                },
            ))

        if not findings:
            findings.append(Finding(
                title="No vulnerabilities found by nuclei",
                severity=Severity.INFO,
                description="Nuclei found no matching templates for the configured severity levels.",
                recommendation=(
                    "Consider expanding the severity scope or updating nuclei templates: "
                    "nuclei -update-templates"
                ),
            ))

        passed = not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
        return CheckResult(
            check_name=self.name, target=host, passed=passed,
            findings=findings,
            metadata={"target_url": target_url, "finding_count": len(findings)},
        )
