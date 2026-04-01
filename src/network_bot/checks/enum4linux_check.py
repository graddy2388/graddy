"""
network_bot.checks.enum4linux_check – SMB/Samba enumeration via enum4linux.

Falls back gracefully when enum4linux is not installed.
"""
from __future__ import annotations

import logging
import re
import subprocess

from .base import BaseCheck, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)


class Enum4LinuxCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "enum4linux"

    def run(self, target: dict) -> CheckResult:
        import shutil
        host = target["host"]

        binary = shutil.which("enum4linux-ng") or shutil.which("enum4linux")
        if binary is None:
            return CheckResult(
                check_name=self.name, target=host, passed=True,
                error="enum4linux not installed",
                findings=[Finding(
                    title="enum4linux binary not found",
                    severity=Severity.INFO,
                    description="Neither enum4linux nor enum4linux-ng found on this system.",
                    recommendation="Install: apt install enum4linux",
                )],
            )

        timeout = int(self.config.get("enum4linux", {}).get("timeout", 120))
        cmd = [binary, "-a", host]
        logger.info("Running enum4linux: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False,
            )
            output = proc.stdout + proc.stderr
        except subprocess.TimeoutExpired:
            return CheckResult(check_name=self.name, target=host, passed=False,
                               error=f"enum4linux timed out after {timeout}s")
        except Exception as exc:
            return CheckResult(check_name=self.name, target=host, passed=False, error=str(exc))

        findings: list[Finding] = []
        users: list[str] = []
        shares: list[str] = []

        # Null session
        if re.search(r"null session", output, re.IGNORECASE):
            findings.append(Finding(
                title="SMB null session permitted",
                severity=Severity.HIGH,
                description=(
                    "The target allows unauthenticated (null session) SMB connections, "
                    "enabling anonymous enumeration of users, shares, and policies."
                ),
                recommendation=(
                    "Set RestrictAnonymous=2 in HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA. "
                    "Disable the 'Network access: Allow anonymous SID/Name translation' policy."
                ),
            ))

        # Users
        users = re.findall(r"user:\[(\S+?)\]\s+rid:\[", output)
        if users:
            findings.append(Finding(
                title=f"Enumerated {len(users)} user account(s) via null session",
                severity=Severity.MEDIUM,
                description=(
                    f"SMB null session allowed user enumeration. "
                    f"Accounts: {', '.join(users[:20])}"
                    f"{'…' if len(users) > 20 else ''}"
                ),
                recommendation=(
                    "Disable null session access. Restrict anonymous enumeration via "
                    "Group Policy: 'Network access: Do not allow anonymous enumeration of SAM accounts'."
                ),
                details={"users": users[:50]},
            ))

        # Shares
        share_matches = re.findall(
            r"^\s+(\S+)\s+(?:Disk|Printer|IPC)\s", output, re.MULTILINE,
        )
        shares = [s for s in share_matches if s not in ("Sharename", "Type")]
        if shares:
            findings.append(Finding(
                title=f"Enumerated {len(shares)} SMB share(s)",
                severity=Severity.LOW,
                description=f"Accessible shares: {', '.join(shares[:10])}",
                recommendation=(
                    "Audit share permissions. Remove world-readable or unnecessarily "
                    "exposed shares."
                ),
                details={"shares": shares},
            ))

        # Weak password policy
        min_len_match = re.search(r"Min password len:\s*(\d+)", output)
        if min_len_match:
            min_len = int(min_len_match.group(1))
            if min_len < 8:
                findings.append(Finding(
                    title=f"Weak password policy: minimum length {min_len}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"Domain password policy allows passwords as short as "
                        f"{min_len} character(s)."
                    ),
                    recommendation=(
                        "Configure minimum password length of at least 12 characters "
                        "in Group Policy → Account Policies → Password Policy."
                    ),
                    details={"min_password_length": min_len},
                ))

        if not findings:
            findings.append(Finding(
                title="No SMB enumeration findings",
                severity=Severity.INFO,
                description=(
                    "enum4linux did not find exploitable SMB information. "
                    "The host may not be a Windows/Samba system or SMB may be blocked."
                ),
                recommendation="Verify port 445 is open and SMB is running on the target.",
            ))

        passed = not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
        return CheckResult(
            check_name=self.name, target=host, passed=passed,
            findings=findings,
            metadata={"users": users[:50], "shares": shares},
        )
