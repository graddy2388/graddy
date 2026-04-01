"""
network_bot.checks.sqlmap_check – SQL injection detection via sqlmap.

Runs at level=1, risk=1 (safest non-intrusive settings).
Falls back gracefully when sqlmap is not installed.
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile

from .base import BaseCheck, CheckResult, Finding, Severity

logger = logging.getLogger(__name__)


class SQLMapCheck(BaseCheck):
    @property
    def name(self) -> str:
        return "sqlmap"

    def run(self, target: dict) -> CheckResult:
        import shutil
        host = target["host"]

        if shutil.which("sqlmap") is None:
            return CheckResult(
                check_name=self.name, target=host, passed=True,
                error="sqlmap not installed",
                findings=[Finding(
                    title="sqlmap binary not found",
                    severity=Severity.INFO,
                    description="sqlmap is not installed on this system.",
                    recommendation="Install sqlmap: apt install sqlmap",
                )],
            )

        timeout = int(self.config.get("sqlmap", {}).get("timeout", 120))
        url = host if host.startswith(("http://", "https://")) else f"http://{host}/"

        output_dir = tempfile.mkdtemp(prefix="sqlmap_viridis_")
        cmd = [
            "sqlmap",
            "-u", url,
            "--batch",              # non-interactive
            "--level=1",            # basic crawl depth
            "--risk=1",             # safest test payloads
            "--forms",              # test discovered forms
            "--output-dir", output_dir,
            "--no-cast",
            "--disable-coloring",
        ]
        logger.info("Running sqlmap: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False,
            )
            output = proc.stdout + proc.stderr
        except subprocess.TimeoutExpired:
            return CheckResult(check_name=self.name, target=host, passed=False,
                               error=f"sqlmap timed out after {timeout}s")
        except Exception as exc:
            return CheckResult(check_name=self.name, target=host, passed=False, error=str(exc))
        finally:
            import shutil as sh
            try:
                sh.rmtree(output_dir, ignore_errors=True)
            except Exception:
                pass

        findings: list[Finding] = []

        if re.search(r"sqlmap identified the following injection point", output, re.IGNORECASE):
            params = re.findall(r"Parameter:\s+(\S+)\s+\(", output)
            params_str = ", ".join(params) if params else "unknown parameter(s)"
            db_match = re.search(r"back-end DBMS:\s+(.+)", output)
            db_type = db_match.group(1).strip() if db_match else "unknown"

            findings.append(Finding(
                title=f"SQL Injection found in parameter(s): {params_str}",
                severity=Severity.CRITICAL,
                description=(
                    f"sqlmap detected injectable parameter(s): {params_str}. "
                    f"Backend database identified as: {db_type}."
                ),
                recommendation=(
                    "Use parameterized queries / prepared statements exclusively. "
                    "Never concatenate user input into SQL strings. "
                    "Apply input validation at the application layer."
                ),
                details={"parameters": params, "dbms": db_type, "url": url},
            ))
        else:
            not_vuln_msg = re.search(
                r"all tested parameters do not appear to be injectable"
                r"|does not seem to be injectable",
                output, re.IGNORECASE,
            )
            findings.append(Finding(
                title="No SQL injection found by sqlmap",
                severity=Severity.INFO,
                description=(
                    "sqlmap found no SQL injection at level=1 risk=1. "
                    + ("sqlmap confirmed the target is not injectable at this level."
                       if not_vuln_msg else "Scan completed.")
                ),
                recommendation=(
                    "For deeper coverage run sqlmap manually with --level=3 --risk=2. "
                    "Also review stored procedures and ORM usage."
                ),
            ))

        passed = not any(f.severity == Severity.CRITICAL for f in findings)
        return CheckResult(
            check_name=self.name, target=host, passed=passed,
            findings=findings,
            metadata={"url": url},
        )
