import json
import logging
import os
import re
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, BaseLoader

from ..checks.base import CheckResult, Finding, Severity

logger = logging.getLogger(__name__)

# Severity sort order (highest first)
SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#65a30d",
    "info": "#2563eb",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Network Security Report – {{ timestamp }}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           background: #0f172a; color: #e2e8f0; line-height: 1.6; }
    a { color: #60a5fa; }
    .container { max-width: 1200px; margin: 0 auto; padding: 2rem 1rem; }

    /* Header */
    .header { background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%);
               border-bottom: 2px solid #334155; padding: 2rem 0; margin-bottom: 2rem; }
    .header h1 { font-size: 2rem; font-weight: 700; color: #f8fafc; }
    .header .meta { font-size: 0.875rem; color: #94a3b8; margin-top: 0.5rem; }

    /* Summary cards */
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                    gap: 1rem; margin-bottom: 2rem; }
    .card { background: #1e293b; border-radius: 0.75rem; padding: 1.25rem; text-align: center;
            border: 1px solid #334155; }
    .card-count { font-size: 2.5rem; font-weight: 800; }
    .card-label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.1em;
                  color: #94a3b8; margin-top: 0.25rem; }
    .badge { display: inline-block; padding: 0.2em 0.65em; border-radius: 9999px;
             font-size: 0.75rem; font-weight: 600; text-transform: uppercase;
             letter-spacing: 0.05em; }
    .badge-critical { background: #7f1d1d; color: #fca5a5; }
    .badge-high     { background: #7c2d12; color: #fdba74; }
    .badge-medium   { background: #78350f; color: #fcd34d; }
    .badge-low      { background: #365314; color: #86efac; }
    .badge-info     { background: #1e3a5f; color: #93c5fd; }

    /* Targets */
    .target-card { background: #1e293b; border: 1px solid #334155; border-radius: 0.75rem;
                   margin-bottom: 1.5rem; overflow: hidden; }
    .target-header { display: flex; justify-content: space-between; align-items: center;
                     padding: 1rem 1.5rem; background: #162032; border-bottom: 1px solid #334155;
                     cursor: pointer; }
    .target-title { font-size: 1.1rem; font-weight: 600; color: #f8fafc; }
    .target-host  { font-size: 0.85rem; color: #94a3b8; font-family: monospace; }
    .target-status-pass { color: #4ade80; font-weight: 600; }
    .target-status-fail { color: #f87171; font-weight: 600; }
    .target-body  { padding: 1.25rem 1.5rem; }

    /* Check sections */
    .check-section { margin-bottom: 1rem; }
    .check-title { font-weight: 600; color: #cbd5e1; margin-bottom: 0.5rem;
                   font-size: 0.95rem; border-left: 3px solid #475569; padding-left: 0.5rem; }
    .finding { background: #0f172a; border: 1px solid #1e293b; border-radius: 0.5rem;
               padding: 0.75rem 1rem; margin-bottom: 0.5rem; }
    .finding-title { display: flex; align-items: center; gap: 0.5rem; font-weight: 500; }
    .finding-desc  { font-size: 0.875rem; color: #94a3b8; margin-top: 0.35rem; }
    .finding-rec   { font-size: 0.85rem; color: #60a5fa; margin-top: 0.35rem;
                     border-left: 2px solid #2563eb; padding-left: 0.5rem; }

    /* Error */
    .error-box { background: #450a0a; border: 1px solid #7f1d1d; border-radius: 0.5rem;
                 padding: 0.75rem 1rem; color: #fca5a5; font-size: 0.875rem; }

    /* Stats bar */
    .stats-row { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1rem; }

    /* Collapsible details */
    details summary { cursor: pointer; }
    details summary::-webkit-details-marker { display: none; }
    .toggle-icon { font-size: 0.75rem; transition: transform 0.2s; }
    details[open] .toggle-icon { transform: rotate(90deg); }

    /* Footer */
    .footer { text-align: center; padding: 2rem 0; color: #475569; font-size: 0.8rem; }

    @media (max-width: 600px) {
      .target-header { flex-direction: column; align-items: flex-start; gap: 0.5rem; }
    }
  </style>
</head>
<body>

<div class="header">
  <div class="container">
    <h1>&#128737; Network Security Report</h1>
    <p class="meta">
      Generated: {{ timestamp }} &nbsp;|&nbsp;
      Targets scanned: {{ targets | length }} &nbsp;|&nbsp;
      Total findings: {{ total_findings }}
    </p>
  </div>
</div>

<div class="container">

  <!-- Summary Dashboard -->
  <div class="summary-grid">
    {% for sev, count in severity_counts.items() %}
    <div class="card">
      <div class="card-count" style="color: {{ severity_color(sev) }};">{{ count }}</div>
      <div class="card-label"><span class="badge badge-{{ sev }}">{{ sev }}</span></div>
    </div>
    {% endfor %}
    <div class="card">
      <div class="card-count" style="color: #4ade80;">{{ pass_count }}</div>
      <div class="card-label" style="color:#4ade80;">Checks Passed</div>
    </div>
    <div class="card">
      <div class="card-count" style="color: #f87171;">{{ fail_count }}</div>
      <div class="card-label" style="color:#f87171;">Checks Failed</div>
    </div>
  </div>

  <!-- Target Results -->
  {% for target_result in targets %}
  <div class="target-card">
    <div class="target-header">
      <div>
        <div class="target-title">{{ target_result.name }}</div>
        <div class="target-host">{{ target_result.host }}</div>
      </div>
      <div>
        {% if target_result.all_passed %}
          <span class="target-status-pass">&#10003; All checks passed</span>
        {% else %}
          <span class="target-status-fail">&#10007; Issues found</span>
        {% endif %}
        &nbsp;
        <div class="stats-row" style="margin: 0.25rem 0 0;">
          {% for sev, cnt in target_result.severity_counts.items() if cnt > 0 %}
            <span class="badge badge-{{ sev }}">{{ sev }} {{ cnt }}</span>
          {% endfor %}
        </div>
      </div>
    </div>
    <div class="target-body">
      {% for check in target_result.checks %}
      <div class="check-section">
        <div class="check-title">
          {{ check.check_name | upper }}
          {% if check.passed %}<span style="color:#4ade80;"> &#10003;</span>
          {% else %}<span style="color:#f87171;"> &#10007;</span>{% endif %}
          {% if check.error %}&#9888;{% endif %}
        </div>

        {% if check.error %}
        <div class="error-box">Error: {{ check.error }}</div>
        {% endif %}

        {% for finding in check.findings | sort_findings %}
        <details>
          <summary>
            <div class="finding">
              <div class="finding-title">
                <span class="toggle-icon">&#9658;</span>
                <span class="badge badge-{{ finding.severity }}">{{ finding.severity }}</span>
                {{ finding.title }}
              </div>
            </div>
          </summary>
          <div style="padding: 0 0 0.5rem 1.5rem;">
            <div class="finding">
              <div class="finding-desc">{{ finding.description }}</div>
              {% if finding.recommendation %}
              <div class="finding-rec">
                <strong>Recommendation:</strong> {{ finding.recommendation }}
              </div>
              {% endif %}
              {% if finding.details %}
              <details style="margin-top: 0.5rem;">
                <summary style="font-size:0.8rem; color:#64748b; cursor:pointer;">Technical details</summary>
                <pre style="font-size:0.75rem; color:#94a3b8; margin-top:0.35rem; overflow:auto;
                            background:#0f172a; padding:0.5rem; border-radius:0.375rem;">{{ finding.details | tojson(indent=2) }}</pre>
              </details>
              {% endif %}
            </div>
          </div>
        </details>
        {% endfor %}
      </div>
      {% endfor %}
    </div>
  </div>
  {% endfor %}

</div>

<div class="footer">
  <p>Viridis Security Scanner &mdash; Report generated at {{ timestamp }}</p>
</div>

</body>
</html>
"""


def _severity_value(sev_str: str) -> int:
    mapping = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return mapping.get(sev_str.lower(), 99)


def _finding_to_dict(finding: Finding) -> Dict[str, Any]:
    return {
        "title": finding.title,
        "severity": finding.severity.value,
        "description": finding.description,
        "recommendation": finding.recommendation,
        "details": finding.details,
    }


def _result_to_dict(result: CheckResult) -> Dict[str, Any]:
    return {
        "check_name": result.check_name,
        "target": result.target,
        "passed": result.passed,
        "findings": [_finding_to_dict(f) for f in result.findings],
        "metadata": result.metadata,
        "error": result.error,
        "timestamp": result.timestamp,
    }


class ReportGenerator:
    """Generates JSON and HTML security reports from check results."""

    def __init__(self, config: Dict[str, Any]) -> None:
        self._config = config
        reporting_cfg = config.get("reporting", {})
        self._output_dir = Path(reporting_cfg.get("output_dir", "reports"))
        self._formats: List[str] = reporting_cfg.get("formats", ["json", "html"])
        self._keep_last: int = int(reporting_cfg.get("keep_last", 10))
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        results: List[CheckResult],
        targets: List[Dict[str, Any]],
        run_timestamp: Optional[str] = None,
    ) -> Dict[str, Path]:
        """Generate reports in configured formats.

        Args:
            results: All check results from this run.
            targets: Original target configuration list.
            run_timestamp: ISO timestamp string; defaults to now.

        Returns:
            Dict mapping format name to output Path.
        """
        if run_timestamp is None:
            run_timestamp = datetime.now(timezone.utc).isoformat()

        # Build a clean timestamp for filenames
        safe_ts = re.sub(r"[:\\.+]", "-", run_timestamp)[:19]

        report_data = self._build_report_data(results, targets, run_timestamp)
        output_paths: Dict[str, Path] = {}

        if "json" in self._formats:
            json_path = self._output_dir / f"report_{safe_ts}.json"
            self._write_json(report_data, json_path)
            output_paths["json"] = json_path
            logger.info("JSON report written to %s", json_path)

        if "html" in self._formats:
            html_path = self._output_dir / f"report_{safe_ts}.html"
            self._write_html(report_data, html_path)
            output_paths["html"] = html_path
            logger.info("HTML report written to %s", html_path)

        self._prune_old_reports()
        return output_paths

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_report_data(
        self,
        results: List[CheckResult],
        targets: List[Dict[str, Any]],
        timestamp: str,
    ) -> Dict[str, Any]:
        """Build a unified report data structure."""
        # Group results by target host
        by_host: Dict[str, List[CheckResult]] = {}
        for r in results:
            by_host.setdefault(r.target, []).append(r)

        # Compute aggregate severity counts
        severity_counts: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        total_findings = 0
        pass_count = 0
        fail_count = 0

        target_reports = []
        for tgt in targets:
            host = tgt["host"]
            name = tgt.get("name", host)
            checks = by_host.get(host, [])

            tgt_sev: Dict[str, int] = {
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
            }
            all_passed = True
            check_dicts = []

            for result in checks:
                check_dict = _result_to_dict(result)
                check_dicts.append(check_dict)
                if not result.passed:
                    all_passed = False
                    fail_count += 1
                else:
                    pass_count += 1
                for finding in result.findings:
                    sev = finding.severity.value
                    tgt_sev[sev] = tgt_sev.get(sev, 0) + 1
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                    total_findings += 1

            target_reports.append({
                "name": name,
                "host": host,
                "checks": check_dicts,
                "severity_counts": tgt_sev,
                "all_passed": all_passed,
            })

        return {
            "timestamp": timestamp,
            "targets": target_reports,
            "severity_counts": severity_counts,
            "total_findings": total_findings,
            "pass_count": pass_count,
            "fail_count": fail_count,
        }

    def _write_json(self, data: Dict[str, Any], path: Path) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def _write_html(self, data: Dict[str, Any], path: Path) -> None:
        env = Environment(loader=BaseLoader(), autoescape=True)

        # Custom filters
        def sort_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
            return sorted(findings, key=lambda f: _severity_value(f.get("severity", "info")))

        def tojson_filter(value: Any, indent: int = 0) -> str:
            return json.dumps(value, indent=indent if indent else None, default=str)

        env.filters["sort_findings"] = sort_findings
        env.filters["tojson"] = tojson_filter

        def severity_color(sev: str) -> str:
            return SEVERITY_COLORS.get(sev.lower(), "#94a3b8")

        template = env.from_string(HTML_TEMPLATE)
        html = template.render(**data, severity_color=severity_color)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def _prune_old_reports(self) -> None:
        """Remove oldest reports exceeding keep_last limit."""
        for ext in ("json", "html"):
            files = sorted(
                self._output_dir.glob(f"report_*.{ext}"),
                key=lambda p: p.stat().st_mtime,
            )
            while len(files) > self._keep_last:
                oldest = files.pop(0)
                try:
                    oldest.unlink()
                    logger.debug("Pruned old report: %s", oldest)
                except OSError as exc:
                    logger.warning("Could not delete old report %s: %s", oldest, exc)
