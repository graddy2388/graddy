"""
viridis.web.api.export – Scan export endpoints (JSON, CSV, PDF).
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse

from ..db.crud import get_scan, get_scan_results, get_scans
from ..validation import MAX_EXPORT_LIMIT, clamp_limit


def _flatten_findings(scan: Dict, results: List[Dict]) -> List[Dict]:
    """Flatten results/findings into a flat list of rows for CSV."""
    rows = []
    for r in results:
        for f in r.get("findings") or []:
            rows.append({
                "scan_id": scan["id"],
                "scan_date": (scan.get("started_at") or "")[:19].replace("T", " "),
                "target_host": r["target_host"],
                "target_name": r.get("target_name") or r["target_host"],
                "check": r["check_name"],
                "severity": f.get("severity", ""),
                "title": f.get("title", ""),
                "description": f.get("description", ""),
                "recommendation": f.get("recommendation", ""),
            })
    return rows


def _build_pdf(scan: Dict, results: List[Dict]) -> bytes:
    """Generate a PDF report using reportlab."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        )

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=0.75*inch, rightMargin=0.75*inch)
        styles = getSampleStyleSheet()
        story = []

        sev_colors = {
            "critical": colors.HexColor("#ef4444"),
            "high": colors.HexColor("#f97316"),
            "medium": colors.HexColor("#eab308"),
            "low": colors.HexColor("#22c55e"),
            "info": colors.HexColor("#3b82f6"),
        }

        # Title
        story.append(Paragraph(f"Security Scan Report – Scan #{scan['id']}", styles["Title"]))
        story.append(Paragraph(
            f"Date: {(scan.get('started_at') or '')[:19].replace('T', ' ')}  |  "
            f"Status: {scan.get('status', '')}  |  "
            f"Targets: {scan.get('total_targets', 0)}",
            styles["Normal"],
        ))
        story.append(Spacer(1, 0.2*inch))

        # Summary table
        story.append(Paragraph("Severity Summary", styles["Heading2"]))
        summary_data = [
            ["Critical", "High", "Medium", "Low", "Info"],
            [
                str(scan.get("critical_count", 0)),
                str(scan.get("high_count", 0)),
                str(scan.get("medium_count", 0)),
                str(scan.get("low_count", 0)),
                str(scan.get("info_count", 0)),
            ],
        ]
        summary_table = Table(summary_data, colWidths=[1.2*inch]*5)
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), sev_colors["critical"]),
            ("BACKGROUND", (1, 0), (1, 0), sev_colors["high"]),
            ("BACKGROUND", (2, 0), (2, 0), sev_colors["medium"]),
            ("BACKGROUND", (3, 0), (3, 0), sev_colors["low"]),
            ("BACKGROUND", (4, 0), (4, 0), sev_colors["info"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))

        # Findings
        story.append(Paragraph("Findings", styles["Heading2"]))
        rows = _flatten_findings(scan, results)
        if rows:
            table_data = [["Target", "Check", "Sev", "Finding", "Recommendation"]]
            for row in rows:
                rec = (row["recommendation"] or "")[:80]
                if len(row.get("recommendation") or "") > 80:
                    rec += "..."
                table_data.append([
                    row["target_name"][:25],
                    row["check"][:15],
                    row["severity"].upper(),
                    row["title"][:50],
                    rec,
                ])
            t = Table(table_data, colWidths=[1.2*inch, 0.9*inch, 0.6*inch, 2.3*inch, 2.0*inch])
            ts = TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#6366f1")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
            # Colour severity column
            for i, row in enumerate(rows, start=1):
                sev = row["severity"].lower()
                c = sev_colors.get(sev, colors.grey)
                ts.add("TEXTCOLOR", (2, i), (2, i), c)
                ts.add("FONTNAME", (2, i), (2, i), "Helvetica-Bold")
            t.setStyle(ts)
            story.append(t)
        else:
            story.append(Paragraph("No findings recorded.", styles["Normal"]))

        doc.build(story)
        return buf.getvalue()

    except ImportError:
        raise HTTPException(status_code=501, detail="reportlab not installed – PDF export unavailable")


def make_router(get_db_dep) -> APIRouter:
    r = APIRouter(prefix="/api/export", tags=["export"])

    @r.get("/scans/{id}/json")
    def export_json(id: int, db=Depends(get_db_dep)):
        scan = get_scan(db, id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        results = get_scan_results(db, id)
        payload = json.dumps({**scan, "results": results}, indent=2)
        return Response(
            content=payload,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=scan_{id}.json"},
        )

    @r.get("/scans/{id}/csv")
    def export_csv(id: int, db=Depends(get_db_dep)):
        scan = get_scan(db, id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        results = get_scan_results(db, id)
        rows = _flatten_findings(scan, results)

        buf = io.StringIO()
        if rows:
            writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        else:
            buf.write("scan_id,scan_date,target_host,target_name,check,severity,title,description,recommendation\n")
            buf.write(f"{scan['id']},{(scan.get('started_at') or '')[:10]},,,,,No findings,,\n")

        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=scan_{id}.csv"},
        )

    @r.get("/scans/{id}/pdf")
    def export_pdf(id: int, db=Depends(get_db_dep)):
        scan = get_scan(db, id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        results = get_scan_results(db, id)
        pdf_bytes = _build_pdf(scan, results)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=scan_{id}.pdf"},
        )

    @r.get("/scans/all/json")
    def export_all_json(limit: int = 50, db=Depends(get_db_dep)):
        limit = clamp_limit(limit, default=50, cap=MAX_EXPORT_LIMIT)
        scans = get_scans(db, limit=limit)
        return Response(
            content=json.dumps({"scans": scans}, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=all_scans.json"},
        )

    return r
