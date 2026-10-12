"""
report_generator.py
---------------------
Turns a campaign's compliance findings (services/compliance_mapper.py)
into a downloadable report — the core academic differentiator (actionable
regulatory recommendations, not a generic awareness score) made into a
tangible artifact an admin can hand to a DPO/compliance team, rather than
only a dashboard page.

Two formats, same underlying data:
  - CSV: easiest to import into Excel/SPSS/Python for the evaluation
    study's own statistics (personalized vs generic comparison).
  - PDF: a presentable one-pager, suitable for attaching to an internal
    compliance record or including as an appendix artifact in the thesis.

Both take the exact same data campaign_detail() already assembles —
nothing here re-queries the database, so there's only one source of
truth for "what counts as a campaign's result."
"""

import csv
import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)

SEVERITY_COLORS = {
    "critical": colors.HexColor("#842029"),
    "high": colors.HexColor("#842029"),
    "medium": colors.HexColor("#997404"),
    "info": colors.HexColor("#0a3622"),
}


def _generated_at() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def build_csv_report(org_name: str, campaign: dict, counts: dict, findings: list, employee_rows: list,
                      attack_techniques: list = None) -> bytes:
    """
    employee_rows: [{'full_name', 'email', 'department', 'events': set-like
    of event_type strings}, ...] — already scoped to whatever the
    requesting admin is allowed to see (see admin.py's view-accessibility
    checks; a department admin's report only ever contains their own
    department's rows, exactly like the on-screen results page).

    attack_techniques (optional): the MITRE ATT&CK technique dicts this
    campaign demonstrates (services/attack_mapping.py) — grounds the
    report in a published, citable framework rather than only this
    platform's own compliance rules.
    """
    buf = io.StringIO()
    writer = csv.writer(buf)

    writer.writerow(["PhishSim Compliance Report"])
    writer.writerow(["Organization", org_name])
    writer.writerow(["Campaign", campaign["name"]])
    writer.writerow(["Condition", campaign["condition"]])
    writer.writerow(["Stage", "Stage 2 (real-world-informed)" if campaign["stage2_reference"] else "Stage 1"])
    writer.writerow(["Status", campaign["status"]])
    writer.writerow(["Created", campaign["created_at"]])
    writer.writerow(["Report generated", _generated_at()])
    writer.writerow([])

    if attack_techniques:
        writer.writerow(["MITRE ATT&CK techniques demonstrated"])
        writer.writerow(["Technique ID", "Name", "URL"])
        for t in attack_techniques:
            writer.writerow([t["id"], t["name"], t["url"]])
        writer.writerow([])

    writer.writerow(["Summary metrics"])
    writer.writerow(["Metric", "Count", "Rate"])
    total = max(counts.get("total", 0), 1)
    for label, key in [
        ("Recipients", "total"), ("Opened", "open"), ("Clicked", "click"),
        ("Submitted data", "submit"), ("Downloaded attachment", "download"),
        ("Reported as suspicious", "report"), ("Called (TOAD)", "called"),
    ]:
        count = counts.get(key, 0)
        rate = "100%" if key == "total" else f"{count / total:.0%}"
        writer.writerow([label, count, rate])
    writer.writerow([])

    writer.writerow(["Compliance findings"])
    writer.writerow(["Severity", "Regulation", "Finding", "Exact citations (jurisdiction | article | quoted text)",
                      "Organisational impact", "Recommendation"])
    for f in findings:
        citations_text = " || ".join(
            f"{c['jurisdiction']} | {c['article']} | {c['text']}" for c in f.get("citations", [])
        )
        writer.writerow([
            f["severity"].upper(), f["regulation"], f["finding"],
            citations_text, f.get("impact") or "", f["recommendation"],
        ])
    writer.writerow([])

    writer.writerow(["Per-employee interactions"])
    writer.writerow(["Full name", "Email", "Department", "Opened", "Clicked", "Submitted", "Downloaded", "Reported", "Called"])
    for row in employee_rows:
        events = row["events"]
        writer.writerow([
            row["full_name"], row["email"], row["department"] or "",
            "Yes" if "open" in events else "No",
            "Yes" if "click" in events else "No",
            "Yes" if "submit" in events else "No",
            "Yes" if "download" in events else "No",
            "Yes" if "report" in events else "No",
            "Yes" if "called" in events else "No",
        ])

    return buf.getvalue().encode("utf-8")


def build_roster_csv(rows: list) -> bytes:
    """
    rows: [{'full_name', 'email', 'department', 'job_title', 'campaigns',
    'risk_score', 'risk_tier', 'impact_weight'}, ...] — already scoped to
    whatever the requesting admin is allowed to see (see
    admin.export_employees_csv; a department admin's roster only ever
    contains their own department's employees, same pattern as
    build_csv_report's employee_rows). 'risk_score'/'risk_tier' are the
    final likelihood x impact figure (see
    compliance_mapper.compute_employee_overall_risk); 'impact_weight' is
    included as its own column so the multiplier behind that number is
    visible on the exported roster, not just the final score.
    """
    buf = io.StringIO()
    writer = csv.writer(buf)

    writer.writerow(["PhishSim Employee Roster"])
    writer.writerow(["Report generated", _generated_at()])
    writer.writerow([])
    writer.writerow(["Full name", "Email", "Department", "Job title", "Campaigns",
                      "Risk score", "Risk tier", "Dept. impact weight"])
    for row in rows:
        writer.writerow([
            row["full_name"], row["email"], row["department"] or "", row["job_title"] or "",
            row["campaigns"], row["risk_score"], row["risk_tier"],
            f"{row.get('impact_weight', 1.0):.1f}x",
        ])

    return buf.getvalue().encode("utf-8")


def build_pdf_report(org_name: str, campaign: dict, counts: dict, findings: list, employee_rows: list,
                      attack_techniques: list = None) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=20 * mm, bottomMargin=18 * mm, leftMargin=18 * mm, rightMargin=18 * mm,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=18, spaceAfter=4)
    meta_style = ParagraphStyle("Meta", parent=styles["Normal"], textColor=colors.HexColor("#555555"))
    h2_style = ParagraphStyle("H2", parent=styles["Heading2"], spaceBefore=14, spaceAfter=6)
    body_style = styles["BodyText"]

    story = []
    story.append(Paragraph("Compliance Report", title_style))
    story.append(Paragraph(
        f"{org_name} &middot; Campaign: {campaign['name']} &middot; "
        f"{'Stage 2 (real-world-informed)' if campaign['stage2_reference'] else 'Stage 1'}",
        meta_style,
    ))
    story.append(Paragraph(f"Generated {_generated_at()}", meta_style))
    story.append(Spacer(1, 10))

    # ---- MITRE ATT&CK techniques demonstrated ----
    if attack_techniques:
        story.append(Paragraph("MITRE ATT&CK Techniques Demonstrated", h2_style))
        attack_rows = [["Technique ID", "Name"]]
        for t in attack_techniques:
            attack_rows.append([t["id"], t["name"]])
        attack_table = Table(attack_rows, colWidths=[35 * mm, 95 * mm])
        attack_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14213D")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F7F5")]),
        ]))
        story.append(attack_table)
        story.append(Paragraph(
            "See https://attack.mitre.org/techniques/T1566/ for the full technique reference.",
            ParagraphStyle("Small", parent=body_style, fontSize=8, textColor=colors.HexColor("#777777")),
        ))
        story.append(Spacer(1, 6))

    # ---- Summary metrics table ----
    story.append(Paragraph("Summary Metrics", h2_style))
    total = max(counts.get("total", 0), 1)
    metric_rows = [["Metric", "Count", "Rate"]]
    for label, key in [
        ("Recipients", "total"), ("Opened", "open"), ("Clicked", "click"),
        ("Submitted data", "submit"), ("Downloaded attachment", "download"),
        ("Reported as suspicious", "report"), ("Called (TOAD)", "called"),
    ]:
        count = counts.get(key, 0)
        rate = "100%" if key == "total" else f"{count / total:.0%}"
        metric_rows.append([label, str(count), rate])
    metrics_table = Table(metric_rows, colWidths=[70 * mm, 30 * mm, 30 * mm])
    metrics_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14213D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F7F5")]),
    ]))
    story.append(metrics_table)

    # ---- Compliance findings ----
    story.append(Paragraph("Compliance Findings", h2_style))
    if not findings:
        story.append(Paragraph("No findings were triggered by this campaign's results.", body_style))
    citation_style = ParagraphStyle(
        "Citation", parent=body_style, fontSize=8.5, leftIndent=10,
        textColor=colors.HexColor("#444444"), spaceBefore=2, spaceAfter=2,
    )
    for f in findings:
        sev_color = SEVERITY_COLORS.get(f["severity"], colors.black)
        sev_style = ParagraphStyle(
            "Sev", parent=body_style, textColor=sev_color, fontName="Helvetica-Bold", fontSize=10,
        )
        story.append(Paragraph(f"{f['severity'].upper()} &mdash; {f['regulation']}", sev_style))
        story.append(Paragraph(f["finding"], body_style))
        for c in f.get("citations", []):
            story.append(Paragraph(
                f"<b>{c['jurisdiction']}</b> &mdash; {c['article']}: <i>{c['text']}</i>",
                citation_style,
            ))
        if f.get("impact"):
            story.append(Paragraph(f"<b>Organisational impact:</b> {f['impact']}", body_style))
        story.append(Paragraph(f"<b>Recommendation:</b> {f['recommendation']}", body_style))
        story.append(Spacer(1, 8))

    # ---- Per-employee table ----
    story.append(PageBreak())
    story.append(Paragraph("Per-Employee Interactions", h2_style))
    emp_rows = [["Name", "Department", "Open", "Click", "Submit", "DL", "Report", "Call"]]
    for row in employee_rows:
        events = row["events"]
        emp_rows.append([
            row["full_name"], row["department"] or "",
            "Y" if "open" in events else "",
            "Y" if "click" in events else "",
            "Y" if "submit" in events else "",
            "Y" if "download" in events else "",
            "Y" if "report" in events else "",
            "Y" if "called" in events else "",
        ])
    emp_table = Table(emp_rows, colWidths=[48 * mm, 30 * mm, 11 * mm, 11 * mm, 14 * mm, 9 * mm, 14 * mm, 11 * mm])
    emp_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14213D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F7F5")]),
    ]))
    story.append(emp_table)

    doc.build(story)
    return buf.getvalue()
