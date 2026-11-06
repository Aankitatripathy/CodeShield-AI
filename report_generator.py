
import html
import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle,
)
from reportlab.lib.utils import simpleSplit
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Preformatted,
    HRFlowable,
    KeepTogether,
)


SEVERITIES = ["Critical", "High", "Medium", "Low"]


def get_related_lines(finding):
    """Return all reported line numbers as readable text."""
    related = finding.get("RelatedLines")

    if isinstance(related, (list, tuple)) and related:
        return ", ".join(str(number) for number in related)

    return str(finding.get("Line", ""))


def get_secure_code(finding):
    """Read a suggested secure code example, if available."""
    value = finding.get("SecureCode", "")
    return str(value).strip() if value else ""


def generate_html_report(filename, scanned_files, findings):
    """Generate a standalone HTML security report."""

    findings = findings or []

    counts = {
        level: sum(
            f.get("Severity") == level
            for f in findings
        )
        for level in SEVERITIES
    }

    def safe(value):
        return html.escape(str(value), quote=True)

    sections = []

    for index, finding in enumerate(findings, start=1):
        name = safe(
            finding.get("Vulnerability", "Security issue")
        )
        severity = safe(
            finding.get("Severity", "Unknown")
        )
        path = safe(finding.get("File", ""))
        line = safe(get_related_lines(finding))
        detection = safe(finding.get("Detection", ""))

        evidence = safe(
            finding.get("CodeContext")
            or finding.get("Evidence", "")
        )

        description = safe(
            finding.get("Description", "")
        )
        fix = safe(finding.get("Fix", ""))

        secure_code = get_secure_code(finding)

        secure_section = ""

        if secure_code:
            secure_section = f"""
            <div class="secure-fix">
                <h3>Suggested Secure Code Example</h3>
                <pre><code>{safe(secure_code)}</code></pre>
                <p class="code-note">
                    Example only. Adapt and test this fix
                    against the application's actual code,
                    database schema, and authorization rules.
                </p>
            </div>
            """

        sections.append(f"""
        <section class="finding">
            <h2>{index}. {name}</h2>

            <div class="finding-meta">
                <p><strong>Severity:</strong> {severity}</p>
                <p><strong>File:</strong> {path}</p>
                <p><strong>Line(s):</strong> {line}</p>
                <p><strong>Detection:</strong> {detection}</p>
            </div>

            <h3>Source Code Evidence</h3>
            <pre><code>{evidence}</code></pre>

            <h3>Root Cause / Description</h3>
            <p>{description}</p>

            <h3>Recommended Secure Fix</h3>
            <p>{fix}</p>

            {secure_section}
        </section>
        """)

    summary = "".join(
        f"<span>{safe(level)}: {count}</span>"
        for level, count in counts.items()
    )

    generated = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>CodeShield AI Security Assessment</title>

<style>
body {{
    font-family: Arial, sans-serif;
    background: #f5f7fb;
    color: #1d2939;
    margin: 0;
    line-height: 1.6;
}}

header {{
    background: #14263e;
    color: white;
    padding: 36px 8%;
}}

header h2 {{
    color: white;
}}

main {{
    max-width: 1000px;
    margin: 30px auto;
    padding: 0 20px;
}}

.summary, .finding {{
    background: white;
    border: 1px solid #e1e5ed;
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 22px;
}}

.summary span {{
    display: inline-block;
    margin: 8px 14px 8px 0;
    font-weight: bold;
}}

.finding {{
    border-left: 5px solid #cc4052;
}}

.finding-meta {{
    overflow-wrap: anywhere;
}}

h2 {{
    color: #172c48;
}}

h3 {{
    color: #243b53;
    margin-top: 22px;
}}

pre {{
    background: #101c2d;
    color: #e6edf5;
    padding: 16px;
    overflow-x: auto;
    border-radius: 8px;
    font-size: 12px;
    line-height: 1.6;
    white-space: pre;
    tab-size: 4;
}}

.secure-fix {{
    margin-top: 24px;
    padding-top: 12px;
    border-top: 1px solid #d0d5dd;
}}

.secure-fix h3 {{
    color: #087443;
}}

.secure-fix pre {{
    background: #102a24;
    color: #e4f6e9;
    border-left: 4px solid #12a66a;
}}

.code-note {{
    color: #667085;
    font-size: 12px;
    line-height: 1.6;
}}

footer {{
    text-align: center;
    padding: 25px;
    color: #667085;
}}

@media print {{
    body {{
        background: white;
    }}

    header {{
        padding: 20px;
    }}

    .summary, .finding {{
        box-shadow: none;
        break-inside: auto;
    }}

    pre {{
        white-space: pre-wrap;
        overflow-wrap: anywhere;
    }}
}}
</style>
</head>

<body>
<header>
    <h1>CodeShield AI</h1>
    <h2>Security Assessment Report</h2>
    <p>Generated: {generated}</p>
</header>

<main>
    <section class="summary">
        <h2>Executive Summary</h2>

        <p>
            <strong>Application:</strong>
            {safe(filename)}
        </p>

        <p>
            <strong>Files scanned:</strong>
            {scanned_files}
        </p>

        <p>
            <strong>Potential findings:</strong>
            {len(findings)}
        </p>

        <div>{summary}</div>

        <p>
            All findings require manual verification.
        </p>
    </section>

    <h2>Detailed Security Findings</h2>

    {''.join(sections) if sections else '<p>No potential findings identified.</p>'}

    <section class="summary">
        <h2>Assessment Limitations</h2>
        <p>
            Static analysis and AI review may produce
            false positives or miss vulnerabilities.
            Suggested code examples require developer
            review, adaptation, and testing.
        </p>
    </section>
</main>

<footer>
    CodeShield AI | CDF CyberSec Hackathon
</footer>
</body>
</html>"""


def generate_pdf_report(filename, scanned_files, findings):
    """Generate a PDF security report and return its bytes."""

    findings = findings or []

    buffer = io.BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=(612, 792),
        rightMargin=42,
        leftMargin=42,
        topMargin=42,
        bottomMargin=42,
    )

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="CodeShieldTitle",
        parent=styles["Title"],
        fontSize=19,
        leading=24,
        textColor=colors.HexColor("#14263e"),
        alignment=TA_CENTER,
        spaceAfter=16,
    ))

    styles.add(ParagraphStyle(
        name="CodeShieldFinding",
        parent=styles["Heading2"],
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#b4233a"),
        spaceBefore=16,
        spaceAfter=8,
        wordWrap="CJK",
    ))

    styles.add(ParagraphStyle(
        name="CodeShieldBody",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        spaceAfter=6,
        wordWrap="CJK",
    ))

    styles.add(ParagraphStyle(
        name="CodeShieldCode",
        fontName="Courier",
        fontSize=7,
        leading=10,
        textColor=colors.HexColor("#243247"),
        spaceAfter=0,
    ))

    styles.add(ParagraphStyle(
        name="CodeShieldSecureCode",
        fontName="Courier",
        fontSize=7,
        leading=10,
        textColor=colors.HexColor("#087443"),
        spaceAfter=0,
    ))

    styles.add(ParagraphStyle(
        name="CodeShieldNote",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#667085"),
        spaceAfter=10,
    ))

    styles.add(ParagraphStyle(
        name="CodeShieldSecureHeading",
        parent=styles["Heading4"],
        textColor=colors.HexColor("#087443"),
        spaceBefore=12,
        spaceAfter=8,
    ))

    story = []

    def paragraph(value, style="CodeShieldBody"):
        return Paragraph(
            html.escape(str(value)),
            styles[style],
        )

    def add_code_block(code, secure=False, heading=None):
        """Wrap long code lines and keep a secure heading with its code."""
        code_style = (
            styles["CodeShieldSecureCode"]
            if secure else styles["CodeShieldCode"]
        )
        code_flowables = []

        for code_line in str(code).splitlines():
            normalized = code_line.replace("\t", "    ")
            wrapped_lines = simpleSplit(
                normalized,
                "Courier",
                7,
                510,
            )

            for wrapped_line in wrapped_lines or [""]:
                code_flowables.append(
                    Preformatted(
                        wrapped_line,
                        code_style,
                        maxLineLength=100,
                    )
                )

        if heading is not None:
            # Keep the heading with the first six code lines.
            opening = [
                Paragraph(
                    heading,
                    styles["CodeShieldSecureHeading"],
                ),
                paragraph(
                    "Illustrative replacement code.",
                    "CodeShieldNote",
                ),
            ]

            opening.extend(code_flowables[:6])
            story.append(KeepTogether(opening))
            story.extend(code_flowables[6:])
        else:
            story.extend(code_flowables)

    def add_page_number(canvas, doc):
        canvas.saveState()

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(
            colors.HexColor("#667085")
        )

        canvas.drawRightString(
            570,
            24,
            f"Page {doc.page}",
        )

        canvas.restoreState()

    story.append(Paragraph(
        "CodeShield AI Security Assessment",
        styles["CodeShieldTitle"],
    ))

    story.append(paragraph(
        "Generated: " +
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    ))

    story.append(Spacer(1, 12))

    story.append(Paragraph(
        "Executive Summary",
        styles["Heading2"],
    ))

    story.append(paragraph(
        f"Application: {filename}"
    ))

    story.append(paragraph(
        f"Files scanned: {scanned_files}"
    ))

    story.append(paragraph(
        f"Potential findings: {len(findings)}"
    ))

    for severity in SEVERITIES:
        count = sum(
            f.get("Severity") == severity
            for f in findings
        )

        story.append(paragraph(
            f"{severity}: {count}"
        ))

    story.append(Spacer(1, 10))

    story.append(paragraph(
        "These findings are potential security issues "
        "and require manual verification."
    ))

    story.append(HRFlowable(
        width="100%",
        thickness=1,
        color=colors.HexColor("#d0d5dd"),
        spaceBefore=10,
        spaceAfter=12,
    ))

    story.append(Paragraph(
        "Detailed Security Findings",
        styles["Heading2"],
    ))

    if not findings:
        story.append(paragraph(
            "No potential findings were identified."
        ))

    for index, finding in enumerate(
        findings, start=1
    ):
        name = html.escape(str(
            finding.get(
                "Vulnerability", "Security issue"
            )
        ))

        severity = finding.get(
            "Severity", "Unknown"
        )
        path = finding.get("File", "")
        line = get_related_lines(finding)
        detection = finding.get(
            "Detection", ""
        )

        story.append(KeepTogether([
            Paragraph(
                f"{index}. {name}",
                styles["CodeShieldFinding"],
            ),
            paragraph(
                f"Severity: {severity}"
            ),
            paragraph(
                f"File: {path}"
            ),
            paragraph(
                f"Line(s): {line}"
            ),
            paragraph(
                f"Detection: {detection}"
            ),
        ]))

        story.append(Paragraph(
            "Source Code Evidence",
            styles["Heading4"],
        ))

        evidence = (
            finding.get("CodeContext")
            or finding.get("Evidence", "")
        )

        add_code_block(evidence)

        story.append(Spacer(1, 8))

        story.append(Paragraph(
            "Root Cause / Description",
            styles["Heading4"],
        ))

        story.append(paragraph(
            finding.get("Description", "")
        ))

        story.append(KeepTogether([
            Paragraph(
                "Recommended Secure Fix",
                styles["Heading4"],
            ),
            paragraph(
                finding.get("Fix", "")
            ),
        ]))

        secure_code = get_secure_code(finding)

        if secure_code:
            add_code_block(
                secure_code,
                secure=True,
                heading="Suggested Secure Code Example",
            )

            story.append(Spacer(1, 8))

            story.append(paragraph(
                "Example only. Adapt and test this "
                "fix against the application's actual "
                "code, database schema, and "
                "authorization rules.",
                "CodeShieldNote",
            ))

        story.append(Spacer(1, 12))

        story.append(HRFlowable(
            width="100%",
            thickness=0.5,
            color=colors.HexColor("#e1e5ed"),
            spaceAfter=10,
        ))

    story.append(Paragraph(
        "Assessment Limitations",
        styles["Heading2"],
    ))

    story.append(paragraph(
        "Static analysis and AI review may produce "
        "false positives or miss vulnerabilities. "
        "Suggested code examples require developer "
        "review, adaptation, and testing."
    ))

    document.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number,
    )

    return buffer.getvalue()
