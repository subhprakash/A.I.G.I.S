from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os

REPORT_DIR = "/tmp/aigis_reports"


def export_pdf(job_id, results, remediation, score):

    os.makedirs(REPORT_DIR, exist_ok=True)

    path = f"{REPORT_DIR}/report_{job_id}.pdf"

    c = canvas.Canvas(path, pagesize=letter)

    y = 750

    c.drawString(50, y, f"AIGIS Security Report")

    y -= 40
    c.drawString(50, y, f"Job ID: {job_id}")

    y -= 30
    c.drawString(50, y, f"CVSS Score: {score}")

    y -= 40

    for r in results:

        c.drawString(50, y, f"{r['tool']}")

        y -= 20

    y -= 30

    for line in remediation.split("\n"):

        c.drawString(50, y, line)

        y -= 15

    c.save()

    return path