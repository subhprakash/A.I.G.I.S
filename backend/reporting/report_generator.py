from backend.reporting.pdf_exporter import export_pdf
from backend.database.database import SessionLocal
from backend.database.models import Report


def generate_report(job_id, results, remediation, score):

    path = export_pdf(job_id, results, remediation, score)

    db = SessionLocal()

    report = Report(
        job_id=job_id,
        path=path
    )

    db.add(report)
    db.commit()

    db.close()