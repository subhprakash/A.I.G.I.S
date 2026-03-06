from workers.celery_app import celery
from sandbox.tool_executor import execute_security_tests
from security.cvss_engine import compute_cvss
from ai.remediation_engine import generate_remediation
from reporting.report_generator import generate_report

from database.database import SessionLocal
from database.models import ScanResult, ScanJob


@celery.task
def run_scan_task(job_id, path):

    db = SessionLocal()

    job = db.query(ScanJob).get(job_id)

    results = execute_security_tests(path, job.detected_language)

    score = compute_cvss(results)

    remediation = generate_remediation(results)

    record = ScanResult(
        job_id=job_id,
        result=str(results),
        ai_remediation=remediation,
        cvss_score=str(score)
    )

    job.status = "completed"

    db.add(record)
    db.commit()

    generate_report(job_id, results, remediation, score)

    db.close()