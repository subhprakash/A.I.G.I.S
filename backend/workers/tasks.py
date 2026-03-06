from backend.workers.celery_app import celery
from backend.sandbox.tool_executor import execute_security_tests
from backend.security.cvss_engine import compute_cvss
from backend.ai.remediation_engine import generate_remediation
from backend.reporting.report_generator import generate_report

from backend.database.database import SessionLocal
from backend.database.models import ScanResult, ScanJob


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