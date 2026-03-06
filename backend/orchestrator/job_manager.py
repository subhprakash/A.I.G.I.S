import os
import uuid

from backend.database.models import ScanJob
from backend.workers.tasks import run_scan_task
from backend.orchestrator.input_detector import detect_input_type


UPLOAD_DIR = "/tmp/aigis_uploads"


async def create_scan_job(file, db):

    os.makedirs(UPLOAD_DIR, exist_ok=True)

    filename = f"{uuid.uuid4()}_{file.filename}"

    path = os.path.join(UPLOAD_DIR, filename)

    with open(path, "wb") as f:
        f.write(await file.read())

    input_type, language = detect_input_type(path)

    job = ScanJob(
        input_name=filename,
        input_type=input_type,
        detected_language=language,
        status="queued"
    )

    db.add(job)
    db.commit()

    run_scan_task.delay(job.id, path)

    return job