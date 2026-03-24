from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, status, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
import os
import uuid

from backend.workers.tasks import run_scan_task, run_zip_scan_task
from backend.auth.dependencies import get_current_user

router = APIRouter(tags=["scan"])

UPLOAD_DIR = "/app/uploads"
limiter    = Limiter(key_func=get_remote_address)


# ── Single-file scan ──────────────────────────────────────────────────────────

@router.post("/upload")
@limiter.limit("10/minute")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    current_user=Depends(get_current_user),
):
    """
    Upload a single source file for scanning.
    Supported: .py .js .ts .jsx .tsx .java .c .cpp .rb .go .php .html
    """
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    job_id    = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, f"{job_id}_{file.filename}")

    with open(file_path, "wb") as buf:
        buf.write(await file.read())

    run_scan_task.apply_async(
        args=[file_path],
        kwargs={"user_id": current_user.id},
        task_id=job_id,
    )

    return {
        "filename":    file.filename,
        "stored_path": file_path,
        "job_id":      job_id,
        "status":      "scan_started",
        "message":     f"Poll /api/scan/status/{job_id} for results.",
    }


# ── ZIP archive scan ──────────────────────────────────────────────────────────

@router.post("/upload/zip")
@limiter.limit("5/minute")
async def upload_zip(
    request: Request,
    file: UploadFile = File(...),
    current_user=Depends(get_current_user),
):
    """
    Upload a .zip archive for scanning.

    Each file inside is safely extracted and scanned individually.
    All findings are aggregated into a single PDF report.

    Safety limits enforced:
      - Max extracted size: 500 MB  (zip bomb protection)
      - Max file count: 100 files   (processing cap)
      - ZipSlip path traversal: blocked
    """
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Only .zip files are accepted on this endpoint. "
                "For individual files use /api/scan/upload."
            ),
        )

    os.makedirs(UPLOAD_DIR, exist_ok=True)

    job_id    = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, f"{job_id}_{file.filename}")

    with open(file_path, "wb") as buf:
        buf.write(await file.read())

    run_zip_scan_task.apply_async(
        args=[file_path],
        kwargs={"user_id": current_user.id},
        task_id=job_id,
    )

    return {
        "filename":    file.filename,
        "stored_path": file_path,
        "job_id":      job_id,
        "status":      "scan_started",
        "message":     f"ZIP scan queued. Poll /api/scan/status/{job_id} for results.",
    }