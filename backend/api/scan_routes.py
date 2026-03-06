from fastapi import APIRouter, UploadFile, Depends
from sqlalchemy.orm import Session

from database.database import get_db
from orchestrator.job_manager import create_scan_job
from auth.dependencies import get_current_user

router = APIRouter()

@router.post("/upload")

async def upload(
    file: UploadFile,
    db: Session = Depends(get_db),
    user = Depends(get_current_user)
):

    job = await create_scan_job(file, db)

    return {"job_id": job.id}