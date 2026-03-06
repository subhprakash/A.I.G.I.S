from fastapi import APIRouter
from fastapi.responses import FileResponse
from backend.database.database import SessionLocal
from backend.database.models import Report

router = APIRouter()

@router.get("/{job_id}/download")
def download(job_id: int):

    db = SessionLocal()

    report = db.query(Report).filter_by(job_id=job_id).first()

    return FileResponse(report.path)