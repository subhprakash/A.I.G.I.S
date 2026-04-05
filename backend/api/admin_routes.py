from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import func  # <-- Add this line
import os

from backend.database.database import get_db
from backend.database.models import User, Report, ScanJob
from backend.auth.rbac import require_role

router = APIRouter(tags=["admin"])


@router.get("/users")
def list_users(
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin"))
):
    users = db.query(User).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "role": u.role.name if u.role else "none",
            "created_at": u.created_at
        }
        for u in users
    ]


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin"))
):
    if user_id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own admin account"
        )
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    db.delete(user)
    db.commit()
    return {"message": f"User '{user.username}' deleted successfully"}


@router.get("/reports")
def list_all_reports(
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin"))
):
    reports = db.query(Report).order_by(Report.created_at.desc()).all()
    return [
        {
            "id": r.id,
            "job_id": r.job_id,
            "scan_type": r.scan_type,
            "target": r.target,
            "vulnerability_count": r.vulnerability_count or 0,
            "threat_score": r.threat_score or 0.0,
            "highest_severity": r.highest_severity or "none",
            "user_id": r.user_id,
            "username": r.user.username if r.user else "unknown",
            "path": r.path,
            "created_at": r.created_at
        }
        for r in reports
    ]


@router.get("/reports/{job_id}/download")
def admin_download_report(
    job_id: str,
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin"))
):
    report = db.query(Report).filter(Report.job_id == job_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not os.path.exists(report.path):
        raise HTTPException(status_code=404, detail="Report file not found on disk")
    return FileResponse(
        path=report.path,
        filename=f"{job_id}.pdf",
        media_type="application/pdf"
    )


@router.get("/scans")
def list_all_scans(
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin"))
):
    """Returns all scan jobs grouped by user."""
    users = db.query(User).all()
    scans = db.query(ScanJob).order_by(ScanJob.created_at.desc()).all()

    user_lookup = {u.id: u.username for u in users}
    grouped = {}
    unassigned = []

    for s in scans:
        uid = getattr(s, 'user_id', None)
        entry = {
            "id": s.id,
            "input_name": s.input_name,
            "input_type": s.input_type,
            "status": s.status,
            "created_at": s.created_at,
        }
        if uid and uid in user_lookup:
            username = user_lookup[uid]
            if username not in grouped:
                grouped[username] = []
            grouped[username].append(entry)
        else:
            unassigned.append(entry)

    result = [
        {"username": username, "scans": user_scans}
        for username, user_scans in grouped.items()
    ]
    if unassigned:
        result.append({"username": "unassigned", "scans": unassigned})

    return result

@router.get("/dashboard/summary")
def get_dashboard_summary(
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin"))
):
    """
    Returns aggregated system-wide analytics for the admin dashboard.
    Demonstrates database-level aggregation (COUNT, SUM, GROUP BY) 
    to fulfill the 'Dashboard Summary APIs' assignment requirement.
    """
    # 1. Total Users Calculation
    total_users = db.query(User).count()

    # 2. Total Scans and Status Breakdown (Group By)
    total_scans = db.query(ScanJob).count()
    scans_by_status = db.query(
        ScanJob.status, func.count(ScanJob.id)
    ).group_by(ScanJob.status).all()

    # 3. Vulnerability Metrics (Sum and Group By)
    total_vulns = db.query(func.sum(Report.vulnerability_count)).scalar() or 0
    reports_by_severity = db.query(
        Report.highest_severity, func.count(Report.id)
    ).group_by(Report.highest_severity).all()

    return {
        "overview": {
            "total_users": total_users,
            "total_scans_run": total_scans,
            "total_vulnerabilities_detected": int(total_vulns)
        },
        "scans_by_status": {
            status: count for status, count in scans_by_status if status
        },
        "reports_by_highest_severity": {
            severity: count for severity, count in reports_by_severity if severity
        }
    }