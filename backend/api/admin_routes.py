import secrets

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database.database import get_db
from database.models import APIKey
from auth.rbac import require_role

router = APIRouter()

@router.post("/apikey")

def create_key(
    db: Session = Depends(get_db),
    user = Depends(require_role("Admin"))
):

    key = secrets.token_hex(32)

    api = APIKey(key=key, user_id=user.id)

    db.add(api)
    db.commit()

    return {"api_key": key}