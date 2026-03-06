from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import jwt
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.models import User
from backend.config import settings


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/auth/auth/login"
)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):

    payload = jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM]
    )

    user = db.query(User).get(payload["user_id"])

    if not user:
        raise HTTPException(401)

    return user