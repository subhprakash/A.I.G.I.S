from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database.database import get_db
from database.schemas import LoginRequest, UserCreate
from database.models import User
from auth.password import hash_password, verify_password
from auth.jwt_handler import create_token

router = APIRouter()

@router.post("/register")
def register(data: UserCreate, db: Session = Depends(get_db)):

    existing = db.query(User).filter_by(username=data.username).first()

    if existing:
        raise HTTPException(400, "User already exists")

    user = User(
        username=data.username,
        password_hash=hash_password(data.password)
    )

    db.add(user)
    db.commit()

    return {"status": "created"}

@router.post("/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):

    user = db.query(User).filter_by(username=data.username).first()

    if not user:
        raise HTTPException(401)

    if not verify_password(data.password, user.password_hash):
        raise HTTPException(401)

    token = create_token({"user_id": user.id})

    return {"access_token": token}