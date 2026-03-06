from datetime import datetime, timedelta, timezone
from jose import jwt
from backend.config import settings

# Ensure the name is 'create_access_token' to match your router's import
def create_access_token(data: dict):
    to_encode = data.copy()
    
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    
    to_encode.update({"exp": expire})
    
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.SECRET_KEY, 
        algorithm=settings.JWT_ALGORITHM
    )
    
    return encoded_jwt