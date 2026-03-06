from pydantic import BaseModel


class UserCreate(BaseModel):

    username: str
    password: str


class LoginRequest(BaseModel):

    username: str
    password: str


class ScanRequest(BaseModel):

    url: str | None = None