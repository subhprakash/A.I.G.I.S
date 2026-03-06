from fastapi import FastAPI
from backend.api.router import api_router
from backend.database.database import engine
from backend.database.models import Base

app = FastAPI(title="AIGIS")

Base.metadata.create_all(bind=engine)

app.include_router(api_router)