from fastapi import FastAPI
from api.router import api_router
from database.database import engine
from database.models import Base

app = FastAPI(
    title="AIGIS",
    description="Autonomous Intelligent Guard & Inspection System",
    version="1.0"
)

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)

app.include_router(api_router)