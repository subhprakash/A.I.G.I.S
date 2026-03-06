import os

class Settings:

    DATABASE_URL = os.getenv(
        "DATABASE_URL",
        "postgresql://aigis:aigis@postgres:5432/aigis"
    )

    REDIS_URL = os.getenv(
        "REDIS_URL",
        "redis://redis:6379/0"
    )

    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "aigis-secret"
    )

    JWT_ALGORITHM = "HS256"

    ACCESS_TOKEN_EXPIRE_MINUTES = 60

    OLLAMA_URL = os.getenv(
        "OLLAMA_URL",
        "http://ollama:11434/api/generate"
    )

settings = Settings()