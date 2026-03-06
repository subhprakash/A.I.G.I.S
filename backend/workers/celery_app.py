from celery import Celery
from config import settings

celery = Celery(
    "aigis",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL
)

celery.conf.task_routes = {
    "workers.tasks.*": {"queue": "scanning"}
}