FROM python:3.11

WORKDIR /app

COPY backend/requirements.txt .

RUN pip install -r requirements.txt

COPY backend /app

CMD ["celery","-A","workers.celery_app.celery","worker","--loglevel=info"]