FROM python:3.11

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libmagic1 \
    file \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY backend ./backend

RUN pip install --no-cache-dir -r backend/requirements.txt

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]