# AIGIS — Autonomous Intelligent Guard & Inspection System

Enterprise automated security analysis platform.

AIGIS analyzes:

- Source code
- Executable binaries
- Web targets

The system performs automated vulnerability scanning using containerized tools and distributed workers.

## Features

- FastAPI backend
- React dashboard
- Distributed Celery workers
- Docker sandbox scanning
- AI remediation using Ollama
- CVSS vulnerability scoring
- PDF security reports
- RBAC authentication
- API key automation
- Horizontal scaling

---

## Requirements

Docker  
Docker Compose  
Node.js

---

## Running AIGIS

Start infrastructure:

```bash
docker-compose up --build