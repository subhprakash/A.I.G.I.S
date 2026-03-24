from fastapi import FastAPI
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from backend.api.scan_routes import router as scan_router
from backend.api.url_scan_routes import router as url_scan_router
from backend.api.auth_routes import router as auth_router
from backend.api.admin_routes import router as admin_router
from backend.api.report_routes import router as report_router
from backend.database.database import engine
from backend.database.models import Base

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="A.I.G.I.S — AI-powered Security Scanner")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

Base.metadata.create_all(bind=engine)

# Route map:
#   /api/scan/upload          ← scan_router  (file upload)
#   /api/scan/upload/zip      ← scan_router  (zip upload)
#   /api/scan/url             ← url_scan_router
#   /api/scan/repository      ← url_scan_router
#   /api/scan/status/{job_id} ← url_scan_router
#   /api/scan/cancel/{job_id} ← url_scan_router  (single definition)
#   /api/auth/...             ← auth_router
#   /api/admin/...            ← admin_router
#   /api/reports/...          ← report_router

app.include_router(scan_router,     prefix="/api/scan")
app.include_router(url_scan_router)          
app.include_router(auth_router,     prefix="/api/auth")
app.include_router(admin_router,    prefix="/api/admin")
app.include_router(report_router,   prefix="/api/reports")