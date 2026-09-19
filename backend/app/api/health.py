import time
from fastapi import APIRouter
from app.config import PROJECT_NAME, VERSION

router = APIRouter()

@router.get("/health", tags=["System"])
async def health_check():
    return {
        "status": "healthy",
        "service": PROJECT_NAME,
        "version": VERSION,
        "timestamp": time.time(),
        "modules": {
            "ingestion": "ready",
            "tls_analysis": "ready",
            "ml_engine": "ready",
            "reporting": "ready"
        }
    }
