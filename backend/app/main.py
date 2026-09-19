from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import PROJECT_NAME, VERSION, API_V1_STR
from app.api.health import router as health_router
from app.api.ingest import router as ingest_router
from app.api.tls import router as tls_router
from app.api.synthetic import router as synthetic_router
from app.api.ml import router as ml_router
from app.api.simulator import router as simulator_router
from app.api.compliance import router as compliance_router
from app.api.reports import router as reports_router

app = FastAPI(
    title=PROJECT_NAME,
    version=VERSION,
    description="AI-Assisted Passive Network Forensic Framework for Email Infrastructure (SMTP, IMAP, POP3 TLS Analysis)"
)

# Enable CORS for local dashboard development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health_router, prefix=API_V1_STR)
app.include_router(health_router)  # Also expose top-level /health
app.include_router(ingest_router, prefix=API_V1_STR)
app.include_router(tls_router, prefix=API_V1_STR)
app.include_router(synthetic_router, prefix=API_V1_STR)
app.include_router(ml_router, prefix=API_V1_STR)
app.include_router(simulator_router, prefix=API_V1_STR)
app.include_router(simulator_router)  # Top level /sessions/{id}/simulate
app.include_router(compliance_router, prefix=API_V1_STR)
app.include_router(compliance_router)
app.include_router(reports_router, prefix=API_V1_STR)
app.include_router(reports_router)

@app.get("/")
async def root():
    return {
        "message": f"Welcome to {PROJECT_NAME} API",
        "health_check": f"{API_V1_STR}/health",
        "docs": "/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
