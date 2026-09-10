from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.db import init_db
from app.api.routes_scans import router as scans_router
from app.api.routes_ai import router as ai_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables on startup
    init_db()
    yield


app = FastAPI(
    title="Codebase Doctor API",
    description="Automated static analysis, architecture inspection, and deterministic health scoring for codebases.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS if settings.CORS_ORIGINS else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Routers
app.include_router(scans_router)
app.include_router(ai_router)


@app.get("/health", tags=["health"])
def health_check():
    """Application health endpoint."""
    return {"status": "ok"}
