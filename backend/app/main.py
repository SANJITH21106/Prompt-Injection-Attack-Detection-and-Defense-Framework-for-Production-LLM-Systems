"""
FastAPI Application Entry Point.
Assembles middleware, routers, and initializes the database on startup.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db
from app.routers import chat, security, events


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database tables on startup."""
    await init_db()
    print(f"[OK] Database initialized ({settings.DATABASE_URL})")
    print(f"[OK] Gemini model: {settings.GEMINI_MODEL}")
    print(f"[OK] Security weights: R={settings.RULE_WEIGHT} S={settings.SQL_WEIGHT} "
          f"M={settings.ML_WEIGHT} G={settings.GUARDRAIL_WEIGHT} "
          f"C={settings.CHUNK_WEIGHT} A={settings.ANOMALY_WEIGHT}")
    print(f"[OK] Thresholds: SANITIZE={settings.SANITIZE_THRESHOLD} BLOCK={settings.BLOCK_THRESHOLD}")
    yield


app = FastAPI(
    title="Real-Time Prompt Defense",
    description="Runtime security framework protecting LLM applications from prompt injection attacks.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(chat.router)
app.include_router(security.router)
app.include_router(events.router)


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "gemini_model": settings.GEMINI_MODEL,
        "database": settings.DATABASE_URL.split("///")[0] if "///" in settings.DATABASE_URL else "configured",
    }
