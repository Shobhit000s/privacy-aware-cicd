"""
backend/main.py

Entry point for the actual business application deployed by the pipeline.
Run: uvicorn main:app --reload --port 8000
Docs: http://localhost:8000/docs
"""
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import Base, engine
import models  # noqa: F401  (ensures models are registered before create_all)
from routers import auth, deployments, audit

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Privacy-Aware CI/CD Platform API",
    description="Backend service deployed by the privacy-aware CI/CD pipeline. "
                 "Provides auth, deployment tracking, and a tamper-evident audit trail.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "http://localhost:3000,http://localhost:5173").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(deployments.router)
app.include_router(audit.router)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/")
def root():
    return {"service": "privacy-aware-cicd-backend", "docs": "/docs"}
