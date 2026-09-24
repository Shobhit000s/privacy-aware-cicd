"""
backend/database.py

Defaults to a local SQLite file so the app runs out of the box for grading/
demo purposes. Set DATABASE_URL to a Postgres DSN in production, e.g.:
    postgresql+psycopg2://app_user:PASSWORD@postgres:5432/privacy_cicd
(the password itself should come from Vault/K8s secret injection, never
hardcoded — see docs/ARCHITECTURE.md and vault/ for how that's wired.)
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./privacy_cicd.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
