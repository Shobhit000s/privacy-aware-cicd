"""
tests/integration/test_backend_api.py

Full integration test suite for the FastAPI backend, using an isolated
in-memory SQLite DB per test run (via dependency override) so tests never
touch a real Postgres instance or leave state behind.

Run with: pytest tests/integration/test_backend_api.py -v
"""
import os
import sys
import importlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "backend")
sys.path.insert(0, BACKEND_DIR)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Spin up the FastAPI app against a fresh SQLite file per test."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-secret-key")

    # Force reimport so main.py/database.py pick up the patched env vars —
    # necessary because these modules read os.environ at import time.
    for mod in ["main", "database", "models", "auth", "schemas",
                "routers.auth", "routers.deployments", "routers.audit"]:
        sys.modules.pop(mod, None)

    import main as main_module  # noqa: E402
    return TestClient(main_module.app)


def register_and_login(client, username="alice", role="admin", password="StrongPass1!"):
    resp = client.post("/api/auth/register", json={
        "username": username, "email": f"{username}@example.com",
        "password": password, "role": role,
    })
    assert resp.status_code == 201, resp.text

    resp = client.post("/api/auth/login", data={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestHealthAndRoot:
    def test_healthz(self, client):
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_root(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "docs" in resp.json()


class TestAuth:
    def test_register_creates_user(self, client):
        resp = client.post("/api/auth/register", json={
            "username": "bob", "email": "bob@example.com",
            "password": "Password123!", "role": "developer",
        })
        assert resp.status_code == 201
        body = resp.json()
        assert body["username"] == "bob"
        assert body["role"] == "developer"
        assert "password" not in body and "hashed_password" not in body

    def test_duplicate_username_rejected(self, client):
        payload = {"username": "carol", "email": "carol@example.com",
                   "password": "Password123!", "role": "viewer"}
        assert client.post("/api/auth/register", json=payload).status_code == 201
        resp = client.post("/api/auth/register", json=payload)
        assert resp.status_code == 400

    def test_invalid_role_rejected(self, client):
        resp = client.post("/api/auth/register", json={
            "username": "dave", "email": "dave@example.com",
            "password": "Password123!", "role": "superadmin",
        })
        assert resp.status_code == 400

    def test_login_wrong_password_rejected(self, client):
        client.post("/api/auth/register", json={
            "username": "erin", "email": "erin@example.com",
            "password": "CorrectPass1!", "role": "viewer",
        })
        resp = client.post("/api/auth/login", data={"username": "erin", "password": "WrongPass!"})
        assert resp.status_code == 401

    def test_login_returns_bearer_token(self, client):
        headers = register_and_login(client, "frank", "developer")
        assert headers["Authorization"].startswith("Bearer ")


class TestDeployments:
    def test_create_requires_auth(self, client):
        resp = client.post("/api/deployments", json={
            "commit_sha": "abc123", "service_name": "svc", "environment": "production",
        })
        assert resp.status_code == 401

    def test_create_and_list_deployment(self, client):
        headers = register_and_login(client, "grace", "developer")
        resp = client.post("/api/deployments", json={
            "commit_sha": "abc123", "service_name": "privacy-aware-app", "environment": "production",
        }, headers=headers)
        assert resp.status_code == 201
        dep = resp.json()
        assert dep["status"] == "pending"
        assert dep["run_id"].startswith("run-")

        resp = client.get("/api/deployments")
        assert resp.status_code == 200
        assert any(d["run_id"] == dep["run_id"] for d in resp.json())

    def test_update_deployment_risk_score(self, client):
        headers = register_and_login(client, "heidi", "developer")
        dep = client.post("/api/deployments", json={
            "commit_sha": "def456", "service_name": "svc", "environment": "production",
        }, headers=headers).json()

        resp = client.patch(f"/api/deployments/{dep['run_id']}", json={
            "risk_score": 82.5, "risk_level": "CRITICAL", "status": "blocked",
        }, headers=headers)
        assert resp.status_code == 200
        updated = resp.json()
        assert updated["risk_score"] == 82.5
        assert updated["status"] == "blocked"

    def test_approve_requires_admin_or_reviewer_role(self, client):
        dev_headers = register_and_login(client, "ivan", "developer")
        dep = client.post("/api/deployments", json={
            "commit_sha": "ghi789", "service_name": "svc", "environment": "production",
        }, headers=dev_headers).json()

        # developer role should NOT be able to approve
        resp = client.post(f"/api/deployments/{dep['run_id']}/approve", headers=dev_headers)
        assert resp.status_code == 403

        admin_headers = register_and_login(client, "judy", "admin")
        resp = client.post(f"/api/deployments/{dep['run_id']}/approve", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "approved_override"

    def test_get_nonexistent_deployment_404s(self, client):
        resp = client.get("/api/deployments/run-doesnotexist")
        assert resp.status_code == 404

    def test_stats_summary(self, client):
        headers = register_and_login(client, "kim", "developer")
        client.post("/api/deployments", json={
            "commit_sha": "aaa", "service_name": "svc", "environment": "production",
        }, headers=headers)
        resp = client.get("/api/deployments/stats/summary")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] >= 1
        assert "by_status" in body


class TestAuditTrail:
    def test_deployment_creation_writes_audit_event(self, client):
        headers = register_and_login(client, "leo", "developer")
        dep = client.post("/api/deployments", json={
            "commit_sha": "aud123", "service_name": "svc", "environment": "production",
        }, headers=headers).json()

        resp = client.get("/api/audit")
        assert resp.status_code == 200
        events = resp.json()
        assert any(e["deployment_id"] == dep["id"] and e["event_type"] == "deployment_created" for e in events)

    def test_audit_chain_hashes_link(self, client):
        headers = register_and_login(client, "mia", "developer")
        for i in range(3):
            client.post("/api/deployments", json={
                "commit_sha": f"chain{i}", "service_name": "svc", "environment": "production",
            }, headers=headers)

        events = client.get("/api/audit").json()
        events_sorted = sorted(events, key=lambda e: e["id"])
        for prev, curr in zip(events_sorted, events_sorted[1:]):
            assert curr["prev_hash"] == prev["event_hash"], "audit chain is not properly linked"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
