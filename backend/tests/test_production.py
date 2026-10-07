from dataclasses import replace

import pytest
from agentsec.api import create_app
from agentsec.worker import Worker
from fastapi.testclient import TestClient

from .conftest import create_job


async def test_production_settings_real_postgres_cookie_and_worker(settings, db):
    if not settings.database_url.startswith("postgresql"):
        pytest.skip("Production requires real PostgreSQL")
    production = replace(
        settings,
        mode="production",
        public_origin="https://security.example.com",
        cookie_secure=True,
    ).validate()
    with TestClient(create_app(production), base_url="https://security.example.com") as client:
        assert client.get("/health/ready").status_code == 200
        assert client.get("/api/docs").status_code == 404
        result = client.post(
            "/api/auth/login",
            headers={"Origin": production.public_origin},
            json={"username": "admin", "password": "test-password-123"},
        )
        assert result.status_code == 200
        assert all("Secure" in value for value in result.headers.get_list("set-cookie"))
        client.headers["X-CSRF-Token"] = result.json()["csrf_token"]
        client.headers["Origin"] = production.public_origin
        job = create_job(client)
        assert await Worker(production, db).run_once()
        report = client.get("/api/evaluations/" + job["id"] + "/report").json()
        assert report["status"] == "COMPLETED"
        assert report["summary"]["gate_passed"]
