import os
import uuid

import pytest
from agentsec.api import create_app
from agentsec.cases import seed_cases
from agentsec.cli import migrate
from agentsec.config import Settings
from agentsec.db import Database
from agentsec.security import bootstrap_user
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


@pytest.fixture
def settings(tmp_path):
    database_url = "sqlite:///" + str(tmp_path / "test.db")
    postgres_url = os.getenv("AGENTSEC_TEST_POSTGRES_URL")
    engine = None
    schema = "test_" + uuid.uuid4().hex
    if postgres_url:
        engine = create_engine(postgres_url)
        with engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        database_url = (
            make_url(postgres_url)
            .update_query_dict({"options": "-csearch_path=" + schema})
            .render_as_string(hide_password=False)
        )
    value = Settings(
        database_url=database_url,
        data_dir=tmp_path / "data",
        master_key=Fernet.generate_key().decode(),
        target_hosts=frozenset({"127.0.0.1"}),
    ).validate()
    try:
        yield value
    finally:
        if engine is not None:
            with engine.begin() as connection:
                connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
            engine.dispose()


@pytest.fixture
def db(settings):
    migrate(settings)
    database = Database(settings)
    with database.session.begin() as session:
        seed_cases(session)
        bootstrap_user(session, "admin", "test-password-123")
        bootstrap_user(session, "viewer", "test-password-123", "viewer")
    yield database
    database.engine.dispose()


@pytest.fixture
def client(settings, db):
    with TestClient(create_app(settings)) as client:
        yield client


@pytest.fixture
def admin(client):
    result = client.post(
        "/api/auth/login", json={"username": "admin", "password": "test-password-123"}
    )
    assert result.status_code == 200
    client.headers["X-CSRF-Token"] = result.json()["csrf_token"]
    return client


def create_job(client, guard="strict", cases=None, kind="fixture", config=None):
    target = client.post(
        "/api/targets",
        json={"name": "test-agent", "kind": kind, "config": config or {"guard": guard}},
    )
    assert target.status_code == 201, target.text
    response = client.post(
        "/api/evaluations",
        json={
            "target_id": target.json()["id"],
            "case_ids": cases or ["direct-tool", "clean-query"],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()
