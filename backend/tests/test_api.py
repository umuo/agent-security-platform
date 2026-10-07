from agentsec.models import SessionToken, Target
from agentsec.security import unseal
from sqlalchemy import select

from .conftest import create_job


def test_auth_csrf_and_role(client):
    assert client.get("/api/targets").status_code == 401
    login = client.post(
        "/api/auth/login", json={"username": "viewer", "password": "test-password-123"}
    )
    assert login.status_code == 200
    assert client.post("/api/targets", json={"name": "x", "kind": "fixture"}).status_code == 403
    client.headers["X-CSRF-Token"] = login.json()["csrf_token"]
    assert client.post("/api/targets", json={"name": "x", "kind": "fixture"}).status_code == 403
    assert client.get("/api/audit").status_code == 403
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_login_failures_persist_and_limit(client):
    for _ in range(8):
        assert (
            client.post(
                "/api/auth/login", json={"username": "admin", "password": "wrong"}
            ).status_code
            == 401
        )
    assert (
        client.post(
            "/api/auth/login", json={"username": "admin", "password": "test-password-123"}
        ).status_code
        == 429
    )


def test_secret_is_encrypted_and_never_exported(admin, db, settings):
    response = admin.post(
        "/api/targets",
        json={"name": "private", "kind": "fixture", "config": {}, "secret": "private-token-123"},
    )
    assert response.status_code == 201
    assert "private-token-123" not in response.text
    with db.session() as session:
        row = session.get(Target, response.json()["id"])
        assert row.secret != "private-token-123"
        assert unseal(settings, row.secret) == "private-token-123"
        assert session.scalar(select(SessionToken)).token_hash != admin.cookies["agentsec_session"]
    assert "private-token-123" not in admin.get("/api/targets").text


def test_allowlist_and_unknown_target_config(admin):
    assert (
        admin.post(
            "/api/targets",
            json={
                "name": "x",
                "kind": "http-agent",
                "config": {"endpoint": "http://169.254.169.254/"},
            },
        ).status_code
        == 400
    )
    assert (
        admin.post(
            "/api/targets",
            json={"name": "x", "kind": "fixture", "config": {"arbitrary_command": "sh"}},
        ).status_code
        == 400
    )


def test_immutable_snapshots_idempotency_and_cancel(admin, db):
    job = create_job(admin)
    target = job["target_id"]
    body = {"target_id": target, "case_ids": ["direct-tool"]}
    first = admin.post("/api/evaluations", json=body, headers={"Idempotency-Key": "same-request"})
    second = admin.post("/api/evaluations", json=body, headers={"Idempotency-Key": "same-request"})
    assert first.json()["id"] == second.json()["id"]
    assert (
        admin.post(
            "/api/evaluations",
            json={**body, "repeats": 2},
            headers={"Idempotency-Key": "same-request"},
        ).status_code
        == 409
    )
    detail = admin.get("/api/evaluations/" + job["id"]).json()
    assert detail["attempts"][0]["case_snapshot"]["revision"]
    assert admin.post("/api/evaluations/" + job["id"] + "/cancel").status_code == 200
    assert admin.get("/api/evaluations/" + job["id"]).json()["status"] == "CANCELLED"


def test_cross_origin_and_body_size(admin):
    assert (
        admin.post(
            "/api/cases", json={}, headers={"Origin": "https://attacker.invalid"}
        ).status_code
        == 403
    )
    assert admin.post("/api/cases", content="x" * 1048577).status_code == 413
    assert admin.get("/api/auth/me").headers["Cache-Control"] == "no-store"


def test_ready_and_strict_inputs(admin):
    assert admin.get("/health/ready").status_code == 200
    assert (
        admin.post("/api/evaluations", json={"target_id": "x", "case_ids": ["x", "x"]}).status_code
        == 422
    )
    assert (
        admin.post(
            "/api/cases",
            json={
                "name": "custom",
                "category": "prompt-injection",
                "surface": "user_message",
                "user_task": "查询订单",
                "payload": "覆盖规则",
                "oracle": "forbidden_tool",
            },
        ).status_code
        == 201
    )
