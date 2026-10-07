from concurrent.futures import ThreadPoolExecutor

from agentsec.api import create_app
from agentsec.models import User
from fastapi.testclient import TestClient
from sqlalchemy import select


def test_admin_changes_revoke_sessions_and_preserve_last_admin(admin, settings, db):
    users = admin.get("/api/users").json()
    viewer = next(row for row in users if row["username"] == "viewer")
    owner = next(row for row in users if row["username"] == "admin")
    with TestClient(create_app(settings)) as other:
        assert (
            other.post(
                "/api/auth/login", json={"username": "viewer", "password": "test-password-123"}
            ).status_code
            == 200
        )
        assert other.get("/api/users").status_code == 403
        assert admin.patch("/api/users/" + viewer["id"], json={"disabled": True}).status_code == 200
        assert other.get("/api/auth/me").status_code == 401
        assert (
            other.post(
                "/api/auth/login", json={"username": "viewer", "password": "test-password-123"}
            ).status_code
            == 401
        )
    assert admin.patch("/api/users/" + owner["id"], json={"role": "viewer"}).status_code == 409
    assert admin.patch("/api/users/" + owner["id"], json={"disabled": True}).status_code == 409
    assert (
        admin.patch(
            "/api/users/" + viewer["id"],
            json={"disabled": False, "new_password": "new-password-123"},
        ).status_code
        == 200
    )
    with TestClient(create_app(settings)) as other:
        assert (
            other.post(
                "/api/auth/login", json={"username": "viewer", "password": "new-password-123"}
            ).status_code
            == 200
        )
    with db.session() as session:
        assert (
            session.scalar(select(User).where(User.username == "viewer")).password_hash
            != "new-password-123"
        )


def test_own_password_change_requires_current_password_and_revokes_all(admin, settings, db):
    with TestClient(create_app(settings)) as other:
        other.post("/api/auth/login", json={"username": "admin", "password": "test-password-123"})
        assert (
            admin.post(
                "/api/auth/change-password",
                json={"current_password": "wrong", "new_password": "replacement-123"},
            ).status_code
            == 400
        )
        assert (
            admin.post(
                "/api/auth/change-password",
                json={"current_password": "test-password-123", "new_password": "replacement-123"},
            ).status_code
            == 200
        )
        assert other.get("/api/auth/me").status_code == 401
        assert admin.get("/api/auth/me").status_code == 401
        assert (
            other.post(
                "/api/auth/login", json={"username": "admin", "password": "replacement-123"}
            ).status_code
            == 200
        )


def test_role_change_invalidates_cookie_and_permissions(admin, settings):
    created = admin.post(
        "/api/users", json={"username": "ops", "password": "test-password-123", "role": "operator"}
    ).json()
    with TestClient(create_app(settings)) as other:
        other.post("/api/auth/login", json={"username": "ops", "password": "test-password-123"})
        assert (
            admin.patch("/api/users/" + created["id"], json={"role": "viewer"}).status_code == 200
        )
        assert other.get("/api/auth/me").status_code == 401
        result = other.post(
            "/api/auth/login", json={"username": "ops", "password": "test-password-123"}
        ).json()
        other.headers["X-CSRF-Token"] = result["csrf_token"]
        assert (
            other.post(
                "/api/evaluations", json={"target_id": "not-real", "case_ids": ["direct-tool"]}
            ).status_code
            == 403
        )


def test_concurrent_admin_demotion_keeps_one_owner(admin, settings):
    original = next(row for row in admin.get("/api/users").json() if row["username"] == "admin")
    second = admin.post(
        "/api/users",
        json={"username": "second-admin", "password": "test-password-123", "role": "admin"},
    ).json()
    with TestClient(create_app(settings)) as other:
        login = other.post(
            "/api/auth/login", json={"username": "second-admin", "password": "test-password-123"}
        ).json()
        other.headers["X-CSRF-Token"] = login["csrf_token"]
        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(admin.patch, "/api/users/" + original["id"], json={"role": "viewer"})
            b = pool.submit(other.patch, "/api/users/" + second["id"], json={"role": "viewer"})
            first_status, second_status = a.result().status_code, b.result().status_code
            assert sorted([first_status, second_status]) == [200, 409]
        assert admin.get("/api/auth/me").status_code == (401 if first_status == 200 else 200)
        assert other.get("/api/auth/me").status_code == (401 if second_status == 200 else 200)
