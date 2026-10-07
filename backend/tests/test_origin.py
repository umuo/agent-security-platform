from dataclasses import replace

import pytest
from agentsec.api import create_app
from fastapi.testclient import TestClient


def test_explicit_https_origin_behind_http_proxy(settings, db):
    proxy_settings = replace(settings, public_origin="https://security.example.com")
    with TestClient(create_app(proxy_settings)) as client:
        credentials = {"username": "admin", "password": "test-password-123"}
        assert (
            client.post(
                "/api/auth/login",
                json=credentials,
                headers={"Origin": "https://security.example.com"},
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/api/auth/login", json=credentials, headers={"Origin": "http://testserver"}
            ).status_code
            == 403
        )


def test_production_origin_is_required_and_https(settings):
    with pytest.raises(ValueError, match="PUBLIC_ORIGIN"):
        replace(
            settings,
            mode="production",
            database_url="postgresql+psycopg://test/db",
            cookie_secure=True,
        ).validate()
    with pytest.raises(ValueError, match="HTTPS"):
        replace(
            settings,
            mode="production",
            database_url="postgresql+psycopg://test/db",
            cookie_secure=True,
            public_origin="http://security.example.com",
        ).validate()
    for invalid in [
        "https://example.com/path",
        "https://user:pass@example.com",
        "https://example.com?query=x",
    ]:
        with pytest.raises(ValueError, match="valid origin"):
            replace(settings, public_origin=invalid).validate()
