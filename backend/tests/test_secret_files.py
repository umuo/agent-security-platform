import pytest
from agentsec.config import Settings
from cryptography.fernet import Fernet
from sqlalchemy.engine import make_url


def test_file_secrets_and_url_escaping(monkeypatch, tmp_path):
    key = Fernet.generate_key().decode()
    (tmp_path / "key").write_text(key)
    (tmp_path / "password").write_text("p@ss/with:special")
    monkeypatch.setenv("AGENTSEC_MODE", "local")
    monkeypatch.setenv("AGENTSEC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("AGENTSEC_MASTER_KEY", "")
    monkeypatch.setenv("AGENTSEC_MASTER_KEY_FILE", str(tmp_path / "key"))
    monkeypatch.setenv("AGENTSEC_DATABASE_URL", "postgresql+psycopg://agentsec@db/agentsec")
    monkeypatch.setenv("AGENTSEC_DATABASE_PASSWORD_FILE", str(tmp_path / "password"))
    settings = Settings.load().validate()
    assert settings.master_key == key
    assert make_url(settings.database_url).password == "p@ss/with:special"
    monkeypatch.setenv("AGENTSEC_MASTER_KEY", key)
    with pytest.raises(ValueError, match="only one master"):
        Settings.load()
