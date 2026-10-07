from dataclasses import replace

import pytest
from agentsec.backups import create_backup, restore_backup, verify_backup
from agentsec.db import Database
from agentsec.models import SessionToken, Target, User
from agentsec.security import seal, unseal
from sqlalchemy import func, select


def test_backup_integrity_and_restore_sqlite(settings, db, admin, tmp_path):
    if not settings.database_url.startswith("sqlite"):
        pytest.skip("SQLite filesystem restore path")
    with db.session.begin() as session:
        session.add(
            Target(
                name="encrypted-target",
                kind="fixture",
                config={},
                secret=seal(settings, "test-secret"),
                revision="r1",
            )
        )
    log = settings.data_dir / "inspect/logs/evidence.json"
    log.parent.mkdir(parents=True)
    log.write_text('{"fixture":true}')
    destination = tmp_path / "backup"
    create_backup(settings, destination)
    manifest = verify_backup(settings, destination)
    assert manifest["dialect"] == "sqlite"
    assert "test-secret" not in (destination / "manifest.json").read_text()
    restored = replace(
        settings,
        database_url="sqlite:///" + str(tmp_path / "restored.db"),
        data_dir=tmp_path / "restored-data",
    ).validate()
    restore_backup(restored, destination)
    restored_db = Database(restored)
    try:
        assert restored_db.ready()
        with restored_db.session() as session:
            assert session.scalar(select(func.count()).select_from(User)) == 2
            assert session.scalar(select(func.count()).select_from(SessionToken)) == 0
            target = session.scalar(select(Target).where(Target.name == "encrypted-target"))
            assert unseal(restored, target.secret) == "test-secret"
        assert (restored.data_dir / "inspect/logs/evidence.json").read_text() == log.read_text()
        with pytest.raises(ValueError, match="必须为空|必须不存在"):
            restore_backup(restored, destination)
    finally:
        restored_db.engine.dispose()


def test_backup_rejects_active_jobs_and_bad_checksum(settings, db, admin, tmp_path):
    from .conftest import create_job

    job = create_job(admin)
    with pytest.raises(ValueError, match="活动任务"):
        create_backup(settings, tmp_path / "backup")
    admin.post("/api/evaluations/" + job["id"] + "/cancel")
    create_backup(settings, tmp_path / "backup")
    manifest = verify_backup(settings, tmp_path / "backup")
    file = tmp_path / "backup" / manifest["database_file"]
    with file.open("ab") as stream:
        stream.write(b"corruption")
    with pytest.raises(ValueError, match="校验和"):
        verify_backup(settings, tmp_path / "backup")


def test_backup_wrong_key_and_overwrite_rejected(settings, db, tmp_path):
    from cryptography.fernet import Fernet

    destination = tmp_path / "backup"
    create_backup(settings, destination)
    with pytest.raises(ValueError, match="全新目录"):
        create_backup(settings, destination)
    different = replace(settings, master_key=Fernet.generate_key().decode())
    with pytest.raises(ValueError, match="主密钥"):
        verify_backup(different, destination)
    (destination / "unexpected.json").write_text("{}")
    with pytest.raises(ValueError, match="未列入清单"):
        verify_backup(settings, destination)
