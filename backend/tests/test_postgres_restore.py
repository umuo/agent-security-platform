import os
import secrets
import uuid
from dataclasses import replace

import pytest
from agentsec.backups import create_backup, restore_backup
from agentsec.db import Database
from agentsec.models import SessionToken, Target, User
from agentsec.security import seal, unseal
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import make_url


def test_actual_postgres_dump_restore(settings, db, admin, tmp_path):
    if (
        not settings.database_url.startswith("postgresql")
        or os.getenv("AGENTSEC_TEST_POSTGRES_RESTORE") != "true"
    ):
        pytest.skip("Requires PostgreSQL pg_dump/pg_restore and CREATE DATABASE permission")
    with db.session.begin() as session:
        session.add(
            Target(
                name="restored-target",
                kind="fixture",
                config={},
                secret=seal(settings, "restore-test-secret"),
                revision="r1",
            )
        )
    create_backup(settings, tmp_path / "snapshot")
    destination_name = "restore_" + uuid.uuid4().hex
    role_name = "restore_role_" + uuid.uuid4().hex
    password = secrets.token_hex(24)
    maintenance = create_engine(settings.database_url, isolation_level="AUTOCOMMIT")
    restored_db = None
    try:
        with maintenance.connect() as connection:
            connection.execute(
                text(
                    f"CREATE ROLE \"{role_name}\" LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE"
                )
            )
            connection.execute(text(f'CREATE DATABASE "{destination_name}" OWNER "{role_name}"'))
        url = make_url(settings.database_url).set(
            database=destination_name, username=role_name, password=password
        )
        restored = replace(
            settings,
            database_url=url.render_as_string(hide_password=False),
            data_dir=tmp_path / "restored-data",
        ).validate()
        restore_backup(restored, tmp_path / "snapshot")
        restored_db = Database(restored)
        assert restored_db.ready()
        with restored_db.session() as session:
            privileges = session.execute(
                text(
                    "SELECT rolsuper, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname=:name"
                ),
                {"name": role_name},
            ).one()
            assert not any(privileges)
            assert session.scalar(select(func.count()).select_from(User)) == 2
            assert session.scalar(select(func.count()).select_from(SessionToken)) == 0
            target = session.scalar(select(Target).where(Target.name == "restored-target"))
            assert unseal(restored, target.secret) == "restore-test-secret"
        with pytest.raises(ValueError, match="没有用户表"):
            restore_backup(restored, tmp_path / "snapshot")
    finally:
        if restored_db:
            restored_db.engine.dispose()
        with maintenance.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{destination_name}" WITH (FORCE)'))
            connection.execute(text(f'DROP ROLE IF EXISTS "{role_name}"'))
        maintenance.dispose()
