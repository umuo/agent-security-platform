"""离线应用备份：数据库与证据文件，主密钥由独立的秘密管理流程保管。"""

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

from sqlalchemy import delete, select, text, update
from sqlalchemy.engine import make_url

from .db import Database
from .models import Attempt, Evaluation, SessionToken


def checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1048576):
            digest.update(block)
    return digest.hexdigest()


def pg_environment(settings):
    url = make_url(settings.database_url)
    env = dict(os.environ)
    # 连接凭据只通过子进程环境传递，不进入 argv、备份清单或错误文本。
    values = {
        "PGHOST": url.host,
        "PGPORT": str(url.port) if url.port else None,
        "PGUSER": url.username,
        "PGPASSWORD": url.password,
        "PGDATABASE": url.database,
    }
    for name, value in values.items():
        env.pop(name, None)
        if value is not None:
            env[name] = value
    for name in ["host", "port", "sslmode", "sslrootcert", "sslcert", "sslkey", "options"]:
        if name in url.query:
            env["PG" + name.upper()] = url.query[name]
    return env


def pg_command(name, args, settings):
    binary = shutil.which(name)
    if not binary:
        raise ValueError(f"需要 {name}，客户端版本必须不低于数据库服务端")
    try:
        result = subprocess.run(
            [binary, *args], env=pg_environment(settings), capture_output=True, timeout=900
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(f"{name} 执行失败") from error
    if result.returncode:
        raise ValueError(f"{name} 执行失败；检查数据库权限与客户端版本")


def create_backup(settings, destination):
    destination = Path(destination).resolve()
    if destination.exists() or destination.is_relative_to(settings.data_dir.resolve()):
        raise ValueError("备份目标必须是数据目录之外的全新目录")
    database = Database(settings)
    try:
        with database.session() as session:
            active = session.scalar(
                select(Evaluation.id).where(Evaluation.status.in_(["QUEUED", "RUNNING"])).limit(1)
            )
            if active:
                raise ValueError(
                    "先停止接单并结束或取消活动任务，再停止 API 与 Worker 进行离线备份"
                )
        destination.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=".agentsec-backup-", dir=destination.parent))
        try:
            url = make_url(settings.database_url)
            dialect = url.get_backend_name()
            schema = None
            if dialect == "sqlite":
                snapshot = staging / "database.sqlite"
                with sqlite3.connect(url.database) as source, sqlite3.connect(snapshot) as target:
                    source.backup(target)
                    target.execute("PRAGMA journal_mode=DELETE")
                    if target.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                        raise ValueError("数据库完整性校验失败")
            elif dialect == "postgresql":
                snapshot = staging / "database.dump"
                with database.engine.connect() as connection:
                    schema = connection.execute(text("SELECT current_schema()")).scalar()
                if not schema:
                    raise ValueError("无法确定应用数据库 schema")
                pg_command(
                    "pg_dump",
                    [
                        "--format=custom",
                        "--no-owner",
                        "--no-acl",
                        "--schema=" + '"' + schema.replace('"', '""') + '"',
                        "--file=" + str(snapshot),
                    ],
                    settings,
                )
            else:
                raise ValueError("不支持此数据库类型")
            for name in ["inspect", "sdk-attempts"]:
                source_dir = settings.data_dir / name
                if source_dir.exists():
                    # 不跟随证据目录中的符号链接，避免归档意外的外部数据。
                    if (
                        any(path.is_symlink() for path in source_dir.rglob("*"))
                        or source_dir.is_symlink()
                    ):
                        raise ValueError("证据目录包含符号链接")
                    shutil.copytree(source_dir, staging / name)
            files = {}
            for path in staging.rglob("*"):
                if path.is_file():
                    path.chmod(0o600)
                    files[path.relative_to(staging).as_posix()] = checksum(path)
                elif path.is_dir():
                    path.chmod(0o700)
            manifest = {
                "format_version": 1,
                "created_at": time.time(),
                "dialect": dialect,
                "schema": schema,
                "database_file": snapshot.name,
                "files": files,
                "master_key_fingerprint": hashlib.sha256(settings.master_key.encode()).hexdigest(),
            }
            (staging / "manifest.json").write_text(json.dumps(manifest, indent=2))
            (staging / "manifest.json").chmod(0o600)
            # 目录重命名之前再次拒绝覆盖，避免误用旧备份位置。
            if destination.exists():
                raise ValueError("备份目标已存在")
            staging.rename(destination)
            return {"files": len(files), "dialect": dialect}
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
    finally:
        database.engine.dispose()


def verify_backup(settings, source):
    source = Path(source).resolve()
    manifest = json.loads((source / "manifest.json").read_text())
    if manifest.get("format_version") != 1 or not isinstance(manifest.get("files"), dict):
        raise ValueError("备份清单格式不支持")
    if manifest.get("dialect") not in {"sqlite", "postgresql"}:
        raise ValueError("备份数据库类型不支持")
    expected_database = "database.sqlite" if manifest["dialect"] == "sqlite" else "database.dump"
    if manifest.get("database_file") != expected_database:
        raise ValueError("备份数据库文件名不合法")
    paths = list(source.rglob("*"))
    if any(path.is_symlink() for path in paths):
        raise ValueError("备份不能包含符号链接")
    actual_files = {path.relative_to(source).as_posix() for path in paths if path.is_file()} - {
        "manifest.json"
    }
    if actual_files != set(manifest["files"]):
        raise ValueError("备份包含未列入清单或缺失的文件")
    if (
        manifest.get("master_key_fingerprint")
        != hashlib.sha256(settings.master_key.encode()).hexdigest()
    ):
        raise ValueError("主密钥与备份不匹配")
    for name, expected in manifest["files"].items():
        path = source / name
        if path.is_symlink() or not path.resolve().is_relative_to(source) or not path.is_file():
            raise ValueError("备份路径或文件不合法")
        if checksum(path) != expected:
            raise ValueError("备份文件校验和不匹配")
    if manifest.get("database_file") not in manifest["files"]:
        raise ValueError("备份缺少数据库文件")
    return manifest


def restore_backup(settings, source):
    source = Path(source).resolve()
    manifest = verify_backup(settings, source)
    url = make_url(settings.database_url)
    if url.get_backend_name() != manifest["dialect"]:
        raise ValueError("恢复目标数据库类型不同")
    for name in ["inspect", "sdk-attempts"]:
        if (settings.data_dir / name).exists():
            raise ValueError("恢复目标证据目录必须为空")
    if manifest["dialect"] == "sqlite":
        destination = Path(url.database)
        if destination.exists():
            raise ValueError("恢复目标 SQLite 文件必须不存在")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with (source / manifest["database_file"]).open("rb") as input_file:
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output_file:
                shutil.copyfileobj(input_file, output_file)
    else:
        database = Database(settings)
        try:
            with database.engine.connect() as connection:
                count = connection.execute(
                    text(
                        "SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON c.relnamespace=n.oid WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' AND c.relkind IN ('r','p','v','m','S','f')"
                    )
                ).scalar()
                if count:
                    raise ValueError("恢复目标 PostgreSQL 数据库必须没有用户表")
            pg_command(
                "pg_restore",
                [
                    "--clean",
                    "--if-exists",
                    "--no-owner",
                    "--no-acl",
                    "--single-transaction",
                    "--exit-on-error",
                    "--dbname=" + (url.database or ""),
                    str(source / manifest["database_file"]),
                ],
                settings,
            )
        finally:
            database.engine.dispose()
    for name in ["inspect", "sdk-attempts"]:
        if (source / name).exists():
            shutil.copytree(source / name, settings.data_dir / name)
    database = Database(settings)
    try:
        if not database.ready():
            raise ValueError("恢复数据库与当前程序迁移版本不匹配")
        with database.session.begin() as session:
            session.execute(delete(SessionToken))
            ids = list(
                session.scalars(
                    select(Evaluation.id).where(Evaluation.status.in_(["RUNNING", "QUEUED"]))
                )
            )
            if ids:
                session.execute(
                    update(Evaluation)
                    .where(Evaluation.id.in_(ids))
                    .values(
                        status="FAILED",
                        error_code="RESTORED_BACKUP",
                        lease_token=None,
                        lease_until=None,
                        finished_at=time.time(),
                    )
                )
                session.execute(
                    update(Attempt)
                    .where(
                        Attempt.evaluation_id.in_(ids), Attempt.status.in_(["PENDING", "RUNNING"])
                    )
                    .values(
                        status="INTERRUPTED",
                        finished_at=time.time(),
                        result={
                            "verdict": "INCONCLUSIVE",
                            "evidence": {"complete": False, "error_code": "RESTORED_BACKUP"},
                        },
                    )
                )
        return {"dialect": manifest["dialect"], "sessions_revoked": True}
    finally:
        database.engine.dispose()
