import argparse
import asyncio
import getpass
import json
import os
import signal
from pathlib import Path

from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet
from dotenv import load_dotenv

from .cases import seed_cases
from .config import Settings
from .db import Database
from .security import bootstrap_user


def migrate(settings):
    root = Path(__file__).resolve().parents[2]
    config = Config(str(root / "alembic.ini"))
    config.attributes["settings"] = settings
    command.upgrade(config, "head")


def main():
    os.umask(0o077)
    load_dotenv(override=False)
    parser = argparse.ArgumentParser(description="Agent 安全评测平台")
    subs = parser.add_subparsers(dest="command", required=True)
    subs.add_parser("migrate")
    init = subs.add_parser("create-user")
    init.add_argument("--username", default="admin")
    init.add_argument("--role", choices=["admin", "operator", "viewer"], default="admin")
    subs.add_parser("seed")
    subs.add_parser("generate-key")
    subs.add_parser("worker-health")
    prune = subs.add_parser("prune-evidence")
    prune.add_argument("--days", type=int, default=90)
    prune.add_argument("--apply", action="store_true", help="执行清理；默认只预览")
    prune.add_argument("--services-stopped", action="store_true")
    for name, argument in [
        ("backup", "destination"),
        ("verify-backup", "source"),
        ("restore", "source"),
    ]:
        operation = subs.add_parser(name)
        operation.add_argument(argument)
        if name != "verify-backup":
            operation.add_argument(
                "--services-stopped", action="store_true", help="确认 API 和 Worker 已停止"
            )
    serve = subs.add_parser("serve")
    serve.add_argument("--host", default=os.getenv("AGENTSEC_BIND", "127.0.0.1"))
    serve.add_argument("--port", type=int, default=int(os.getenv("AGENTSEC_PORT", "8088")))
    worker = subs.add_parser("worker")
    worker.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if args.command == "generate-key":
        print(Fernet.generate_key().decode())
        return
    settings = Settings.load().validate()
    if args.command in {"backup", "verify-backup", "restore"}:
        from .backups import create_backup, restore_backup, verify_backup

        if args.command != "verify-backup" and not args.services_stopped:
            raise SystemExit("备份/恢复须先停止 API 与 Worker，再显式传入 --services-stopped")
        try:
            if args.command == "backup":
                create_backup(settings, args.destination)
            elif args.command == "restore":
                restore_backup(settings, args.source)
            else:
                verify_backup(settings, args.source)
        except (ValueError, OSError) as error:
            raise SystemExit(str(error)) from error
        print("操作完成；数据库、证据校验和与主密钥指纹已校验")
        return
    if args.command == "migrate":
        migrate(settings)
        print("数据库迁移完成")
        return
    db = Database(settings)
    if not db.ready():
        raise SystemExit("请先执行 agentsec migrate")
    if args.command == "worker-health":
        from .health import worker_healthy

        db.engine.dispose()
        raise SystemExit(0 if worker_healthy(settings) else 1)
    if args.command == "prune-evidence":
        from .retention import prune_evidence

        try:
            result = prune_evidence(settings, db, args.days, args.apply, args.services_stopped)
        except (ValueError, OSError) as error:
            raise SystemExit(str(error)) from error
        finally:
            db.engine.dispose()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if result.get("failed"):
            raise SystemExit(1)
        return
    if args.command == "create-user":
        password = getpass.getpass("密码（至少 12 字符）: ")
        if password != getpass.getpass("再次输入密码: "):
            raise SystemExit("两次密码不一致")
        with db.session.begin() as session:
            bootstrap_user(session, args.username, password, args.role)
        print("用户创建完成")
    elif args.command == "seed":
        with db.session.begin() as session:
            seed_cases(session)
        print("内置场景初始化完成")
    elif args.command == "serve":
        import uvicorn

        from .api import create_app

        uvicorn.run(create_app(settings), host=args.host, port=args.port, proxy_headers=False)
    elif args.command == "worker":
        from .worker import Worker

        runner = Worker(settings, db)

        def shutdown(signum, frame):
            runner.stopping = True

        signal.signal(signal.SIGTERM, shutdown)
        signal.signal(signal.SIGINT, shutdown)
        asyncio.run(runner.run_once() if args.once else runner.run())
    db.engine.dispose()


if __name__ == "__main__":
    main()
