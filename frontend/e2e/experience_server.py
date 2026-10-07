import argparse
import json
import os
import secrets
from pathlib import Path

import uvicorn
from agentsec.api import create_app
from agentsec.cases import seed_cases
from agentsec.cli import migrate
from agentsec.config import Settings
from agentsec.db import Database
from agentsec.security import bootstrap_user
from cryptography.fernet import Fernet

os.umask(0o077)
parser = argparse.ArgumentParser(description="Create a new isolated UI acceptance database")
parser.add_argument("--data-dir", type=Path, required=True)
parser.add_argument("--port", type=int, default=8089)
args = parser.parse_args()
if not 1024 <= args.port <= 65535:
    parser.error("Port must be between 1024 and 65535")
root = args.data_dir.resolve()
root.mkdir(parents=True, exist_ok=False)
settings = Settings(
    database_url=f"sqlite:///{root}/platform.db",
    data_dir=root,
    master_key=Fernet.generate_key().decode(),
    target_hosts=frozenset({"127.0.0.1"}),
)
migrate(settings)
db = Database(settings)
credentials = {
    "username": "ux-admin",
    "password": secrets.token_urlsafe(24),
    "viewer": {"username": "ux-viewer", "password": secrets.token_urlsafe(24)},
}
with db.session.begin() as session:
    bootstrap_user(session, credentials["username"], credentials["password"])
    bootstrap_user(
        session, credentials["viewer"]["username"], credentials["viewer"]["password"], "viewer"
    )
    seed_cases(session)
(root / "login.json").write_text(json.dumps(credentials))
db.engine.dispose()
uvicorn.run(create_app(settings), host="127.0.0.1", port=args.port)
