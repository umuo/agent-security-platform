import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from dotenv import load_dotenv
from sqlalchemy.engine import make_url


@dataclass
class Settings:
    mode: str = "local"
    database_url: str = "sqlite:///data/platform.db"
    data_dir: Path = Path("data")
    master_key: str = ""
    target_hosts: frozenset[str] = field(default_factory=frozenset)
    cookie_secure: bool = False
    session_hours: int = 8
    lease_seconds: int = 30
    sdk_repo: str = ""
    public_origin: str = ""
    observer_endpoint: str = ""
    observer_token: str = field(default="", repr=False)

    @classmethod
    def load(cls):
        load_dotenv(override=False)
        master_key = os.getenv("AGENTSEC_MASTER_KEY", "")
        master_file = os.getenv("AGENTSEC_MASTER_KEY_FILE", "")
        database_url = os.getenv("AGENTSEC_DATABASE_URL", "sqlite:///data/platform.db")
        database_password_file = os.getenv("AGENTSEC_DATABASE_PASSWORD_FILE", "")
        observer_file = os.getenv("AGENTSEC_OBSERVER_TOKEN_FILE", "")

        def read_secret(path):
            with Path(path).open("rb") as stream:
                content = stream.read(8193)
            if len(content) > 8192:
                raise ValueError("Secret file exceeds size limit")
            return content.decode().strip()

        if master_file:
            if master_key:
                raise ValueError("Configure only one master key source")
            master_key = read_secret(master_file)
        if database_password_file:
            url = make_url(database_url)
            if url.password is not None:
                raise ValueError("Configure only one database password source")
            database_url = url.set(password=read_secret(database_password_file)).render_as_string(
                hide_password=False
            )
        return cls(
            mode=os.getenv("AGENTSEC_MODE", "local"),
            database_url=database_url,
            data_dir=Path(os.getenv("AGENTSEC_DATA_DIR", "data")),
            master_key=master_key,
            target_hosts=frozenset(
                x.strip().lower()
                for x in os.getenv("AGENTSEC_TARGET_HOSTS", "").split(",")
                if x.strip()
            ),
            cookie_secure=os.getenv("AGENTSEC_COOKIE_SECURE", "false").lower() == "true",
            session_hours=int(os.getenv("AGENTSEC_SESSION_HOURS", "8")),
            lease_seconds=int(os.getenv("AGENTSEC_LEASE_SECONDS", "30")),
            sdk_repo=os.getenv("AGENTSEC_SDK_REPO", ""),
            public_origin=os.getenv("AGENTSEC_PUBLIC_ORIGIN", "").rstrip("/"),
            observer_endpoint=os.getenv("AGENTSEC_OBSERVER_ENDPOINT", ""),
            observer_token=read_secret(observer_file) if observer_file else "",
        )

    def validate(self):
        if self.mode not in {"local", "production"}:
            raise ValueError("AGENTSEC_MODE must be local or production")
        if bool(self.observer_endpoint) != bool(self.observer_token):
            raise ValueError("Observer endpoint and token file must be configured together")
        if not 1 <= self.session_hours <= 24 or not 15 <= self.lease_seconds <= 300:
            raise ValueError("Invalid session or lease duration")
        if self.mode == "production":
            if not self.database_url.startswith("postgresql"):
                raise ValueError("Production requires PostgreSQL")
            if not self.master_key or not self.cookie_secure:
                raise ValueError("Production requires explicit master key and secure cookies")
            if not self.public_origin:
                raise ValueError("Production requires AGENTSEC_PUBLIC_ORIGIN")
        if self.public_origin:
            origin = urlsplit(self.public_origin)
            if (
                origin.scheme not in {"http", "https"}
                or not origin.hostname
                or origin.path
                or origin.query
                or origin.fragment
                or origin.username
                or origin.password
            ):
                raise ValueError(
                    "AGENTSEC_PUBLIC_ORIGIN must be a valid origin without path or credentials"
                )
            if self.mode == "production" and origin.scheme != "https":
                raise ValueError("Production public origin requires HTTPS")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        if not self.master_key:
            path = self.data_dir / "master.key"
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, "w") as f:
                    f.write(Fernet.generate_key().decode())
            self.master_key = path.read_text().strip()
        Fernet(self.master_key.encode())
        return self
