from pathlib import Path

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker


class Database:
    def __init__(self, settings):
        if settings.database_url.startswith("sqlite:///"):
            path = settings.database_url.removeprefix("sqlite:///")
            if path != ":memory:":
                Path(path).parent.mkdir(parents=True, exist_ok=True)
        kwargs = (
            {"connect_args": {"check_same_thread": False, "timeout": 15}}
            if settings.database_url.startswith("sqlite")
            else {}
        )
        self.engine = create_engine(settings.database_url, pool_pre_ping=True, **kwargs)
        if settings.database_url.startswith("sqlite"):

            @event.listens_for(self.engine, "connect")
            def configure(conn, record):
                conn.execute("PRAGMA foreign_keys=ON")
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA busy_timeout=15000")

        self.session = sessionmaker(self.engine, expire_on_commit=False)

    def ready(self):
        with self.engine.connect() as conn:
            return conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0001"
