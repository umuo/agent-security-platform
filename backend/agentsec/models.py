import time
import uuid

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def uid():
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(20), default="operator")
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)


class SessionToken(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    csrf_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[float] = mapped_column(Float, index=True)


class LoginThrottle(Base):
    __tablename__ = "login_throttles"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    until: Mapped[float] = mapped_column(Float)


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    asset_id: Mapped[str] = mapped_column(String(36), default=uid, index=True)
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(32))
    config: Mapped[dict] = mapped_column(JSON)
    secret: Mapped[str] = mapped_column(Text, default="")
    revision: Mapped[str] = mapped_column(String(64))
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    category: Mapped[str] = mapped_column(String(64), index=True)
    surface: Mapped[str] = mapped_column(String(64))
    spec: Mapped[dict] = mapped_column(JSON)
    revision: Mapped[str] = mapped_column(String(64))
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Evaluation(Base):
    __tablename__ = "evaluations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(160))
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"))
    target_snapshot: Mapped[dict] = mapped_column(JSON)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    idempotency_key: Mapped[str | None] = mapped_column(String(120), nullable=True)
    request_digest: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24), index=True, default="QUEUED")
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    lease_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_until: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[float] = mapped_column(Float, default=time.time, index=True)
    finished_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    budget: Mapped[dict] = mapped_column(JSON)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    __table_args__ = (UniqueConstraint("created_by", "idempotency_key"),)


class Attempt(Base):
    __tablename__ = "attempts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    evaluation_id: Mapped[str] = mapped_column(ForeignKey("evaluations.id"), index=True)
    case_id: Mapped[str] = mapped_column(String(80))
    case_snapshot: Mapped[dict] = mapped_column(JSON)
    repeat: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(24), default="PENDING")
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    started_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    finished_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    __table_args__ = (UniqueConstraint("evaluation_id", "case_id", "repeat"),)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    attempt_id: Mapped[str] = mapped_column(ForeignKey("attempts.id"), unique=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"))
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(32), default="OPEN")
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[float] = mapped_column(Float, default=time.time)


class Audit(Base):
    __tablename__ = "management_audit"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    actor_id: Mapped[str] = mapped_column(String(36))
    action: Mapped[str] = mapped_column(String(64))
    object_id: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[float] = mapped_column(Float, default=time.time, index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
