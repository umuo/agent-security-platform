import hashlib
import json
import secrets
import time

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet
from fastapi import HTTPException, Request
from sqlalchemy import delete, select

from .models import Audit, SessionToken, User

PASSWORDS = PasswordHasher()
DUMMY_PASSWORD = PASSWORDS.hash(secrets.token_urlsafe(24))


def digest(value):
    if not isinstance(value, str):
        value = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(value.encode()).hexdigest()


def seal(settings, value):
    return Fernet(settings.master_key.encode()).encrypt(value.encode()).decode() if value else ""


def unseal(settings, value):
    return Fernet(settings.master_key.encode()).decrypt(value.encode()).decode() if value else ""


def verify_password(hashed, password):
    try:
        return PASSWORDS.verify(hashed, password)
    except (VerificationError, InvalidHashError):
        return False


def audit(db, actor_id, action, object_id, details=None):
    db.add(Audit(actor_id=actor_id, action=action, object_id=object_id, details=details or {}))


def current_user(request: Request):
    token = request.cookies.get("agentsec_session", "")
    if not token:
        raise HTTPException(401, "请登录")
    with request.app.state.db.session() as db:
        session = db.get(SessionToken, digest(token))
        user = (
            db.get(User, session.user_id) if session and session.expires_at > time.time() else None
        )
        if not user or user.disabled:
            raise HTTPException(401, "会话已过期")
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            csrf = request.headers.get("X-CSRF-Token", "")
            if not secrets.compare_digest(session.csrf_hash, digest(csrf)):
                raise HTTPException(403, "CSRF 校验失败")
        return user


def require_role(user, *roles):
    if user.role not in roles:
        raise HTTPException(403, "没有执行此操作的权限")


def create_session(db, settings, user):
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    db.execute(delete(SessionToken).where(SessionToken.expires_at < time.time()))
    db.add(
        SessionToken(
            token_hash=digest(token),
            user_id=user.id,
            csrf_hash=digest(csrf),
            expires_at=time.time() + settings.session_hours * 3600,
        )
    )
    return token, csrf


def bootstrap_user(db, username, password, role="admin"):
    if not 12 <= len(password) <= 256:
        raise ValueError("密码长度必须为 12–256")
    if db.scalar(select(User).where(User.username == username)):
        raise ValueError("用户已存在")
    user = User(username=username, password_hash=PASSWORDS.hash(password), role=role)
    db.add(user)
    db.flush()
    audit(db, user.id, "user.create", user.id, {"role": role})
    return user
