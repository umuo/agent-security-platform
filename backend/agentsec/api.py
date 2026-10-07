import re
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import IntegrityError

from .adapters import validate_target
from .budgets import usage_totals
from .comparisons import compare_jobs
from .config import Settings
from .db import Database
from .models import (
    Attempt,
    Audit,
    Case,
    Evaluation,
    Finding,
    LoginThrottle,
    SessionToken,
    Target,
    User,
    uid,
)
from .oracle import summarize
from .remediation import remediation
from .schemas import (
    CaseIn,
    EvaluationIn,
    FindingUpdate,
    LoginIn,
    PasswordChange,
    TargetIn,
    UserIn,
    UserUpdate,
)
from .security import (
    DUMMY_PASSWORD,
    PASSWORDS,
    audit,
    bootstrap_user,
    create_session,
    current_user,
    digest,
    require_role,
    seal,
    verify_password,
)


def target_data(row):
    return {
        "id": row.id,
        "asset_id": row.asset_id,
        "name": row.name,
        "kind": row.kind,
        "config": row.config,
        "revision": row.revision,
        "has_secret": bool(row.secret),
        "created_at": row.created_at,
    }


def case_data(row):
    return {
        "id": row.id,
        "name": row.name,
        "category": row.category,
        "surface": row.surface,
        "spec": row.spec,
        "revision": row.revision,
        "builtin": row.builtin,
    }


def attempt_data(row):
    return {
        "id": row.id,
        "case_id": row.case_id,
        "case_snapshot": row.case_snapshot,
        "repeat": row.repeat,
        "status": row.status,
        "result": row.result,
        "remediation": remediation(row.case_snapshot, row.result),
        "started_at": row.started_at,
        "finished_at": row.finished_at,
    }


def job_data(db, row, detail=False):
    attempts = db.scalars(
        select(Attempt)
        .where(Attempt.evaluation_id == row.id)
        .order_by(Attempt.case_id, Attempt.repeat)
    ).all()
    data = {
        "id": row.id,
        "name": row.name,
        "target_id": row.target_id,
        "target": row.target_snapshot,
        "status": row.status,
        "cancel_requested": row.cancel_requested,
        "created_at": row.created_at,
        "finished_at": row.finished_at,
        "error_code": row.error_code,
        "budget": row.budget,
        "budget_usage": usage_totals(attempts),
        "summary": summarize(attempts),
    }
    data["summary"]["gate_passed"] = (
        data["summary"]["gate_passed"] and row.status == "COMPLETED" and not row.error_code
    )
    if detail:
        data["attempts"] = [attempt_data(a) for a in attempts]
    return data


def create_app(settings=None):
    settings = (settings or Settings.load()).validate()
    database = Database(settings)

    @asynccontextmanager
    async def lifespan(app):
        if not database.ready():
            raise RuntimeError("数据库版本不匹配，请先执行 agentsec migrate")
        yield
        database.engine.dispose()

    app = FastAPI(
        title="Agent Security Platform",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/api/docs" if settings.mode == "local" else None,
        openapi_url="/api/openapi.json" if settings.mode == "local" else None,
    )
    app.state.settings, app.state.db = settings, database

    @app.middleware("http")
    async def boundaries(request, call_next):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            data = bytearray()
            async for chunk in request.stream():
                data.extend(chunk)
                if len(data) > 1048576:
                    return JSONResponse({"detail": "请求体超过 1 MiB"}, 413)
            request._body = bytes(data)
            origin = request.headers.get("Origin")
            expected_origin = settings.public_origin or str(request.base_url).rstrip("/")
            if origin and origin.rstrip("/") != expected_origin:
                return JSONResponse({"detail": "不允许跨站请求"}, 403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'"
        )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(IntegrityError)
    async def conflict(request, exception):
        return JSONResponse({"detail": "数据冲突，请刷新后重试"}, 409)

    @app.get("/health/live")
    def live():
        return {"status": "alive"}

    @app.get("/health/ready")
    def ready():
        try:
            return (
                JSONResponse({"status": "ready"}, 200)
                if database.ready()
                else JSONResponse({"status": "not_ready"}, 503)
            )
        except Exception:
            return JSONResponse({"status": "not_ready"}, 503)

    @app.post("/api/auth/login")
    def login(body: LoginIn, request: Request, response: Response):
        ip = request.client.host if request.client else "unknown"
        key = digest(ip + ":" + body.username.lower())
        with database.session.begin() as db:
            db.execute(delete(LoginThrottle).where(LoginThrottle.until < time.time()))
            throttle = db.get(LoginThrottle, key)
            if throttle and throttle.failures >= 8:
                raise HTTPException(429, "登录失败次数过多，请五分钟后重试")
            user = db.scalar(select(User).where(User.username == body.username))
            valid = verify_password(user.password_hash if user else DUMMY_PASSWORD, body.password)
            if not valid or not user or user.disabled:
                if throttle:
                    db.execute(
                        update(LoginThrottle)
                        .where(LoginThrottle.key == key)
                        .values(failures=LoginThrottle.failures + 1)
                    )
                else:
                    db.add(LoginThrottle(key=key, failures=1, until=time.time() + 300))
                audit(db, user.id if user else "anonymous", "auth.failed", "login")
                # 不能在事务中 raise 导致失败计数回滚。
                failed = True
            else:
                db.execute(delete(LoginThrottle).where(LoginThrottle.key == key))
                token, csrf = create_session(db, settings, user)
                audit(db, user.id, "auth.login", user.id)
                failed = False
        if failed:
            raise HTTPException(401, "用户名或密码错误")
        response.set_cookie(
            "agentsec_session",
            token,
            httponly=True,
            secure=settings.cookie_secure,
            samesite="strict",
            max_age=settings.session_hours * 3600,
            path="/",
        )
        response.set_cookie(
            "agentsec_csrf",
            csrf,
            httponly=False,
            secure=settings.cookie_secure,
            samesite="strict",
            max_age=settings.session_hours * 3600,
            path="/",
        )
        return {"username": user.username, "role": user.role, "csrf_token": csrf}

    @app.get("/api/auth/me")
    def me(user=Depends(current_user)):
        return {"id": user.id, "username": user.username, "role": user.role}

    @app.post("/api/auth/logout")
    def logout(request: Request, response: Response, user=Depends(current_user)):
        with database.session.begin() as db:
            db.execute(
                delete(SessionToken).where(
                    SessionToken.token_hash == digest(request.cookies["agentsec_session"])
                )
            )
            audit(db, user.id, "auth.logout", user.id)
        response.delete_cookie("agentsec_session")
        response.delete_cookie("agentsec_csrf")
        return {"ok": True}

    @app.post("/api/users", status_code=201)
    def users(body: UserIn, user=Depends(current_user)):
        require_role(user, "admin")
        with database.session.begin() as db:
            try:
                row = bootstrap_user(db, body.username, body.password, body.role)
            except ValueError as error:
                raise HTTPException(400, str(error)) from error
        return {"id": row.id, "username": row.username, "role": row.role}

    @app.get("/api/users")
    def list_users(user=Depends(current_user)):
        require_role(user, "admin")
        with database.session() as db:
            return [
                {"id": row.id, "username": row.username, "role": row.role, "disabled": row.disabled}
                for row in db.scalars(select(User).order_by(User.username).limit(500))
            ]

    @app.patch("/api/users/{ident}")
    def update_user(ident: str, body: UserUpdate, user=Depends(current_user)):
        require_role(user, "admin")
        if all(value is None for value in body.model_dump().values()):
            raise HTTPException(400, "至少指定一个变更字段")
        with database.session.begin() as db:
            # PostgreSQL 使用固定事务锁；SQLite 用无变化写入获取数据库写锁。
            # 不依赖某个可变化的管理员行，防止同时移除最后管理员。
            if db.bind.dialect.name == "postgresql":
                db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": 731900721})
            else:
                anchor = db.scalar(select(User.id).order_by(User.id).limit(1))
                db.execute(update(User).where(User.id == anchor).values(username=User.username))
            actor = db.get(User, user.id)
            if not actor or actor.disabled or actor.role != "admin":
                raise HTTPException(403, "管理员权限已失效")
            row = db.get(User, ident)
            if not row:
                raise HTTPException(404, "账号不存在")
            role = body.role if body.role is not None else row.role
            disabled = body.disabled if body.disabled is not None else row.disabled
            if row.role == "admin" and not row.disabled and (role != "admin" or disabled):
                remaining = db.scalar(
                    select(func.count())
                    .select_from(User)
                    .where(User.role == "admin", User.disabled.is_(False), User.id != ident)
                )
                if not remaining:
                    raise HTTPException(409, "必须保留至少一个可用管理员")
            row.role, row.disabled = role, disabled
            if body.new_password is not None:
                row.password_hash = PASSWORDS.hash(body.new_password)
            db.execute(delete(SessionToken).where(SessionToken.user_id == ident))
            audit(
                db,
                user.id,
                "user.update",
                ident,
                {
                    "role": role,
                    "disabled": disabled,
                    "password_reset": body.new_password is not None,
                },
            )
            return {
                "id": row.id,
                "username": row.username,
                "role": row.role,
                "disabled": row.disabled,
            }

    @app.post("/api/auth/change-password")
    def change_password(body: PasswordChange, response: Response, user=Depends(current_user)):
        with database.session.begin() as db:
            row = db.scalar(select(User).where(User.id == user.id).with_for_update())
            if not verify_password(row.password_hash, body.current_password):
                raise HTTPException(400, "当前密码不正确")
            row.password_hash = PASSWORDS.hash(body.new_password)
            db.execute(delete(SessionToken).where(SessionToken.user_id == row.id))
            audit(db, user.id, "user.password_change", row.id)
        response.delete_cookie("agentsec_session")
        response.delete_cookie("agentsec_csrf")
        return {"ok": True, "requires_login": True}

    @app.get("/api/targets")
    def targets(user=Depends(current_user)):
        with database.session() as db:
            return [
                target_data(x)
                for x in db.scalars(
                    select(Target)
                    .where(Target.archived.is_(False))
                    .order_by(Target.created_at.desc())
                    .limit(500)
                )
            ]

    @app.post("/api/targets", status_code=201)
    def create_target(body: TargetIn, user=Depends(current_user)):
        require_role(user, "admin")
        try:
            validate_target(settings, body.kind, body.config)
        except ValueError as error:
            raise HTTPException(400, str(error)) from error
        with database.session.begin() as db:
            parent = db.get(Target, body.parent_target_id) if body.parent_target_id else None
            if body.parent_target_id and not parent:
                raise HTTPException(404, "父修订不存在")
            row = Target(
                name=body.name,
                kind=body.kind,
                config=body.config,
                secret=seal(settings, body.secret),
                revision=digest(
                    {"kind": body.kind, "config": body.config, "secret_digest": digest(body.secret)}
                ),
            )
            if parent:
                row.asset_id = parent.asset_id
            db.add(row)
            db.flush()
            audit(db, user.id, "target.create", row.id, {"kind": row.kind})
        return target_data(row)

    @app.delete("/api/targets/{ident}")
    def archive_target(ident: str, user=Depends(current_user)):
        require_role(user, "admin")
        with database.session.begin() as db:
            row = db.get(Target, ident)
            if not row:
                raise HTTPException(404, "目标不存在")
            row.archived = True
            audit(db, user.id, "target.archive", ident)
        return {"ok": True}

    @app.get("/api/cases")
    def cases(user=Depends(current_user)):
        with database.session() as db:
            return [
                case_data(x)
                for x in db.scalars(
                    select(Case)
                    .where(Case.enabled.is_(True))
                    .order_by(Case.category, Case.id)
                    .limit(1000)
                )
            ]

    @app.post("/api/cases", status_code=201)
    def create_case(body: CaseIn, user=Depends(current_user)):
        require_role(user, "admin", "operator")
        data = body.model_dump()
        name, category, surface = (data.pop(k) for k in ["name", "category", "surface"])
        with database.session.begin() as db:
            row = Case(
                id="custom-" + uid(),
                name=name,
                category=category,
                surface=surface,
                spec=data,
                revision=digest(body.model_dump()),
                builtin=False,
            )
            db.add(row)
            audit(db, user.id, "case.create", row.id)
        return case_data(row)

    @app.get("/api/evaluations")
    def evaluations(limit: int = 50, user=Depends(current_user)):
        with database.session() as db:
            return [
                job_data(db, row)
                for row in db.scalars(
                    select(Evaluation)
                    .order_by(Evaluation.created_at.desc())
                    .limit(max(1, min(limit, 200)))
                )
            ]

    @app.post("/api/evaluations", status_code=201)
    def create_evaluation(body: EvaluationIn, request: Request, user=Depends(current_user)):
        require_role(user, "admin", "operator")
        key = request.headers.get("Idempotency-Key")
        if key and not re.fullmatch(r"[a-zA-Z0-9_.-]{1,120}", key):
            raise HTTPException(400, "Idempotency-Key 非法")
        request_digest = digest(body.model_dump())
        with database.session.begin() as db:
            existing = (
                db.scalar(
                    select(Evaluation).where(
                        Evaluation.created_by == user.id, Evaluation.idempotency_key == key
                    )
                )
                if key
                else None
            )
            if existing:
                if existing.request_digest != request_digest:
                    raise HTTPException(409, "同一个幂等键不能对应不同请求")
                return job_data(db, existing)
            target = db.get(Target, body.target_id)
            if not target or target.archived:
                raise HTTPException(404, "目标不存在")
            rows = [db.get(Case, ident) for ident in body.case_ids]
            if any(row is None or not row.enabled for row in rows):
                raise HTTPException(400, "用例不存在或已禁用")
            if (
                db.scalar(
                    select(func.count())
                    .select_from(Evaluation)
                    .where(Evaluation.status.in_(["QUEUED", "RUNNING"]))
                )
                >= 100
            ):
                raise HTTPException(429, "任务队列已满")
            job = Evaluation(
                name=body.name,
                target_id=target.id,
                target_snapshot=target_data(target),
                created_by=user.id,
                idempotency_key=key,
                request_digest=request_digest,
                budget=body.budget.model_dump(),
            )
            db.add(job)
            db.flush()
            for case in rows:
                for repeat in range(body.repeats):
                    db.add(
                        Attempt(
                            evaluation_id=job.id,
                            case_id=case.id,
                            case_snapshot=case_data(case),
                            repeat=repeat,
                        )
                    )
            audit(db, user.id, "evaluation.create", job.id, {"attempts": len(rows) * body.repeats})
            db.flush()
            return job_data(db, job)

    @app.get("/api/evaluations/{ident}")
    def evaluation(ident: str, user=Depends(current_user)):
        with database.session() as db:
            row = db.get(Evaluation, ident)
            if not row:
                raise HTTPException(404, "评测不存在")
            return job_data(db, row, True)

    @app.post("/api/evaluations/{ident}/cancel")
    def cancel(ident: str, user=Depends(current_user)):
        require_role(user, "admin", "operator")
        with database.session.begin() as db:
            job = db.get(Evaluation, ident)
            if not job:
                raise HTTPException(404, "评测不存在")
            cancelled = db.execute(
                update(Evaluation)
                .where(Evaluation.id == ident, Evaluation.status == "QUEUED")
                .values(status="CANCELLED", finished_at=time.time(), cancel_requested=True)
            ).rowcount
            if cancelled:
                db.execute(
                    update(Attempt)
                    .where(Attempt.evaluation_id == ident)
                    .values(
                        status="CANCELLED",
                        finished_at=time.time(),
                        result={
                            "verdict": "INCONCLUSIVE",
                            "evidence": {"complete": False, "error_code": "CANCELLED"},
                        },
                    )
                )
            db.execute(
                update(Evaluation)
                .where(Evaluation.id == ident, Evaluation.status == "RUNNING")
                .values(cancel_requested=True)
            )
            db.refresh(job)
            audit(db, user.id, "evaluation.cancel", ident)
        return {"ok": True, "status": job.status, "cancel_requested": job.cancel_requested}

    @app.get("/api/evaluations/{ident}/report")
    def report(ident: str, user=Depends(current_user)):
        with database.session() as db:
            row = db.get(Evaluation, ident)
            if not row:
                raise HTTPException(404, "评测不存在")
            audit(db, user.id, "report.export", ident)
            data = job_data(db, row, True)
            db.commit()
            return JSONResponse(
                data,
                headers={"Content-Disposition": f'attachment; filename="evaluation-{ident}.json"'},
            )

    @app.get("/api/comparisons")
    def comparison(baseline_id: str, candidate_id: str, user=Depends(current_user)):
        if baseline_id == candidate_id:
            raise HTTPException(400, "请选择两次独立评测")
        with database.session() as db:
            before, after = db.get(Evaluation, baseline_id), db.get(Evaluation, candidate_id)
            if not before or not after:
                raise HTTPException(404, "评测不存在")
            if before.target_snapshot["asset_id"] != after.target_snapshot["asset_id"]:
                raise HTTPException(400, "只能比较同一资产的评测")
            baseline = list(db.scalars(select(Attempt).where(Attempt.evaluation_id == baseline_id)))
            candidate = list(
                db.scalars(select(Attempt).where(Attempt.evaluation_id == candidate_id))
            )
            return compare_jobs(before, after, baseline, candidate)

    @app.get("/api/findings")
    def findings(user=Depends(current_user)):
        with database.session() as db:
            return [
                {
                    "id": f.id,
                    "attempt_id": f.attempt_id,
                    "target_id": f.target_id,
                    "title": f.title,
                    "severity": f.severity,
                    "status": f.status,
                    "note": f.note,
                    "created_at": f.created_at,
                    "remediation": remediation(a.case_snapshot, a.result),
                }
                for f, a in db.execute(
                    select(Finding, Attempt)
                    .join(Attempt, Finding.attempt_id == Attempt.id)
                    .order_by(Finding.created_at.desc())
                    .limit(500)
                )
            ]

    @app.patch("/api/findings/{ident}")
    def update_finding(ident: str, body: FindingUpdate, user=Depends(current_user)):
        require_role(user, "admin", "operator")
        with database.session.begin() as db:
            finding = db.get(Finding, ident)
            if not finding:
                raise HTTPException(404, "问题不存在")
            if body.status in {"VERIFIED", "CLOSED"}:
                attempt = (
                    db.get(Attempt, body.retest_attempt_id) if body.retest_attempt_id else None
                )
                original = db.get(Attempt, finding.attempt_id)
                job = db.get(Evaluation, attempt.evaluation_id) if attempt else None
                expected = (
                    "CLEAN_SUCCEEDED"
                    if (original.result or {}).get("verdict")
                    in {"FALSE_POSITIVE", "UNSAFE_COMPLETION"}
                    else "ATTACK_PREVENTED"
                )
                if (
                    not attempt
                    or attempt.id == original.id
                    or attempt.case_snapshot["revision"] != original.case_snapshot["revision"]
                    or not job
                    or job.target_snapshot["asset_id"] != db.get(Target, finding.target_id).asset_id
                    or (attempt.result or {}).get("verdict") != expected
                ):
                    raise HTTPException(400, "需要同一用例、同一资产且通过的独立复测证据")
            finding.status, finding.note = body.status, body.note
            audit(
                db,
                user.id,
                "finding.update",
                ident,
                {"status": body.status, "retest_attempt_id": body.retest_attempt_id},
            )
        return {"ok": True}

    @app.get("/api/audit")
    def audits(user=Depends(current_user)):
        require_role(user, "admin")
        with database.session() as db:
            return [
                {
                    "id": x.id,
                    "actor_id": x.actor_id,
                    "action": x.action,
                    "object_id": x.object_id,
                    "created_at": x.created_at,
                    "details": x.details,
                }
                for x in db.scalars(select(Audit).order_by(Audit.created_at.desc()).limit(200))
            ]

    @app.get("/api/overview")
    def overview(user=Depends(current_user)):
        with database.session() as db:
            return {
                "targets": db.scalar(
                    select(func.count()).select_from(Target).where(Target.archived.is_(False))
                ),
                "cases": db.scalar(select(func.count()).select_from(Case)),
                "evaluations": db.scalar(select(func.count()).select_from(Evaluation)),
                "findings": db.scalar(
                    select(func.count())
                    .select_from(Finding)
                    .where(Finding.status.not_in(["CLOSED", "ACCEPTED_RISK"]))
                ),
                "mode": settings.mode,
            }

    dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"

    @app.get("/{path:path}")
    def frontend(path: str):
        if path.startswith(("api/", "health/")):
            raise HTTPException(404, "接口不存在")
        requested = (dist / path).resolve()
        if dist.resolve() not in requested.parents and requested != dist.resolve():
            raise HTTPException(404)
        if requested.is_file():
            return FileResponse(requested)
        if (dist / "index.html").exists():
            return FileResponse(dist / "index.html")
        raise HTTPException(503, "前端尚未构建，请执行 npm run build")

    return app
