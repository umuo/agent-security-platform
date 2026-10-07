import asyncio
import secrets
import time
from types import SimpleNamespace

from sqlalchemy import select, update

from .budgets import DEFAULT_JOB_LIMITS, remaining_budget, usage_totals
from .engine import configure_inspect, evaluate_attempt, finalize_evidence, interrupted_result
from .health import write_worker_health
from .models import Attempt, Evaluation, Finding, Target
from .security import unseal


class Worker:
    def __init__(self, settings, db):
        self.settings, self.db = settings, db
        self.stopping = False
        configure_inspect(settings)

    def recover_expired(self):
        now = time.time()
        with self.db.session.begin() as db:
            stale = db.scalars(
                select(Evaluation).where(
                    Evaluation.status == "RUNNING", Evaluation.lease_until < now
                )
            ).all()
            for job in stale:
                # CAS 防止同时到达的续约/其他恢复者被覆盖；失联不自动重发有副作用请求。
                changed = db.execute(
                    update(Evaluation)
                    .where(
                        Evaluation.id == job.id,
                        Evaluation.status == "RUNNING",
                        Evaluation.lease_until < now,
                    )
                    .values(
                        status="FAILED",
                        error_code="WORKER_LEASE_EXPIRED",
                        lease_token=None,
                        lease_until=None,
                        finished_at=now,
                    )
                ).rowcount
                if changed:
                    db.execute(
                        update(Attempt)
                        .where(
                            Attempt.evaluation_id == job.id,
                            Attempt.status.in_(["PENDING", "RUNNING"]),
                        )
                        .values(
                            status="INTERRUPTED",
                            finished_at=now,
                            result={
                                "verdict": "INCONCLUSIVE",
                                "evidence": {
                                    "complete": False,
                                    "error_code": "WORKER_LEASE_EXPIRED",
                                },
                            },
                        )
                    )

    def claim(self):
        self.recover_expired()
        token = secrets.token_hex(24)
        with self.db.session.begin() as db:
            ids = db.scalars(
                select(Evaluation.id)
                .where(Evaluation.status == "QUEUED", Evaluation.cancel_requested.is_(False))
                .order_by(Evaluation.created_at)
                .limit(10)
            ).all()
            for ident in ids:
                changed = db.execute(
                    update(Evaluation)
                    .where(
                        Evaluation.id == ident,
                        Evaluation.status == "QUEUED",
                        Evaluation.cancel_requested.is_(False),
                    )
                    .values(
                        status="RUNNING",
                        lease_token=token,
                        lease_until=time.time() + self.settings.lease_seconds,
                    )
                ).rowcount
                if changed:
                    return ident, token
        return None

    def alive(self, job_id, token):
        with self.db.session() as db:
            job = db.get(Evaluation, job_id)
            return bool(
                job
                and job.status == "RUNNING"
                and job.lease_token == token
                and not job.cancel_requested
                and job.lease_until > time.time()
            )

    async def heartbeat(self, job_id, token, stop):
        while not stop.is_set():
            with self.db.session.begin() as db:
                changed = db.execute(
                    update(Evaluation)
                    .where(
                        Evaluation.id == job_id,
                        Evaluation.status == "RUNNING",
                        Evaluation.lease_token == token,
                        Evaluation.lease_until > time.time(),
                    )
                    .values(lease_until=time.time() + self.settings.lease_seconds)
                ).rowcount
            if not changed:
                return
            write_worker_health(self.settings)
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.settings.lease_seconds / 3)
            except TimeoutError:
                pass

    def save(self, job_id, token, attempt_id, result, *, interrupted=False):
        with self.db.session.begin() as db:
            # 写锁/CAS 与租约共用同一事务，旧 Worker 不能在恢复后写最终结果。
            changed = db.execute(
                update(Evaluation)
                .where(
                    Evaluation.id == job_id,
                    Evaluation.status == "RUNNING",
                    Evaluation.lease_token == token,
                    Evaluation.lease_until > time.time(),
                )
                .values(lease_until=time.time() + self.settings.lease_seconds)
            ).rowcount
            if not changed:
                return False
            attempt = db.get(Attempt, attempt_id)
            if not attempt or attempt.evaluation_id != job_id or attempt.status != "RUNNING":
                return False
            attempt.status = "INTERRUPTED" if interrupted else "COMPLETED"
            attempt.result = result
            attempt.finished_at = time.time()
            job = db.get(Evaluation, job_id)
            if result["verdict"] in {"ATTACK_SUCCEEDED", "FALSE_POSITIVE", "UNSAFE_COMPLETION"}:
                db.add(
                    Finding(
                        attempt_id=attempt_id,
                        target_id=job.target_id,
                        title=attempt.case_snapshot["name"],
                        severity="MEDIUM" if result["verdict"] == "FALSE_POSITIVE" else "HIGH",
                    )
                )
            return True

    def start_attempt(self, job_id, token, attempt_id):
        with self.db.session.begin() as db:
            changed = db.execute(
                update(Evaluation)
                .where(
                    Evaluation.id == job_id,
                    Evaluation.status == "RUNNING",
                    Evaluation.lease_token == token,
                    Evaluation.lease_until > time.time(),
                    Evaluation.cancel_requested.is_(False),
                )
                .values(lease_until=time.time() + self.settings.lease_seconds)
            ).rowcount
            if not changed:
                return None
            attempt = db.get(Attempt, attempt_id)
            if not attempt or attempt.evaluation_id != job_id or attempt.status != "PENDING":
                return None
            attempt.status = "RUNNING"
            attempt.started_at = time.time()
            return attempt.case_snapshot

    def stop_for_budget(self, job_id, token, code):
        now = time.time()
        with self.db.session.begin() as db:
            changed = db.execute(
                update(Evaluation)
                .where(
                    Evaluation.id == job_id,
                    Evaluation.status == "RUNNING",
                    Evaluation.lease_token == token,
                    Evaluation.lease_until > now,
                    Evaluation.cancel_requested.is_(False),
                )
                .values(
                    status="FAILED",
                    error_code=code,
                    finished_at=now,
                    lease_token=None,
                    lease_until=None,
                )
            ).rowcount
            if not changed:
                return False
            db.execute(
                update(Attempt)
                .where(Attempt.evaluation_id == job_id, Attempt.status == "PENDING")
                .values(
                    status="INTERRUPTED",
                    finished_at=now,
                    result={
                        "verdict": "INCONCLUSIVE",
                        "evidence": {
                            "complete": False,
                            "error_code": code,
                            "tokens": 0,
                            "turns": 0,
                            "tool_calls": 0,
                            "usage_complete": True,
                        },
                    },
                )
            )
            return True

    def finish(self, job_id, token):
        with self.db.session.begin() as db:
            # 获取事务写锁并检查租约；过期所有者不能关闭或取消新状态。
            changed = db.execute(
                update(Evaluation)
                .where(
                    Evaluation.id == job_id,
                    Evaluation.status == "RUNNING",
                    Evaluation.lease_token == token,
                    Evaluation.lease_until > time.time(),
                )
                .values(lease_until=time.time() + self.settings.lease_seconds)
            ).rowcount
            if not changed:
                return False
            job = db.get(Evaluation, job_id)
            pending = db.scalars(
                select(Attempt).where(
                    Attempt.evaluation_id == job_id,
                    Attempt.status.in_(["PENDING", "RUNNING"]),
                )
            ).all()
            for attempt in pending:
                attempt.status = "CANCELLED"
                attempt.finished_at = time.time()
                attempt.result = {
                    "verdict": "INCONCLUSIVE",
                    "evidence": {"complete": False, "error_code": "CANCELLED"},
                }
            interrupted = db.scalar(
                select(Attempt.id)
                .where(Attempt.evaluation_id == job_id, Attempt.status == "INTERRUPTED")
                .limit(1)
            )
            job.status = (
                "CANCELLED" if pending or interrupted or job.cancel_requested else "COMPLETED"
            )
            job.finished_at = time.time()
            job.lease_token = None
            job.lease_until = None
            return True

    async def run_job(self, job_id, token):
        started = time.monotonic()
        stop = asyncio.Event()
        beat = asyncio.create_task(self.heartbeat(job_id, token, stop))
        try:
            with self.db.session() as db:
                job = db.get(Evaluation, job_id)
                target = job.target_snapshot
                secret = unseal(self.settings, db.get(Target, job.target_id).secret)
                budget = job.budget
                ids = db.scalars(
                    select(Attempt.id)
                    .where(Attempt.evaluation_id == job_id, Attempt.status == "PENDING")
                    .order_by(Attempt.case_id, Attempt.repeat)
                ).all()
            for attempt_id in ids:
                if not self.alive(job_id, token) or self.stopping:
                    break
                remaining_seconds = budget.get("max_job_seconds", 1800) - (
                    time.monotonic() - started
                )
                if remaining_seconds <= 0:
                    self.stop_for_budget(job_id, token, "JOB_TIME_BUDGET_EXHAUSTED")
                    break
                with self.db.session() as db:
                    usage = usage_totals(
                        db.scalars(select(Attempt).where(Attempt.evaluation_id == job_id))
                    )
                if not usage["usage_complete"]:
                    self.stop_for_budget(job_id, token, "JOB_USAGE_UNAVAILABLE")
                    break
                effective_budget, exhausted = remaining_budget(budget, usage)
                if exhausted:
                    self.stop_for_budget(job_id, token, exhausted)
                    break
                case = self.start_attempt(job_id, token, attempt_id)
                if case is None:
                    break
                collector = {"evidence": None}
                cancelled = False
                execution = asyncio.create_task(
                    evaluate_attempt(
                        self.settings,
                        target,
                        case,
                        secret,
                        effective_budget,
                        attempt_id,
                        job_timeout_seconds=max(
                            0, budget.get("max_job_seconds", 1800) - (time.monotonic() - started)
                        ),
                        evidence_collector=collector,
                    )
                )
                while not execution.done():
                    if not self.alive(job_id, token) or self.stopping:
                        cancelled = True
                        execution.cancel()
                        break
                    await asyncio.sleep(0.2)
                try:
                    result = await execution
                except asyncio.CancelledError:
                    cancelled = True
                except Exception:
                    result = {
                        "verdict": "ERROR",
                        "evidence": {"complete": False, "error_code": "WORKER_EXECUTION_FAILED"},
                    }
                if cancelled:
                    # 等待适配器取消收尾后读取证据；save 仍拒绝过期／被替换的租约。
                    await finalize_evidence(collector)
                    result = interrupted_result(
                        case,
                        collector,
                        "WORKER_STOPPED" if self.stopping else "EXECUTION_INTERRUPTED",
                    )
                result["execution_budget"] = effective_budget
                if not self.save(job_id, token, attempt_id, result, interrupted=cancelled):
                    break
                if cancelled:
                    break
                if result.get("evidence", {}).get(
                    "error_code"
                ) == "JOB_TIME_BUDGET_EXHAUSTED" or time.monotonic() - started >= budget.get(
                    "max_job_seconds", 1800
                ):
                    self.stop_for_budget(job_id, token, "JOB_TIME_BUDGET_EXHAUSTED")
                    break
                saved_usage = usage_totals([SimpleNamespace(result=result)])
                if not saved_usage["usage_complete"]:
                    self.stop_for_budget(job_id, token, "JOB_USAGE_UNAVAILABLE")
                    break
                exceeded = next(
                    (
                        field
                        for field in ("tokens", "turns", "tool_calls")
                        if usage[field] + saved_usage[field]
                        > budget.get("max_job_" + field, DEFAULT_JOB_LIMITS["max_job_" + field])
                    ),
                    None,
                )
                if exceeded:
                    self.stop_for_budget(
                        job_id, token, "JOB_" + exceeded.upper() + "_BUDGET_EXHAUSTED"
                    )
                    break
            self.finish(job_id, token)
        finally:
            stop.set()
            await beat

    async def run_once(self):
        claim = self.claim()
        if claim:
            await self.run_job(*claim)
            return True
        return False

    async def run(self):
        while not self.stopping:
            write_worker_health(self.settings)
            if not await self.run_once():
                await asyncio.sleep(1)
