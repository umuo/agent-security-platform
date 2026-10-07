"""Offline pruning of recognised raw evidence; database results remain intact."""

import re
import time
from uuid import UUID

from sqlalchemy import select

from .models import Attempt, Audit, Evaluation, Finding, uid

LOG_NAME = re.compile(r"^.+_agentsec[-_]([0-9a-f]{32})_[A-Za-z0-9]+\.eval$")
TERMINAL = {"COMPLETED", "CANCELLED", "FAILED"}


def safe_file(path, root):
    """Reject symlink files and parents, including evidence directories."""
    if path.is_symlink() or not path.is_file():
        return False
    for parent in path.parents:
        if parent.is_symlink():
            return False
        if parent == root:
            return path.resolve().is_relative_to(root.resolve())
    return False


def prune_evidence(settings, database, days=90, apply=False, services_stopped=False):
    if not 1 <= days <= 3650:
        raise ValueError("保留天数须为 1～3650")
    if apply and not services_stopped:
        raise ValueError("执行清理须停止 API 和 Worker，并传入 --services-stopped")
    cutoff = time.time() - days * 86400
    with database.session() as db:
        active = db.scalar(
            select(Evaluation.id).where(Evaluation.status.in_(["QUEUED", "RUNNING"])).limit(1)
        )
        if apply and active:
            raise ValueError("仍有活动评测；请先完成或取消任务")
        protected = set(db.scalars(select(Finding.attempt_id).where(Finding.status != "CLOSED")))
        for details in db.scalars(select(Audit.details).where(Audit.action == "finding.update")):
            if details.get("status") in {"VERIFIED", "CLOSED"}:
                protected.add(details.get("retest_attempt_id"))
        eligible = (
            set(
                db.scalars(
                    select(Attempt.id)
                    .join(Evaluation, Attempt.evaluation_id == Evaluation.id)
                    .where(
                        Attempt.finished_at < cutoff,
                        Attempt.status.in_(["COMPLETED", "CANCELLED", "INTERRUPTED", "FAILED"]),
                        Evaluation.status.in_(TERMINAL),
                    )
                )
            )
            - protected
        )
    root = settings.data_dir.absolute()
    files = []
    logs = root / "inspect" / "logs"
    if logs.is_dir() and not logs.is_symlink() and not logs.parent.is_symlink():
        for path in logs.iterdir():
            match = LOG_NAME.fullmatch(path.name)
            if match and str(UUID(hex=match[1])) in eligible and safe_file(path, root):
                files.append(path)
    sdk = root / "sdk-attempts"
    if sdk.is_dir() and not sdk.is_symlink():
        for ident in sorted(eligible):
            # UUID is checked before constructing a path from database identifiers.
            try:
                if str(UUID(ident)) != ident:
                    continue
            except ValueError:
                continue
            folder = sdk / ident
            if folder.is_dir() and not folder.is_symlink():
                path = folder / "audit.jsonl"
                if safe_file(path, root):
                    files.append(path)
    files = sorted(set(files))
    plan = {
        "dry_run": not apply,
        "days": days,
        "files": [str(p.relative_to(root)) for p in files],
        "bytes": sum(p.stat().st_size for p in files),
        "protected_attempts": len(protected - {None}),
        "database_results_retained": True,
    }
    if not apply:
        return plan
    operation = uid()
    with database.session.begin() as db:
        db.add(
            Audit(
                actor_id="system",
                action="evidence.prune.started",
                object_id=operation,
                details=plan,
            )
        )
    deleted, failed = [], []
    for path in files:
        relative = str(path.relative_to(root))
        try:
            if not safe_file(path, root):
                raise OSError("Evidence path changed")
            path.unlink()
            deleted.append(relative)
        except OSError:
            failed.append(relative)
    result = {**plan, "deleted": deleted, "failed": failed, "operation_id": operation}
    with database.session.begin() as db:
        db.add(
            Audit(
                actor_id="system",
                action="evidence.prune.finished",
                object_id=operation,
                details=result,
            )
        )
    return result
