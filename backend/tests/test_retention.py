import time

import pytest
from agentsec.models import Attempt, Audit, Evaluation, Finding
from agentsec.retention import prune_evidence
from agentsec.worker import Worker
from sqlalchemy import select

from .conftest import create_job


async def test_prune_preserves_findings_retest_unknown_files_and_database(admin, db, settings):
    original = create_job(admin, "none")
    await Worker(settings, db).run_once()
    repaired = create_job(admin, "strict")
    await Worker(settings, db).run_once()
    with db.session.begin() as session:
        attempts = list(session.scalars(select(Attempt)))
        for attempt in attempts:
            attempt.finished_at = time.time() - 100 * 86400
        finding = session.scalar(select(Finding))
        protected_retest = next(
            a for a in attempts if a.evaluation_id == repaired["id"] and a.case_id == "direct-tool"
        )
        session.add(
            Audit(
                actor_id="system",
                action="finding.update",
                object_id=finding.id,
                details={"status": "VERIFIED", "retest_attempt_id": protected_retest.id},
            )
        )
        ids = {a.id for a in attempts}
        open_attempt = finding.attempt_id
    for ident in ids:
        folder = settings.data_dir / "sdk-attempts" / ident
        folder.mkdir(parents=True)
        (folder / "audit.jsonl").write_text("evidence")
        (folder / "policy.properties").write_text("reproducible policy")
        (folder / "unknown.txt").write_text("keep")
    outside = settings.data_dir.parent / "outside.txt"
    outside.write_text("keep")
    logs = settings.data_dir / "inspect" / "logs"
    (logs / "unknown.eval").write_text("keep")
    (logs / "linked.eval").symlink_to(outside)
    plan = prune_evidence(settings, db)
    assert plan["dry_run"] and plan["files"]
    assert not any(open_attempt in p or protected_retest.id in p for p in plan["files"])
    assert not any(
        open_attempt.replace("-", "") in p or protected_retest.id.replace("-", "") in p
        for p in plan["files"]
    )
    assert all((settings.data_dir / p).exists() for p in plan["files"])
    result = prune_evidence(settings, db, apply=True, services_stopped=True)
    assert result["deleted"] == plan["files"] and result["failed"] == []
    assert all(not (settings.data_dir / p).exists() for p in plan["files"])
    for ident in ids:
        folder = settings.data_dir / "sdk-attempts" / ident
        assert (folder / "policy.properties").exists()
        assert (folder / "unknown.txt").exists()
    assert outside.read_text() == "keep"
    assert (logs / "unknown.eval").exists() and (logs / "linked.eval").is_symlink()
    with db.session() as session:
        assert len(list(session.scalars(select(Attempt)))) == 4
        assert all(a.result for a in session.scalars(select(Attempt)))
        assert session.scalar(select(Finding)).status == "OPEN"
        assert session.scalar(select(Audit).where(Audit.action == "evidence.prune.finished"))
    assert admin.get("/api/evaluations/" + original["id"] + "/report").status_code == 200
    assert prune_evidence(settings, db)["files"] == []
    with db.session.begin() as session:
        session.scalar(select(Finding)).status = "ACCEPTED_RISK"
    assert prune_evidence(settings, db)["files"] == []
    with db.session.begin() as session:
        session.scalar(select(Finding)).status = "CLOSED"
    closed_plan = prune_evidence(settings, db)
    assert any(open_attempt in p for p in closed_plan["files"])
    assert not any(
        protected_retest.id in p or protected_retest.id.replace("-", "") in p
        for p in closed_plan["files"]
    )


def test_prune_requires_offline_confirmation_and_no_active_jobs(admin, db, settings):
    create_job(admin)
    with pytest.raises(ValueError, match="停止"):
        prune_evidence(settings, db, apply=True)
    with pytest.raises(ValueError, match="活动评测"):
        prune_evidence(settings, db, apply=True, services_stopped=True)
    assert prune_evidence(settings, db)["dry_run"]
    for days in (0, 3651):
        with pytest.raises(ValueError, match="天数"):
            prune_evidence(settings, db, days=days)


async def test_symlink_evidence_directory_is_never_pruned(admin, db, settings):
    create_job(admin, "strict", ["direct-tool"])
    await Worker(settings, db).run_once()
    with db.session.begin() as session:
        attempt = session.scalar(select(Attempt))
        attempt.finished_at = time.time() - 100 * 86400
        ident = attempt.id
        session.get(Evaluation, attempt.evaluation_id).status = "COMPLETED"
    outside = settings.data_dir.parent / "external"
    outside.mkdir()
    (outside / "audit.jsonl").write_text("keep")
    sdk = settings.data_dir / "sdk-attempts"
    sdk.mkdir()
    (sdk / ident).symlink_to(outside, target_is_directory=True)
    result = prune_evidence(settings, db, apply=True, services_stopped=True)
    assert not any(p.startswith("sdk-attempts/") for p in result["deleted"])
    assert (outside / "audit.jsonl").read_text() == "keep"
