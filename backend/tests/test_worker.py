import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from agentsec.models import Attempt, Evaluation
from agentsec.worker import Worker
from sqlalchemy import select

from .conftest import create_job


@pytest.mark.parametrize(
    "guard,attack,clean",
    [
        ("strict", "ATTACK_PREVENTED", "CLEAN_SUCCEEDED"),
        ("none", "ATTACK_SUCCEEDED", "CLEAN_SUCCEEDED"),
        ("overblock", "ATTACK_PREVENTED", "FALSE_POSITIVE"),
    ],
)
async def test_real_inspect_worker_and_evidence(admin, db, settings, guard, attack, clean):
    job = create_job(admin, guard)
    worker = Worker(settings, db)
    assert await worker.run_once()
    detail = admin.get("/api/evaluations/" + job["id"]).json()
    assert detail["status"] == "COMPLETED"
    outcomes = {x["case_id"]: x["result"]["verdict"] for x in detail["attempts"]}
    assert outcomes == {"direct-tool": attack, "clean-query": clean}
    assert detail["summary"]["gate_passed"] is (guard == "strict")
    assert all(
        x["result"]["evidence"]["provenance"] == "sandbox-recorder" for x in detail["attempts"]
    )
    report = admin.get("/api/evaluations/" + job["id"] + "/report")
    assert report.status_code == 200
    guidance = {x["case_id"]: x["remediation"] for x in report.json()["attempts"]}
    findings = admin.get("/api/findings").json()
    if guard == "none":
        assert guidance["direct-tool"]["basis"] == "ATTACK_SUCCEEDED"
        assert findings[0]["remediation"] == guidance["direct-tool"]
    elif guard == "overblock":
        assert guidance["clean-query"]["basis"] == "FALSE_POSITIVE"
        assert findings[0]["remediation"] == guidance["clean-query"]
    else:
        assert all(x is None for x in guidance.values())
        assert findings == []


def test_concurrent_claim_one_owner(admin, db, settings):
    job = create_job(admin)
    worker = Worker(settings, db)
    with ThreadPoolExecutor(max_workers=6) as pool:
        claims = list(pool.map(lambda _: worker.claim(), range(12)))
    assert sum(x is not None for x in claims) == 1
    assert next(x for x in claims if x)[0] == job["id"]


def test_expired_worker_cannot_write_and_no_retry(admin, db, settings):
    job = create_job(admin)
    worker = Worker(settings, db)
    ident, token = worker.claim()
    with db.session.begin() as session:
        session.get(Evaluation, ident).lease_until = time.time() - 1
        attempt_id = session.scalar(select(Attempt.id).where(Attempt.evaluation_id == ident))
    worker.recover_expired()
    assert not worker.save(ident, token, attempt_id, {"verdict": "ATTACK_PREVENTED"})
    assert not worker.save(
        ident, token, attempt_id, {"verdict": "ATTACK_SUCCEEDED"}, interrupted=True
    )
    assert worker.claim() is None
    detail = admin.get("/api/evaluations/" + job["id"]).json()
    assert detail["status"] == "FAILED"
    assert not detail["summary"]["gate_passed"]
    assert all(x["result"]["verdict"] == "INCONCLUSIVE" for x in detail["attempts"])


def test_expired_owner_cannot_start_or_finish_before_recovery(admin, db, settings):
    job = create_job(admin)
    worker = Worker(settings, db)
    ident, token = worker.claim()
    with db.session.begin() as session:
        session.get(Evaluation, ident).lease_until = time.time() - 1
        attempt_id = session.scalar(select(Attempt.id).where(Attempt.evaluation_id == ident))
    assert worker.start_attempt(ident, token, attempt_id) is None
    assert not worker.save(
        ident, token, attempt_id, {"verdict": "ATTACK_SUCCEEDED"}, interrupted=True
    )
    assert not worker.stop_for_budget(ident, token, "JOB_TOKENS_BUDGET_EXHAUSTED")
    assert not worker.finish(ident, token)
    with db.session() as session:
        assert session.get(Evaluation, ident).status == "RUNNING"
        assert session.get(Attempt, attempt_id).status == "PENDING"
    worker.recover_expired()
    assert not worker.finish(ident, token)
    assert admin.get("/api/evaluations/" + job["id"]).json()["status"] == "FAILED"


def test_running_cancel_prevents_next_attempt_and_preserves_completed(admin, db, settings):
    create_job(admin)
    worker = Worker(settings, db)
    ident, token = worker.claim()
    with db.session() as session:
        ids = list(session.scalars(select(Attempt.id).where(Attempt.evaluation_id == ident)))
    assert worker.start_attempt(ident, token, ids[0])
    assert worker.save(ident, token, ids[0], {"verdict": "ATTACK_SUCCEEDED"})
    assert admin.post("/api/evaluations/" + ident + "/cancel").status_code == 200
    assert worker.start_attempt(ident, token, ids[1]) is None
    assert worker.finish(ident, token)
    detail = admin.get("/api/evaluations/" + ident).json()
    assert detail["status"] == "CANCELLED"
    outcomes = {x["id"]: x["result"]["verdict"] for x in detail["attempts"]}
    assert outcomes[ids[0]] == "ATTACK_SUCCEEDED"
    assert outcomes[ids[1]] == "INCONCLUSIVE"


def test_claim_cancel_race_has_consistent_terminal_state(admin, db, settings):
    job = create_job(admin)
    worker = Worker(settings, db)
    with ThreadPoolExecutor(max_workers=2) as pool:
        claim = pool.submit(worker.claim)
        cancel = pool.submit(admin.post, "/api/evaluations/" + job["id"] + "/cancel")
        owner, response = claim.result(), cancel.result()
    assert response.status_code == 200
    if owner:
        assert not worker.alive(*owner)
        assert worker.finish(*owner)
    detail = admin.get("/api/evaluations/" + job["id"]).json()
    assert detail["status"] == "CANCELLED"
    assert all(x["status"] == "CANCELLED" for x in detail["attempts"])


async def test_finding_retest_requires_same_asset(admin, db, settings):
    job = create_job(admin, "none", ["direct-tool"])
    await Worker(settings, db).run_once()
    finding = admin.get("/api/findings").json()[0]
    unrelated = create_job(admin, "strict", ["direct-tool"])
    await Worker(settings, db).run_once()
    attempt = admin.get("/api/evaluations/" + unrelated["id"]).json()["attempts"][0]["id"]
    assert (
        admin.patch(
            "/api/findings/" + finding["id"],
            json={"status": "CLOSED", "retest_attempt_id": attempt},
        ).status_code
        == 400
    )
    revision = admin.post(
        "/api/targets",
        json={
            "name": "repaired",
            "kind": "fixture",
            "config": {"guard": "strict"},
            "parent_target_id": job["target_id"],
        },
    ).json()
    retest = admin.post(
        "/api/evaluations", json={"target_id": revision["id"], "case_ids": ["direct-tool"]}
    ).json()
    await Worker(settings, db).run_once()
    attempt = admin.get("/api/evaluations/" + retest["id"]).json()["attempts"][0]["id"]
    assert (
        admin.patch(
            "/api/findings/" + finding["id"],
            json={"status": "CLOSED", "retest_attempt_id": attempt},
        ).status_code
        == 200
    )


async def test_cancel_after_last_sample_never_passes_job_gate(admin, db, settings):
    job = create_job(admin, "strict", ["clean-query"])
    worker = Worker(settings, db)
    original_finish = worker.finish

    def cancel_before_finish(ident, token):
        assert admin.post("/api/evaluations/" + ident + "/cancel").status_code == 200
        return original_finish(ident, token)

    worker.finish = cancel_before_finish
    await worker.run_once()
    report = admin.get("/api/evaluations/" + job["id"] + "/report").json()
    assert report["status"] == "CANCELLED"
    assert report["attempts"][0]["result"]["verdict"] == "CLEAN_SUCCEEDED"
    assert not report["summary"]["gate_passed"]
