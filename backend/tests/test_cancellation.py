import asyncio

import pytest
from agentsec.worker import Worker

from .test_business_observer import OBSERVER_TOKEN, example
from .test_business_observer import business_servers as business_servers


@pytest.mark.parametrize("attack,shutdown", [(True, False), (False, False), (True, True)])
async def test_worker_cancellation_publishes_committed_business_effect(
    admin, db, settings, business_servers, attack, shutdown
):
    observer, agent, requests, path = business_servers
    settings.observer_endpoint, settings.observer_token = observer + "/observe", OBSERVER_TOKEN
    target = admin.post(
        "/api/targets",
        json={
            "name": "cancel-business",
            "kind": "http-agent",
            "config": {"endpoint": agent + "/cancel", "protocol": "observed-v1"},
        },
    ).json()
    job = admin.post(
        "/api/evaluations",
        json={
            "target_id": target["id"],
            "case_ids": ["direct-tool" if attack else "clean-query"],
            "repeats": 2,
        },
    ).json()
    worker = Worker(settings, db)
    execution = asyncio.create_task(worker.run_once())
    try:
        async with asyncio.timeout(5):
            while True:
                with example.Store(path).connect() as business:
                    committed = business.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]
                if committed:
                    break
                await asyncio.sleep(0.02)
        if shutdown:
            worker.stopping = True
        else:
            assert admin.post("/api/evaluations/" + job["id"] + "/cancel").status_code == 200
        assert await asyncio.wait_for(execution, 5)
    finally:
        if not execution.done():
            worker.stopping = True
            await asyncio.wait_for(execution, 5)
    report = admin.get("/api/evaluations/" + job["id"] + "/report").json()
    assert report["status"] == "CANCELLED" and not report["summary"]["gate_passed"]
    first, pending = report["attempts"]
    assert first["status"] == "INTERRUPTED"
    assert first["result"]["verdict"] == ("ATTACK_SUCCEEDED" if attack else "UNSAFE_COMPLETION")
    evidence = first["result"]["evidence"]
    assert evidence["error_code"] == ("WORKER_STOPPED" if shutdown else "EXECUTION_INTERRUPTED")
    assert evidence["observation_complete"] and not evidence["complete"]
    assert any(e["kind"] == "tool.effect" for e in evidence["events"])
    assert not evidence["usage_complete"] and not report["budget_usage"]["usage_complete"]
    assert pending["status"] == "CANCELLED" and pending["result"]["verdict"] == "INCONCLUSIVE"
    assert len(requests) == 1
    finding = admin.get("/api/findings").json()[0]
    assert finding["severity"] == "HIGH" and finding["attempt_id"] == first["id"]
    assert finding["remediation"]["basis"] == first["result"]["verdict"]
    with example.Store(path).connect() as business:
        assert business.execute("SELECT COUNT(*) FROM scopes WHERE closed=1").fetchone()[0] == 1
        assert business.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 1


async def test_cancel_before_adapter_never_invents_effects(admin, db, settings, monkeypatch):
    entered = asyncio.Event()

    async def stall(*args, **kwargs):
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr("agentsec.engine.eval_async", stall)
    target = admin.post("/api/targets", json={"name": "before-adapter", "kind": "fixture"}).json()
    job = admin.post(
        "/api/evaluations",
        json={"target_id": target["id"], "case_ids": ["direct-tool"], "repeats": 2},
    ).json()
    worker = Worker(settings, db)
    running = asyncio.create_task(worker.run_once())
    try:
        await asyncio.wait_for(entered.wait(), 2)
        assert admin.post("/api/evaluations/" + job["id"] + "/cancel").status_code == 200
        assert await asyncio.wait_for(running, 5)
    finally:
        if not running.done():
            worker.stopping = True
            await asyncio.wait_for(running, 5)
    report = admin.get("/api/evaluations/" + job["id"]).json()
    assert report["status"] == "CANCELLED" and not report["summary"]["gate_passed"]
    first = report["attempts"][0]
    assert first["status"] == "INTERRUPTED" and first["result"]["verdict"] == "INCONCLUSIVE"
    assert first["result"]["evidence"]["events"] == []
    assert admin.get("/api/findings").json() == []


async def test_business_deadline_finalizes_outside_inspect(admin, db, settings, business_servers):
    observer, agent, requests, path = business_servers
    settings.observer_endpoint, settings.observer_token = observer + "/observe", OBSERVER_TOKEN
    target = admin.post(
        "/api/targets",
        json={
            "name": "business-deadline",
            "kind": "http-agent",
            "config": {"endpoint": agent + "/cancel", "protocol": "observed-v1"},
        },
    ).json()
    job = admin.post(
        "/api/evaluations",
        json={
            "target_id": target["id"],
            "case_ids": ["direct-tool"],
            "repeats": 2,
            "budget": {"max_job_seconds": 2, "timeout_seconds": 30},
        },
    ).json()
    assert await asyncio.wait_for(Worker(settings, db).run_once(), 6)
    report = admin.get("/api/evaluations/" + job["id"] + "/report").json()
    assert report["status"] == "FAILED" and report["error_code"] == "JOB_TIME_BUDGET_EXHAUSTED"
    assert not report["summary"]["gate_passed"]
    first, pending = report["attempts"]
    assert first["result"]["verdict"] == "ATTACK_SUCCEEDED"
    evidence = first["result"]["evidence"]
    assert evidence["observation_complete"] and evidence["finalized_outside_inspect"]
    assert evidence["error_code"] == "JOB_TIME_BUDGET_EXHAUSTED"
    assert pending["status"] == "INTERRUPTED" and len(requests) == 1
    with example.Store(path).connect() as business:
        assert business.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 1
        assert business.execute("SELECT COUNT(*) FROM scopes WHERE closed=1").fetchone()[0] == 1
