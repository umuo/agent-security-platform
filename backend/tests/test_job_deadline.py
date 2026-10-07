import asyncio
import time

import pytest
from agentsec.worker import Worker


@pytest.mark.parametrize("attack", [True, False])
async def test_job_deadline_preserves_effect_and_never_starts_next_sample(
    admin, db, settings, monkeypatch, attack
):
    requests = []

    async def respond(settings, endpoint, secret, body):
        requests.append(body)
        if len(requests) > 1:
            await asyncio.sleep(10)
        return {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "id": "call-a",
                                "function": {
                                    "name": "send_report",
                                    "arguments": '{"recipient":"test@example.invalid"}',
                                },
                            }
                        ]
                    }
                }
            ],
            "usage": {"total_tokens": 10},
        }

    monkeypatch.setattr("agentsec.adapters.bounded_request", respond)
    target = admin.post(
        "/api/targets",
        json={
            "name": "deadline",
            "kind": "openai",
            "config": {"base_url": "http://127.0.0.1/v1", "model": "test", "guard": "none"},
        },
    ).json()
    job = admin.post(
        "/api/evaluations",
        json={
            "target_id": target["id"],
            "case_ids": ["direct-tool" if attack else "clean-query"],
            "repeats": 2,
            "budget": {"timeout_seconds": 30, "max_job_seconds": 1},
        },
    ).json()
    started = time.monotonic()
    await Worker(settings, db).run_once()
    assert time.monotonic() - started < 5
    report = admin.get("/api/evaluations/" + job["id"] + "/report").json()
    assert report["status"] == "FAILED" and report["error_code"] == "JOB_TIME_BUDGET_EXHAUSTED"
    assert len(requests) == 2 and not report["summary"]["gate_passed"]
    assert report["attempts"][1]["status"] == "INTERRUPTED"
    first = report["attempts"][0]["result"]
    assert first["verdict"] == ("ATTACK_SUCCEEDED" if attack else "UNSAFE_COMPLETION")
    assert first["evidence"]["error_code"] == "JOB_TIME_BUDGET_EXHAUSTED"
    assert any(e["kind"] == "tool.completed" for e in first["evidence"]["events"])
    assert admin.get("/api/findings").json()[0]["severity"] == "HIGH"


async def test_deadline_before_adapter_is_unknown_and_has_no_calls(
    admin, db, settings, monkeypatch
):
    async def stall(*args, **kwargs):
        await asyncio.sleep(10)
        raise AssertionError("must be cancelled")

    monkeypatch.setattr("agentsec.engine.eval_async", stall)
    target = admin.post("/api/targets", json={"name": "before adapter", "kind": "fixture"}).json()
    job = admin.post(
        "/api/evaluations",
        json={
            "target_id": target["id"],
            "case_ids": ["direct-tool"],
            "repeats": 2,
            "budget": {"max_job_seconds": 1},
        },
    ).json()
    await Worker(settings, db).run_once()
    report = admin.get("/api/evaluations/" + job["id"]).json()
    assert report["status"] == "FAILED" and report["error_code"] == "JOB_TIME_BUDGET_EXHAUSTED"
    assert report["attempts"][0]["result"]["verdict"] == "ERROR"
    assert report["attempts"][0]["result"]["evidence"]["events"] == []
    assert report["attempts"][1]["status"] == "INTERRUPTED"
