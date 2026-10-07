import pytest
from agentsec.worker import Worker

from .test_http_tools import agent_server as shared_agent_server

agent_server = shared_agent_server


@pytest.mark.parametrize(
    "limits,code,finished,turns,calls",
    [
        ({"max_job_turns": 2}, "JOB_TURNS_BUDGET_EXHAUSTED", 1, 2, 1),
        ({"max_job_tool_calls": 1}, "JOB_TOOL_CALLS_BUDGET_EXHAUSTED", 1, 2, 1),
        ({"max_job_tokens": 64}, "JOB_TOKENS_BUDGET_EXHAUSTED", 4, 7, 3),
    ],
)
async def test_whole_job_budget_stops_remaining_samples(
    admin, db, settings, agent_server, limits, code, finished, turns, calls
):
    url, requests = agent_server
    target = admin.post(
        "/api/targets",
        json={
            "name": "budget target",
            "kind": "http-agent",
            "config": {"endpoint": url + "/clean", "protocol": "tool-loop-v1", "guard": "strict"},
        },
    ).json()
    job = admin.post(
        "/api/evaluations",
        json={
            "target_id": target["id"],
            "case_ids": ["clean-query"],
            "repeats": 5,
            "budget": limits,
        },
    ).json()
    await Worker(settings, db).run_once()
    report = admin.get("/api/evaluations/" + job["id"] + "/report").json()
    assert report["status"] == "FAILED" and report["error_code"] == code
    assert not report["summary"]["gate_passed"]
    assert sum(a["status"] == "COMPLETED" for a in report["attempts"]) == finished
    assert report["budget_usage"]["turns"] == turns == len(requests)
    assert report["budget_usage"]["tool_calls"] == calls
    assert report["budget_usage"]["usage_complete"]
    if "max_job_tokens" in limits:
        assert report["budget_usage"]["tokens"] == 70
        assert requests[-1]["budget"]["max_total_tokens"] == 4
        assert requests[-1]["budget"]["max_tokens"] == 4
        assert report["attempts"][3]["result"]["execution_budget"]["max_total_tokens"] == 4
    assert all(
        a["result"]["verdict"] == "INCONCLUSIVE"
        for a in report["attempts"]
        if a["status"] == "INTERRUPTED"
    )
    assert await Worker(settings, db).run_once() is False


async def test_unknown_usage_stops_job_instead_of_counting_as_zero(
    admin, db, settings, agent_server
):
    url, _ = agent_server
    target = admin.post(
        "/api/targets",
        json={
            "name": "missing usage",
            "kind": "http-agent",
            "config": {"endpoint": url + "/output-no-usage"},
        },
    ).json()
    job = admin.post(
        "/api/evaluations",
        json={"target_id": target["id"], "case_ids": ["direct-tool"], "repeats": 2},
    ).json()
    await Worker(settings, db).run_once()
    report = admin.get("/api/evaluations/" + job["id"] + "/report").json()
    assert report["status"] == "FAILED" and report["error_code"] == "JOB_USAGE_UNAVAILABLE"
    assert not report["budget_usage"]["usage_complete"]
    assert report["attempts"][1]["status"] == "INTERRUPTED"
