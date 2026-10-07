import pytest
from agentsec.worker import Worker

from .conftest import create_job
from .test_http_tools import agent_server as shared_agent_server

agent_server = shared_agent_server


@pytest.mark.parametrize("risk", ["tool", "tenant", "secret"])
async def test_normal_unsafe_effect_creates_high_finding_and_requires_safe_retest(
    admin, db, settings, agent_server, risk
):
    url, _ = agent_server
    original = create_job(
        admin,
        cases=["clean-query"],
        kind="http-agent",
        config={"endpoint": url + "/unsafe-" + risk, "protocol": "tool-loop-v1", "guard": "none"},
    )
    await Worker(settings, db).run_once()
    report = admin.get("/api/evaluations/" + original["id"] + "/report").json()
    assert report["status"] == "COMPLETED" and not report["summary"]["gate_passed"]
    assert report["summary"]["unsafe_completion_rate"] == 1
    assert report["summary"]["attack_success_rate"] is None
    attempt = report["attempts"][0]
    assert attempt["result"]["verdict"] == "UNSAFE_COMPLETION"
    assert attempt["result"]["evidence"]["task_completed"]
    assert attempt["remediation"]["basis"] == "UNSAFE_COMPLETION"
    finding = admin.get("/api/findings").json()[0]
    assert finding["severity"] == "HIGH" and finding["remediation"] == attempt["remediation"]
    assert (
        admin.patch(
            "/api/findings/" + finding["id"],
            json={"status": "CLOSED", "retest_attempt_id": attempt["id"]},
        ).status_code
        == 400
    )
    repaired = admin.post(
        "/api/targets",
        json={
            "name": "repaired control",
            "kind": "http-agent",
            "parent_target_id": original["target_id"],
            "config": {"endpoint": url + "/clean", "protocol": "tool-loop-v1", "guard": "strict"},
        },
    ).json()
    retest = admin.post(
        "/api/evaluations", json={"target_id": repaired["id"], "case_ids": ["clean-query"]}
    ).json()
    await Worker(settings, db).run_once()
    retest_attempt = admin.get("/api/evaluations/" + retest["id"]).json()["attempts"][0]
    assert retest_attempt["result"]["verdict"] == "CLEAN_SUCCEEDED"
    assert (
        admin.patch(
            "/api/findings/" + finding["id"],
            json={"status": "CLOSED", "retest_attempt_id": retest_attempt["id"]},
        ).status_code
        == 200
    )
    comparison = admin.get(
        "/api/comparisons", params={"baseline_id": original["id"], "candidate_id": retest["id"]}
    ).json()
    assert comparison["comparable"] and comparison["improvements"] == 1
