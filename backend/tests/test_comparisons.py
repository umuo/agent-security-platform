import copy

import pytest
from agentsec.models import Attempt
from agentsec.worker import Worker
from sqlalchemy import select

from .conftest import create_job


async def test_compare_repaired_revision_and_unknowns(admin, db, settings):
    before = create_job(admin, "none")
    await Worker(settings, db).run_once()
    repaired = admin.post(
        "/api/targets",
        json={
            "name": "repair",
            "kind": "fixture",
            "config": {"guard": "strict"},
            "parent_target_id": before["target_id"],
        },
    ).json()
    after = admin.post(
        "/api/evaluations",
        json={"target_id": repaired["id"], "case_ids": ["direct-tool", "clean-query"]},
    ).json()
    url = "/api/comparisons?baseline_id=" + before["id"] + "&candidate_id=" + after["id"]
    assert not admin.get(url).json()["comparable"]
    await Worker(settings, db).run_once()
    result = admin.get(url).json()
    assert result["comparable"]
    assert result["improvements"] == 1 and result["regressions"] == 0
    assert {r["case_id"]: r["change"] for r in result["rows"]} == {
        "direct-tool": "IMPROVED",
        "clean-query": "UNCHANGED",
    }
    different_cases = admin.post(
        "/api/evaluations", json={"target_id": repaired["id"], "case_ids": ["direct-tool"]}
    ).json()
    await Worker(settings, db).run_once()
    mismatch = admin.get(
        "/api/comparisons",
        params={"baseline_id": before["id"], "candidate_id": different_cases["id"]},
    ).json()
    assert not mismatch["comparable"]
    assert any(row["change"] == "INCOMPARABLE" for row in mismatch["rows"])
    other_asset = create_job(admin)
    assert (
        admin.get(
            "/api/comparisons",
            params={"baseline_id": before["id"], "candidate_id": other_asset["id"]},
        ).status_code
        == 400
    )

    assert (
        admin.get(
            "/api/comparisons", params={"baseline_id": before["id"], "candidate_id": before["id"]}
        ).status_code
        == 400
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("engine", "another-engine"),
        ("engine_version", "0.0.0"),
        ("oracle_revision", "v1"),
        ("mode", "http-output-only"),
        ("provenance", "application-output"),
        ("oracle_revision", None),
    ],
)
async def test_comparison_refuses_incompatible_execution_metadata(
    admin, db, settings, field, value
):
    before = create_job(admin, "none", ["direct-tool"])
    await Worker(settings, db).run_once()
    after = admin.post(
        "/api/evaluations", json={"target_id": before["target_id"], "case_ids": ["direct-tool"]}
    ).json()
    await Worker(settings, db).run_once()
    params = {"baseline_id": before["id"], "candidate_id": after["id"]}
    assert admin.get("/api/comparisons", params=params).json()["comparable"]
    with db.session.begin() as session:
        attempt = session.scalar(select(Attempt).where(Attempt.evaluation_id == after["id"]))
        result = copy.deepcopy(attempt.result)
        destination = result["evidence"] if field in {"mode", "provenance"} else result
        destination[field] = value
        attempt.result = result
    response = admin.get("/api/comparisons", params=params).json()
    assert not response["comparable"]
    assert response["rows"][0]["change"] == "INCOMPARABLE"
    assert response["warnings"]
    assert response["regressions"] == response["improvements"] == 0


@pytest.mark.parametrize(
    "candidate_hashes",
    [
        None,
        {},
        {"demo": "a" * 64},
        {"demo": "a" * 64, "javaagent": "invalid"},
        {"demo": "b" * 64, "javaagent": "a" * 64},
    ],
)
async def test_sdk_comparison_requires_same_complete_artifact_fingerprints(
    admin, db, settings, candidate_hashes
):
    before = create_job(admin, "none", ["direct-tool"])
    await Worker(settings, db).run_once()
    after = admin.post(
        "/api/evaluations", json={"target_id": before["target_id"], "case_ids": ["direct-tool"]}
    ).json()
    await Worker(settings, db).run_once()
    hashes = {"demo": "a" * 64, "javaagent": "a" * 64}
    with db.session.begin() as session:
        for job in (before, after):
            attempt = session.scalar(select(Attempt).where(Attempt.evaluation_id == job["id"]))
            result = copy.deepcopy(attempt.result)
            result["evidence"].update(provenance="sdk-fixture-counter", artifact_sha256=hashes)
            attempt.result = result
    params = {"baseline_id": before["id"], "candidate_id": after["id"]}
    assert admin.get("/api/comparisons", params=params).json()["comparable"]
    with db.session.begin() as session:
        attempt = session.scalar(select(Attempt).where(Attempt.evaluation_id == after["id"]))
        result = copy.deepcopy(attempt.result)
        result["evidence"]["artifact_sha256"] = candidate_hashes
        attempt.result = result
    response = admin.get("/api/comparisons", params=params).json()
    assert not response["comparable"]
    assert response["rows"][0]["change"] == "INCOMPARABLE"
    assert response["regressions"] == response["improvements"] == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("observer_identity", "b" * 64),
        ("observer_revision", "business-v2"),
        ("observer_revision", None),
    ],
)
async def test_business_comparison_requires_same_observer_identity_and_revision(
    admin, db, settings, field, value
):
    before = create_job(admin, "none", ["direct-tool"])
    await Worker(settings, db).run_once()
    after = admin.post(
        "/api/evaluations", json={"target_id": before["target_id"], "case_ids": ["direct-tool"]}
    ).json()
    await Worker(settings, db).run_once()
    with db.session.begin() as session:
        for job in (before, after):
            attempt = session.scalar(select(Attempt).where(Attempt.evaluation_id == job["id"]))
            result = copy.deepcopy(attempt.result)
            result["evidence"].update(
                provenance="business-observer-v1",
                mode="http-agent-observed-v1",
                observer_identity="a" * 64,
                observer_revision="business-v1",
            )
            attempt.result = result
    params = {"baseline_id": before["id"], "candidate_id": after["id"]}
    assert admin.get("/api/comparisons", params=params).json()["comparable"]
    with db.session.begin() as session:
        attempt = session.scalar(select(Attempt).where(Attempt.evaluation_id == after["id"]))
        result = copy.deepcopy(attempt.result)
        result["evidence"][field] = value
        attempt.result = result
    comparison = admin.get("/api/comparisons", params=params).json()
    assert comparison["rows"][0]["change"] == "INCOMPARABLE"
    assert not comparison["comparable"]
    assert comparison["improvements"] == comparison["regressions"] == 0
