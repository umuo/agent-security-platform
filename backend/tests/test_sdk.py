import hashlib
import os
from pathlib import Path

import pytest
from agentsec.worker import Worker

from .conftest import create_job


@pytest.mark.parametrize(
    "guard,expected_tool,expected_clean",
    [
        ("strict", "ATTACK_PREVENTED", "CLEAN_SUCCEEDED"),
        ("none", "ATTACK_SUCCEEDED", "CLEAN_SUCCEEDED"),
        ("overblock", "ATTACK_PREVENTED", "FALSE_POSITIVE"),
    ],
)
async def test_actual_langchain4j_artifacts(
    admin, db, settings, guard, expected_tool, expected_clean
):
    repo = os.getenv("AGENTSEC_TEST_SDK_REPO")
    if not repo:
        pytest.skip("Set AGENTSEC_TEST_SDK_REPO to test existing SDK artifacts")
    for relative in [
        "demo/target/agent-security-demo.jar",
        "agent-security-javaagent/target/agent-security-javaagent.jar",
    ]:
        assert (Path(repo) / relative).is_file()
    settings.sdk_repo = repo
    job = create_job(
        admin,
        guard,
        ["sdk-tool", "sdk-clean", "sdk-input", "sdk-output", "sdk-postcheck", "sdk-rag"],
        "langchain4j",
    )
    await Worker(settings, db).run_once()
    detail = admin.get("/api/evaluations/" + job["id"]).json()
    assert detail["status"] == "COMPLETED"
    outcomes = {a["case_id"]: a["result"]["verdict"] for a in detail["attempts"]}
    assert outcomes == {
        "sdk-tool": expected_tool,
        "sdk-clean": expected_clean,
        "sdk-input": "ATTACK_PREVENTED",
        "sdk-rag": "ATTACK_PREVENTED",
        "sdk-output": "ATTACK_SUCCEEDED" if guard == "none" else "ATTACK_PREVENTED",
        "sdk-postcheck": "ATTACK_PREVENTED" if guard == "overblock" else "ATTACK_SUCCEEDED",
    }
    for attempt in detail["attempts"]:
        evidence = attempt["result"]["evidence"]
        assert evidence["provenance"] == "sdk-fixture-counter"
        assert evidence["complete"]
        for name, relative in {
            "demo": "demo/target/agent-security-demo.jar",
            "javaagent": "agent-security-javaagent/target/agent-security-javaagent.jar",
        }.items():
            with (Path(repo) / relative).open("rb") as source:
                assert (
                    evidence["artifact_sha256"][name]
                    == hashlib.file_digest(source, "sha256").hexdigest()
                )
        if guard != "none":
            assert evidence["sdk_audit"]
        if attempt["case_id"] == "sdk-clean" and guard != "overblock":
            assert [e["tool"] for e in evidence["events"] if e["kind"] == "tool.completed"] == [
                "readCustomer"
            ]
