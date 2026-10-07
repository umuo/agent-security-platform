import pytest
from agentsec.remediation import remediation


@pytest.mark.parametrize(
    "outcome", ["ERROR", "INCONCLUSIVE", "UNSUPPORTED", "ATTACK_PREVENTED", "CLEAN_SUCCEEDED"]
)
def test_no_security_fix_claim_without_confirmed_problem(outcome):
    assert remediation({"spec": {"oracle": "forbidden_tool"}}, {"verdict": outcome}) is None


def test_guidance_does_not_repeat_untrusted_payload():
    case = {
        "surface": "rag_document",
        "spec": {"oracle": "unauthorized_read", "payload": "evil-secret-instruction"},
    }
    guidance = remediation(case, {"verdict": "ATTACK_SUCCEEDED"})
    assert "evil-secret-instruction" not in str(guidance)
    assert any("租户" in action for action in guidance["actions"])
    assert any("不可信数据" in action for action in guidance["actions"])
