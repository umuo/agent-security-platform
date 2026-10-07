import asyncio
import json

import pytest
from agentsec.transcript import MAX_TRACE_BYTES, record_tool_result, recorded_request


async def test_records_visible_payload_redacts_credentials_and_ignores_headers():
    credential = "private-auth-canary-123"
    body = {"messages": [{"role": "user", "content": credential}], "Authorization": credential}
    evidence = {}

    async def requester(settings, url, secret, sent):
        assert sent is body and secret == credential
        return {"choices": [{"message": {"content": credential, "reasoning_content": "hidden"}}],
                "tool_calls": [{"arguments": {credential: "test", "api_key": credential}}],
                "headers": {"Authorization": credential}, "usage": {"total_tokens": 9}}

    response = await recorded_request(evidence, requester, None, "https://target.example", credential, body)
    assert response["choices"][0]["message"]["content"] == credential
    trace = evidence["transcript"]
    serialized = json.dumps(trace)
    assert credential not in serialized and "Authorization" not in serialized
    assert "reasoning_content" not in serialized and "hidden" not in serialized
    assert trace["exchanges"][0]["status"] == "returned"
    assert trace["exchanges"][0]["duration_ms"] >= 0
    record_tool_result(evidence, "query_orders", "call-1", credential, credential)
    assert credential not in json.dumps(trace)


@pytest.mark.parametrize("failure", [ValueError, asyncio.CancelledError])
async def test_preserves_failed_or_cancelled_request_without_exception_secrets(failure):
    evidence = {}

    async def requester(*args):
        raise failure("private-auth-canary-123")

    with pytest.raises(failure):
        await recorded_request(evidence, requester, None, "https://target.example", "private-auth-canary-123", {"user_message": "hello"})
    entry = evidence["transcript"]["exchanges"][0]
    assert entry["status"] == ("interrupted" if failure is asyncio.CancelledError else "failed")
    assert "response" not in entry
    assert "private-auth" not in json.dumps(evidence)


async def test_record_limits_do_not_stop_execution_and_snapshot_is_immutable():
    evidence = {}
    body = {"messages": [{"content": "汉" * 5000} for _ in range(64)]}
    calls = 0

    async def requester(*args):
        nonlocal calls
        calls += 1
        return {"output": "x" * 10000}

    for _ in range(30):
        await recorded_request(evidence, requester, None, "https://target.example", "", body)
    trace = evidence["transcript"]
    assert calls == 30 and len(trace["exchanges"]) == 16 and trace["limited"]
    assert len(json.dumps(trace, ensure_ascii=False).encode()) <= MAX_TRACE_BYTES
    assert trace["exchanges"][0]["request"]["omitted"]
    body["messages"].clear()
    assert trace["exchanges"][0]["request"]["omitted"]
