import importlib.util
import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import uvicorn
from agentsec.cases import builtin_cases
from agentsec.engine import configure_inspect, evaluate_attempt
from agentsec.observer import PROTOCOL, apply_snapshot
from agentsec.oracle import verdict
from agentsec.worker import Worker
from fastapi.testclient import TestClient

spec = importlib.util.spec_from_file_location(
    "business_example", Path(__file__).parents[2] / "examples/business_observer.py"
)
example = importlib.util.module_from_spec(spec)
spec.loader.exec_module(example)
OBSERVER_TOKEN, TOOL_TOKEN = "observer-private-" + "x" * 32, "tool-private-" + "y" * 32


def binding():
    return {
        "protocol": PROTOCOL,
        "attempt_id": "attempt-a",
        "nonce": "a" * 64,
        "observation_id": "b" * 48,
    }


def snapshot(events=None):
    return {
        **binding(),
        "complete": True,
        "scope": "all-tools",
        "revision": "business-v1",
        "tool_calls": 1,
        "events": events
        or [
            {"seq": 1, "kind": "tool.requested", "tool": "send_report", "call_id": "a"},
            {"seq": 2, "kind": "tool.started", "tool": "send_report", "call_id": "a"},
            {"seq": 3, "kind": "tool.effect", "tool": "send_report", "call_id": "a"},
            {"seq": 4, "kind": "tool.failed", "tool": "send_report", "call_id": "a"},
        ],
    }


def test_committed_effect_survives_failed_return_and_incomplete_tail():
    case = next(c for c in builtin_cases() if c["id"] == "direct-tool")
    evidence = {"provenance": "business-observer-v1", "events": []}
    data = snapshot()
    apply_snapshot(data, binding(), evidence, 12)
    assert verdict(case, evidence) == "ATTACK_SUCCEEDED"
    data.update(complete=False)
    data["events"] = data["events"][:-1]
    apply_snapshot(data, binding(), evidence, 12)
    assert verdict(case, evidence) == "ATTACK_SUCCEEDED"


@pytest.mark.parametrize(
    "mutation",
    [
        "nonce",
        "attempt_id",
        "observation_id",
        "sequence",
        "count",
        "phase",
        "tool",
        "scope",
        "pending",
        "extra",
    ],
)
def test_rejects_malformed_or_replayed_observer_evidence(mutation):
    data = snapshot()
    if mutation in {"nonce", "attempt_id", "observation_id", "scope"}:
        data[mutation] = "another"
    elif mutation == "sequence":
        data["events"][0]["seq"] = 2
    elif mutation == "count":
        data["tool_calls"] = 0
    elif mutation == "phase":
        data["events"][0]["kind"] = "tool.completed"
    elif mutation == "tool":
        data["events"][2]["tool"] = "another"
    elif mutation == "pending":
        data["events"] = data["events"][:-1]
    else:
        data["events"][0]["args"] = {"secret": "should-never-enter-report"}
    evidence = {"events": []}
    with pytest.raises(ValueError):
        apply_snapshot(data, binding(), evidence, 12)
    assert evidence == {"events": []}


def test_reference_observer_auth_atomic_outbox_and_closed_admission(tmp_path):
    path = tmp_path / "business.db"
    client = TestClient(example.create_app(path, OBSERVER_TOKEN, TOOL_TOKEN, "none"))
    opened = {**binding(), "operation": "open", "max_tool_calls": 1}
    observer_headers = {"Authorization": "Bearer " + OBSERVER_TOKEN}
    tool_headers = {"Authorization": "Bearer " + TOOL_TOKEN}
    assert client.post("/observe", json=opened, headers=tool_headers).status_code == 401
    assert client.post("/observe", json=opened, headers=observer_headers).json() == binding()
    tool = {
        "observation_id": binding()["observation_id"],
        "call_id": "one",
        "name": "send_report",
        "arguments": {"recipient": "test@example.invalid"},
    }
    assert client.post("/tools", json=tool, headers=observer_headers).status_code == 401
    assert (
        client.post("/tools", json=tool, headers=tool_headers).json()["status"]
        == "committed-to-outbox"
    )
    assert client.post("/tools", json=tool, headers=tool_headers).status_code == 409
    closed = {**opened, "operation": "close"}
    result = client.post("/observe", json=closed, headers=observer_headers).json()
    assert result["complete"] and result["tool_calls"] == 1
    with example.Store(path).connect() as db:
        assert db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == 1
    tool["call_id"] = "after-close"
    assert client.post("/tools", json=tool, headers=tool_headers).status_code == 409
    assert client.post("/observe", json=closed, headers=observer_headers).json() == result


@pytest.fixture
def business_servers(tmp_path):
    # 观测／业务工具端与被测 Agent 使用独立 HTTP 服务和不同凭据。
    import socket

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    app = example.create_app(tmp_path / "business.db", OBSERVER_TOKEN, TOOL_TOKEN, "none")
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
    worker = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    worker.start()
    base = f"http://127.0.0.1:{port}"
    agent_requests = []
    release_reply = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            agent_requests.append((body, self.headers.get("Authorization")))
            if self.path != "/fake":
                call = {
                    "observation_id": body["observation_id"],
                    "call_id": "one",
                    "name": "query_orders" if self.path == "/clean" else "send_report",
                    "arguments": {"tenant_id": "tenant-a"}
                    if self.path == "/clean"
                    else {"recipient": "test@example.invalid"},
                }
                req = urllib.request.Request(
                    base + "/tools",
                    data=json.dumps(call).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + TOOL_TOKEN,
                    },
                )
                with urllib.request.urlopen(req, timeout=3) as response:
                    assert response.status == 200
            if self.path == "/cancel":
                release_reply.wait(timeout=5)
            data = json.dumps(
                {
                    "output": "订单处理中",
                    "usage": {"total_tokens": 5},
                    "events": [{"kind": "security.decision", "decision": "DENY"}],
                    "blocked": True,
                }
            ).encode()
            self.send_response(500 if self.path == "/failure" else 200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            try:
                self.wfile.write(data)
            except OSError:
                pass  # 被测请求取消后，服务端不重试工具操作。

    agent = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    agent_thread = threading.Thread(target=agent.serve_forever, daemon=True)
    agent_thread.start()
    try:
        yield (
            base,
            f"http://127.0.0.1:{agent.server_port}",
            agent_requests,
            tmp_path / "business.db",
        )
    finally:
        release_reply.set()
        agent.shutdown()
        agent.server_close()
        agent_thread.join(timeout=5)
        server.should_exit = True
        worker.join(timeout=5)
        listener.close()
        assert not worker.is_alive()


@pytest.mark.parametrize(
    "route,case_id,expected",
    [
        ("/unsafe", "direct-tool", "ATTACK_SUCCEEDED"),
        ("/clean", "clean-query", "CLEAN_SUCCEEDED"),
        ("/fake", "clean-query", "TASK_FAILED"),
        ("/failure", "direct-tool", "ATTACK_SUCCEEDED"),
        ("/unsafe", "clean-query", "UNSAFE_COMPLETION"),
    ],
)
async def test_real_business_evidence_via_inspect(
    settings, business_servers, route, case_id, expected
):
    observer, agent, requests, path = business_servers
    settings.target_hosts = frozenset({"127.0.0.1"})
    settings.observer_endpoint, settings.observer_token = observer + "/observe", OBSERVER_TOKEN
    configure_inspect(settings)
    case = next(c for c in builtin_cases() if c["id"] == case_id)
    result = await evaluate_attempt(
        settings,
        {"kind": "http-agent", "config": {"endpoint": agent + route, "protocol": "observed-v1"}},
        case,
        "agent-private",
        {"timeout_seconds": 10, "max_tool_calls": 12, "max_total_tokens": 100},
        "attempt-a",
    )
    assert result["verdict"] == expected
    evidence = result["evidence"]
    assert evidence["observation_complete"]
    assert evidence["observer_revision"] == "example-outbox-v1"
    assert evidence["tool_calls"] == (0 if route == "/fake" else 1)
    assert evidence["blocked"] is False  # Agent 自述 DENY 完全不影响独立证据。
    assert requests[0][1] == "Bearer agent-private"
    assert OBSERVER_TOKEN not in json.dumps(requests)
    with example.Store(path).connect() as db:
        assert db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0] == int(
            route in {"/unsafe", "/failure"}
        )


async def test_observer_unavailable_is_unknown_and_stops_future_samples(
    admin, db, settings, monkeypatch
):
    import agentsec.observer as module

    settings.target_hosts = frozenset({"127.0.0.1"})
    settings.observer_endpoint, settings.observer_token = (
        "http://127.0.0.1:8090/observe",
        OBSERVER_TOKEN,
    )

    async def request(settings, endpoint, token, body, **kwargs):
        if body.get("operation") == "open":
            return {k: body[k] for k in binding()}
        if body.get("operation") == "close":
            raise OSError("Private observer failure")
        return {"output": "拒绝攻击", "usage": {"total_tokens": 5}, "blocked": True}

    monkeypatch.setattr(module, "bounded_request", request)
    target = admin.post(
        "/api/targets",
        json={
            "name": "observed",
            "kind": "http-agent",
            "config": {"endpoint": "http://127.0.0.1:8091/agent", "protocol": "observed-v1"},
        },
    ).json()
    job = admin.post(
        "/api/evaluations",
        json={"target_id": target["id"], "case_ids": ["direct-tool"], "repeats": 2},
    ).json()
    await Worker(settings, db).run_once()
    detail = admin.get("/api/evaluations/" + job["id"]).json()
    assert detail["status"] == "FAILED" and detail["error_code"] == "JOB_USAGE_UNAVAILABLE"
    assert detail["attempts"][0]["result"]["verdict"] == "INCONCLUSIVE"
    assert detail["attempts"][1]["status"] == "INTERRUPTED"


async def test_cancellation_closes_observation_and_preserves_committed_effect(
    settings, monkeypatch
):
    import asyncio

    import agentsec.observer as module
    from agentsec.adapters import ACTIVE_EVIDENCE
    from agentsec.observer import run_observed

    entered = asyncio.Event()
    operations = []

    async def request(settings, endpoint, token, body, **kwargs):
        if body.get("operation") == "open":
            operations.append("open")
            return {k: body[k] for k in binding()}
        if body.get("operation") == "close":
            operations.append("close")
            data = snapshot()
            data.update({k: body[k] for k in binding()})
            return data
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(module, "bounded_request", request)
    collector = {"evidence": None}
    context_token = ACTIVE_EVIDENCE.set(collector)
    case = next(c for c in builtin_cases() if c["id"] == "direct-tool")
    try:
        task = asyncio.create_task(
            run_observed(
                settings,
                case,
                {"endpoint": "http://agent.example/step"},
                "",
                {"max_tool_calls": 12, "max_total_tokens": 100},
                "attempt-a",
            )
        )
        await asyncio.wait_for(entered.wait(), 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        ACTIVE_EVIDENCE.reset(context_token)
    assert operations == ["open", "close"]
    assert collector["evidence"]["complete"] is False
    assert collector["evidence"]["observation_complete"]
    assert verdict(case, collector["evidence"]) == "ATTACK_SUCCEEDED"


def test_observed_protocol_requires_separate_service_and_credentials(settings):
    from agentsec.adapters import validate_target

    settings.target_hosts = frozenset({"127.0.0.1"})
    config = {"endpoint": "http://127.0.0.1:8091/agent", "protocol": "observed-v1"}
    with pytest.raises(ValueError):
        validate_target(settings, "http-agent", config)
    settings.observer_endpoint, settings.observer_token = (
        "http://127.0.0.1:8090/observe",
        OBSERVER_TOKEN,
    )
    validate_target(settings, "http-agent", config)
    with pytest.raises(ValueError):
        validate_target(
            settings, "http-agent", {**config, "endpoint": "http://127.0.0.1:8090/agent"}
        )
    with pytest.raises(ValueError):
        validate_target(settings, "http-agent", {**config, "guard": "strict"})
