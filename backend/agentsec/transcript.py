"""记录适配器可见的往返；不采集认证头、观测凭据或模型内部推理。"""

import asyncio
import json
import time
from datetime import UTC, datetime

MAX_TRACE_BYTES = 256 * 1024
MAX_PART_BYTES = 16 * 1024
MAX_EXCHANGES = 16
REQUEST_FIELDS = {
    "model",
    "messages",
    "tools",
    "temperature",
    "max_tokens",
    "stream",
    "protocol",
    "turn",
    "user_message",
    "attack",
    "setup_turns",
    "test_fixture",
    "budget",
}
PRIVATE_FIELDS = {
    "authorization",
    "api_key",
    "apikey",
    "password",
    "secret",
    "token",
    "access_token",
}


def size(value):
    return len(json.dumps(value, ensure_ascii=False).encode("utf-8"))


def snapshot(value, credential, depth=0):
    if depth > 8:
        return "[层级过深，省略]"
    if isinstance(value, str):
        if credential:
            value = value.replace(credential, "[凭据已隐藏]")
        encoded = value.encode("utf-8")
        return (
            encoded[:4096].decode("utf-8", errors="ignore") + "[内容截断]"
            if len(encoded) > 4096
            else value
        )
    if isinstance(value, dict):
        result = {
            snapshot(str(key), credential): "[敏感字段已隐藏]"
            if str(key).lower() in PRIVATE_FIELDS
            else snapshot(entry, credential, depth + 1)
            for key, entry in list(value.items())[:64]
        }
        if len(value) > 64:
            result["_omitted_fields"] = True
        return result
    if isinstance(value, list):
        result = [snapshot(entry, credential, depth + 1) for entry in value[:64]]
        if len(value) > 64:
            result.append("[其余条目省略]")
        return result
    return value if value is None or isinstance(value, (bool, int, float)) else "[无法记录的类型]"


def store(trace, entry, field, value, credential):
    captured = snapshot(value, credential)
    if size(captured) > MAX_PART_BYTES:
        captured = {"omitted": True, "reason": "单段记录超过 16 KiB，省略"}
    entry[field] = captured
    if size(trace) > MAX_TRACE_BYTES - 1024:
        entry[field] = {"omitted": True, "reason": "样本记录达到大小上限，省略"}
        trace["limited"] = True


def public_response(response):
    if not isinstance(response, dict):
        return {"invalid_response_type": True}
    result = {
        key: response[key]
        for key in ["protocol", "output", "tool_calls", "usage"]
        if key in response
    }
    choices = response.get("choices")
    if isinstance(choices, list) and choices:
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        if isinstance(message, dict):
            result["message"] = {
                key: message[key] for key in ["role", "content", "tool_calls"] if key in message
            }
    return result


async def recorded_request(evidence, requester, settings, url, credential, body, **kwargs):
    trace = evidence.setdefault("transcript", {"version": "v1", "exchanges": [], "limited": False})
    entry = None
    if len(trace["exchanges"]) < MAX_EXCHANGES and size(trace) < MAX_TRACE_BYTES - 2048:
        entry = {
            "round": len(trace["exchanges"]) + 1,
            "started_at": datetime.now(UTC).isoformat(),
            "status": "requesting",
        }
        trace["exchanges"].append(entry)
        store(
            trace,
            entry,
            "request",
            {key: value for key, value in body.items() if key in REQUEST_FIELDS},
            credential,
        )
    else:
        trace["limited"] = True
    started = time.monotonic()
    try:
        response = await requester(settings, url, credential, body, **kwargs)
        if entry is not None:
            store(trace, entry, "response", public_response(response), credential)
            entry["status"] = "returned"
        return response
    except asyncio.CancelledError:
        if entry is not None:
            entry["status"] = "interrupted"
        raise
    except Exception:
        if entry is not None:
            entry["status"] = "failed"
        raise
    finally:
        if entry is not None:
            entry["duration_ms"] = round((time.monotonic() - started) * 1000)


def record_tool_result(evidence, name, call_id, content, credential):
    trace = evidence.get("transcript")
    if not trace or not trace["exchanges"] or trace["limited"]:
        return
    entry = trace["exchanges"][-1]
    previous = entry.get("tool_results", [])
    if not isinstance(previous, list):
        entry["tool_results_limited"] = True
        return
    results = list(previous)
    if len(results) >= 12:
        entry["tool_results_limited"] = True
        return
    results.append({"name": name, "call_id": call_id, "content": content})
    store(trace, entry, "tool_results", results, credential)
