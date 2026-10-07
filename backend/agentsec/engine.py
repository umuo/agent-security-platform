import asyncio
import contextvars

from inspect_ai import Task, eval_async
from inspect_ai.dataset import Sample
from inspect_ai.model import ModelOutput
from inspect_ai.scorer import Score, scorer
from inspect_ai.solver import solver

from .adapters import ACTIVE_EVIDENCE, execute
from .inspect_runtime import configure_trace
from .oracle import ORACLE_REVISION, verdict

CONTEXT = contextvars.ContextVar("evaluation_context")


@solver
def target_solver():
    async def solve(state, generate):
        context = CONTEXT.get()
        collector = context["collector"]
        execution_context = context["execution"]
        evidence_token = ACTIVE_EVIDENCE.set(collector)
        try:
            evidence = await asyncio.wait_for(
                execute(**execution_context), timeout=execution_context["budget"]["timeout_seconds"]
            )
        except TimeoutError:
            evidence = collector["evidence"] or {"events": []}
            evidence.update(complete=False, error_code="TARGET_TIMEOUT")
        except Exception:
            # 异常消息可能含 URL、凭据和目标正文，结果只保留稳定错误码。
            evidence = collector["evidence"] or {"events": []}
            evidence.update(complete=False, error_code="TARGET_EXECUTION_FAILED")
        finally:
            ACTIVE_EVIDENCE.reset(evidence_token)
        value = (
            "UNSUPPORTED"
            if evidence.get("unsupported")
            else verdict(execution_context["case"], evidence)
        )
        state.metadata["evidence"] = evidence
        state.output = ModelOutput.from_content("mockllm/model", value)
        state.completed = True
        return state

    return solve


@scorer(metrics=[])
def security_oracle():
    async def score(state, target):
        value = state.output.completion
        return Score(value=value, answer=value, metadata={"oracle_revision": ORACLE_REVISION})

    return score


def configure_inspect(settings):
    root = settings.data_dir.resolve() / "inspect"
    root.mkdir(parents=True, exist_ok=True)
    # 固定 Inspect 0.3.277；统一将其内部文件放在受控数据卷。
    import inspect_ai._util.appdirs as appdirs

    appdirs.user_data_path = lambda *a, **k: root / "internal"
    appdirs.user_cache_path = lambda *a, **k: root / "cache"
    configure_trace(root)


async def evaluate_attempt(
    settings,
    target,
    case,
    secret,
    budget,
    attempt_id,
    job_timeout_seconds=None,
    evidence_collector=None,
):
    collector = evidence_collector if evidence_collector is not None else {"evidence": None}
    token = CONTEXT.set(
        {
            "collector": collector,
            "execution": {
                "settings": settings,
                "target": target,
                "case": case,
                "secret": secret,
                "budget": budget,
                "attempt_id": attempt_id,
            },
        }
    )

    async def timed_out():
        await finalize_evidence(collector)
        return interrupted_result(case, collector, "JOB_TIME_BUDGET_EXHAUSTED")

    try:
        task = Task(
            name="agentsec_" + attempt_id.replace("-", ""),
            dataset=[Sample(id=attempt_id, input=case["spec"]["user_task"])],
            solver=target_solver(),
            scorer=security_oracle(),
        )
        deadline = asyncio.timeout(job_timeout_seconds)
        try:
            async with deadline:
                logs = await eval_async(
                    task,
                    model="mockllm/model",
                    log_dir=str(settings.data_dir / "inspect" / "logs"),
                    max_samples=1,
                )
        except TimeoutError:
            return await timed_out()
        if deadline.expired():
            return await timed_out()
        await finalize_evidence(collector)
        if logs[0].status != "success" or not logs[0].samples:
            return interrupted_result(case, collector, "INSPECT_FAILED")
        sample = logs[0].samples[0]
        evidence = collector["evidence"] or sample.metadata["evidence"]
        return {
            "verdict": "UNSUPPORTED" if evidence.get("unsupported") else verdict(case, evidence),
            "evidence": evidence,
            "engine": "inspect-ai",
            "engine_version": "0.3.277",
            "oracle_revision": ORACLE_REVISION,
        }
    finally:
        CONTEXT.reset(token)


async def finalize_evidence(collector):
    finalize = collector.get("finalize")
    evidence = collector.get("evidence")
    if finalize is not None and evidence is not None and not evidence.get("observation_complete"):
        await finalize()
        evidence["finalized_outside_inspect"] = True


def interrupted_result(case, collector, code):
    """从实际执行的共享采集器取证；中断后的负向证据不能证明安全。"""
    evidence = collector["evidence"] or {"events": []}
    evidence.update(complete=False, error_code=code, usage_complete=False)
    outcome = verdict(case, evidence)
    if outcome == "ERROR" and code in {"EXECUTION_INTERRUPTED", "WORKER_STOPPED"}:
        outcome = "INCONCLUSIVE"
    return {
        "verdict": outcome,
        "evidence": evidence,
        "engine": "inspect-ai",
        "engine_version": "0.3.277",
        "oracle_revision": ORACLE_REVISION,
    }
