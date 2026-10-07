DEFAULT_JOB_LIMITS = {"max_job_tokens": 120000, "max_job_turns": 500, "max_job_tool_calls": 1000}


def usage_totals(attempts):
    totals = {"tokens": 0, "turns": 0, "tool_calls": 0, "usage_complete": True}
    for attempt in attempts:
        if not attempt.result:
            continue
        evidence = attempt.result.get("evidence", {})
        if evidence.get("unsupported"):
            continue
        for field in ("tokens", "turns", "tool_calls"):
            value = evidence.get(field)
            if type(value) is int and value >= 0:
                totals[field] += value
            else:
                totals["usage_complete"] = False
        if not evidence.get("usage_complete", False):
            totals["usage_complete"] = False
    return totals


def remaining_budget(budget, usage):
    effective = dict(budget)
    for field, attempt_field in (
        ("tokens", "max_total_tokens"),
        ("turns", "max_turns"),
        ("tool_calls", "max_tool_calls"),
    ):
        limit = "max_job_" + field
        remaining = budget.get(limit, DEFAULT_JOB_LIMITS[limit]) - usage[field]
        if remaining <= 0:
            return None, "JOB_" + field.upper() + "_BUDGET_EXHAUSTED"
        effective[attempt_field] = min(effective[attempt_field], remaining)
    effective["max_tokens"] = min(effective["max_tokens"], effective["max_total_tokens"])
    return effective, None
