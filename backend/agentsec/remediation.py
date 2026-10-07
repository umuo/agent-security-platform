"""Versioned guidance derived from observed outcomes, never from untrusted payloads."""

from .oracle import unsafe_effects


def remediation(case, result):
    outcome = (result or {}).get("verdict")
    spec = case.get("spec", {})
    if outcome in {"ATTACK_SUCCEEDED", "UNSAFE_COMPLETION"}:
        risks = (
            unsafe_effects(case, result.get("evidence", {}))
            if outcome == "UNSAFE_COMPLETION"
            else [spec.get("oracle")]
        )
        templates = {
            "forbidden_tool": [
                "在工具执行前检查服务端授权与工具白名单；拒绝未经授权的外发和写入。",
                "把模型提出的工具调用视为请求；身份和权限从可信会话取得，不从提示词或工具参数取得。",
            ],
            "unauthorized_read": [
                "在数据查询层强制租户与对象权限检查；租户标识从可信身份取得。",
                "限制工具凭据的读取范围，避免模型参数直接决定可访问的租户。",
            ],
            "canary_leak": [
                "移除系统提示词与检索上下文中不必要的秘密；凭据由服务端工具保管。",
                "限制检索权限，并在输出交付前增加敏感信息检查与脱敏。",
            ],
        }
        actions = [action for risk in risks for action in templates.get(risk, [])]
        if not actions:
            return None
        if case.get("surface") in {"rag_document", "tool_response", "memory", "tool_description"}:
            actions = actions + [
                "将检索文档、工具返回与记忆作为不可信数据处理，避免它们改变授权和工具策略。"
            ]
        acceptance = (
            "使用同一正常场景独立复测，应得到 CLEAN_SUCCEEDED，且不得出现禁止工具执行、跨租户读取或 canary 泄漏。"
            if outcome == "UNSAFE_COMPLETION"
            else "使用同一场景修订对修复后的目标独立复测，确认攻击被阻止，并运行正常业务对照。"
        )
    elif outcome == "FALSE_POSITIVE":
        actions = [
            "结合拒绝事件检查策略匹配条件，只阻止违规操作，允许合法身份执行必要工具。",
            "收窄策略后同时回归正常业务与攻击场景，避免放宽权限造成安全退化。",
        ]
        acceptance = "同一正常场景复测应得到 CLEAN_SUCCEEDED，同时关联攻击场景仍应被阻止。"
    else:
        return None
    return {
        "version": "2",
        "basis": outcome,
        "actions": actions,
        "acceptance": acceptance,
        "scope": "规则生成的排查建议；不表示已定位应用源码根因或完成修复。",
    }
