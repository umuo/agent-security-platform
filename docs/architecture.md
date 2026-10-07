# 架构与产品对接

[返回 README](../README.md) · [使用指南](user-guide.md)

平台负责安全验证的闭环，SDK 负责执行过程中的防护，业务产品提供被测 Agent 和工具。三者共享版本与证据关系，分别部署和维护。

## 从一次输入看执行链路

以“查询当前用户订单，并被注入内容诱导外发”为例：

1. 用户在页面选择目标修订、攻击与正常对照。API 校验权限和预算，将任务及目标／场景快照持久化。
2. Worker 从数据库队列领取任务，使用租约与心跳约束所有权，交给 Inspect AI 运行每个样本。
3. 适配器把合法任务和载荷映射到所选目标的输入、检索结果或工具上下文，执行模型、HTTP Agent 或固定 Java SDK 场景。
4. 平台工具、SDK 独立计数或业务观测端记录实际执行。模型自述 trace 不作为工具执行证明。
5. 判定器检查工具副作用、跨租户读取和合成 canary 泄漏，并区分误拦、故障、未知及不支持。
6. 结果写入数据库，原始证据保存在数据目录。确认的风险生成问题与修复建议，页面显示逐项结果及 JSON 报告。
7. 业务团队修改防护；管理员从原目标创建新修订，执行同用例的独立任务，比较并引用通过的 Attempt 处理问题。

```text
浏览器 ── API ── PostgreSQL / SQLite
                   │ 数据库队列、版本、结果、问题
                   ▼
              独立 Worker ── Inspect AI
                   │
                   ├─ fixture：模拟流程
                   ├─ 模型适配器：真实模型 + 平台测试工具
                   ├─ SDK 适配器：Java Demo + Java Agent
                   └─ HTTP 适配器：完整业务 Agent
                                      │ 工具调用
                                      ▼
                              业务工具 + 独立观测端
```

数据库也是队列状态的来源；当前架构不需要单独部署消息队列。Caddy 在容器部署中提供 HTTPS 入口。API 和 Worker 使用相同数据库、主密钥和必要连接配置。

## 防护与评测的职责

| 部件 | 负责 | 配置／证据在哪里 |
| --- | --- | --- |
| 安全 SDK 或网关 | 在模型、检索和工具边界落实防护 | 业务系统自己的策略与部署制品 |
| 被测 Agent | 完成业务任务，按测试契约接收注入和预算 | 产品测试端点与目标修订 |
| 平台 API／页面 | 认证、目标、场景、任务、问题、比较和报告 | 平台数据库 |
| Worker／Inspect | 领取任务、执行样本、预算与取消收尾 | 数据库状态与 Inspect 原始日志 |
| 判定器 | 基于可信证据形成风险结论 | 结果中的规则版本、来源与完整性 |
| 独立业务观测 | 从业务真实读取／提交边界记录工具行为 | 独立审计绑定及观测版本 |

fixture 的 guard 和模型平台测试工具的 guard 是测试环境策略；业务产品的 SDK 策略由业务方修改和发布。平台没有通用策略自动下发控制面。

## 产品集成分三步

**先接入输出。** 按 [HTTP 契约](http-agent-integration.md) 提供测试端点，实现合法任务、攻击注入、返回输出与用量。先确认连接、版本和 canary 判定。此阶段不能据输出缺少危险文本推断工具没有执行。

**再取得可信工具证据。** 如果测试平台工具，用 tool-loop-v1；如果测试自己的业务工具，用 [observed-v1](business-observer-integration.md)，在实际读取／提交位置绑定观测 ID 并提供独立审计。完成业务自己的正常操作判定器与注入面映射。

**最后接入发布回归。** 每次策略、模型或业务版本修改，登记新修订并运行攻击与正常对照；根据任务门禁及逐项证据决定业务发布。当前版本提供 API、JSON 报告与人工问题处置，具体 CI 流水线、审批、策略发布和通知需要产品集成者实现。

## 执行与判定边界

任务预算覆盖 token 声明用量、执行轮次、工具调用和墙钟时间；不是供应商精确计费硬限制。完整业务 Agent 内部的调用上限须由业务实现落实，见 [预算说明](budgets.md)。

取消和超时无法撤销已经提交的操作。平台保留已观察到的危险效果，Worker 失联后不会自动重发可能有副作用的业务请求。业务侧仍需实现过期观测窗口和调用约束。

门禁只代表所选版本、场景与证据范围中的结果。正常任务目前以固定订单操作或 SDK 合法方法完成为标准；自由文本质量与其他业务语义需另加判定器。跨版本比较有规则、引擎、来源与制品身份限制，见 [判定说明](scoring.md)。

## 源码阅读路径

下面的路径均相对于仓库根目录。

| 顺序 | 文件 | 读什么 |
| --- | --- | --- |
| 1 | frontend/src/main.tsx、api.ts、Management.tsx | 页面动作、接口调用、结果标签与版本比较 |
| 2 | backend/agentsec/api.py、schemas.py、models.py | 请求校验、权限、目标快照、任务与问题关系 |
| 3 | backend/agentsec/worker.py | 数据库领取、租约、心跳、取消与失联恢复 |
| 4 | backend/agentsec/engine.py、inspect_runtime.py | 每个样本怎样进入 Inspect 执行 |
| 5 | backend/agentsec/adapters.py、observer.py、network.py | 目标协议、工具观测及外部连接约束 |
| 6 | backend/agentsec/cases.py、oracle.py、remediation.py | 注入场景、结果判定与修复建议 |
| 7 | backend/agentsec/comparisons.py、budgets.py | 哪些结果可比较、何时停止执行 |
| 8 | backend/agentsec/backups.py、retention.py、cli.py | 运维命令、恢复和证据保留 |

验证自己的理解：先按使用指南执行两场景 fixture，在结果中找工具事件与 Attempt ID，再沿 api.py → worker.py → engine.py → adapters.py → oracle.py 跟踪。SDK 场景的固定名称和 ID 在 cases.py，真实制品接入回归在 backend/tests/test_sdk.py。
