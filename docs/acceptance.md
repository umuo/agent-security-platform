# 生产可用验收清单

勾选必须有真实代码、测试或运行证据。2026-10-07 先完成代码与本地验收，随后在用户指定的 Podman 主机完成容器全栈与内网 HTTPS 运行验证。验证历史见 verification.md，操作说明见 operations.md。

- [x] 指定目录有独立项目、锁定依赖、独立虚拟环境安装与 API/Worker 启动。见 verification.md 的独立环境验证。
- [x] 认证、角色权限、CSRF、持久化登录限流、加密凭据与响应／报告敏感字段约束。见 test_api.py、test_accounts.py、test_origin.py、test_secret_files.py；浏览器验证会话撤销和查看者只读。原始评测证据可包含测试内容，按敏感数据管理，不能宣称所有日志均不含业务数据。
- [x] SQLite 本地使用、真实 PostgreSQL 路径、显式迁移与实际备份恢复。见 test_production.py、test_backups.py、test_postgres_restore.py 和独立 CLI 演练；数据库套件使用 PostgreSQL 16.2，远端容器 PostgreSQL 17.11 的运行、备份与独立恢复也已验证.
- [x] 持久化队列、并发领取、租约心跳、失联恢复、取消、预算与副作用不自动重发。见 test_worker.py、test_cancellation.py、test_job_budgets.py、test_job_deadline.py；真实业务提交后 UI 取消仍保留危险证据，后续样本不运行。
- [x] 真实 Inspect AI 0.3.277 Worker 与不可变目标／用例快照。见 test_worker.py、test_api.py 和独立运行 Worker 的浏览器评测。
- [x] 内置提示词攻击、五类注入面、诱导工具调用、多轮与正常对照。见 cases.py、test_adapters.py、test_http_tools.py；多轮前置响应真实进入后续请求。场景覆盖有限，不代表未知攻击不存在。
- [x] OpenAI 兼容适配器、HTTP 输出／平台工具循环／独立业务观测协议及实际 LangChain4j 制品接入。见 test_adapters.py、test_http_tools.py、test_business_observer.py、test_sdk.py 和三组 Chrome 验收。OpenAI 兼容协议以真实本地 HTTP 服务验证；尚未以付费外部模型证明线上连接或模型鲁棒性。SDK 18 样本属于确定性边界回归。
- [x] 可信副作用、输出泄漏、未知、故障与不支持分别记录；目标自述 trace 不作为执行证明。见 test_oracle.py、test_normal_safety.py、test_business_observer.py、test_cancellation.py。独立业务参考服务实际订单读取／outbox 提交已验证；任意生产业务需按业务观测接入契约集成。
- [x] 问题确认、基于证据的修复建议、同资产独立复测关闭、JSON 报告与版本比较。见 test_remediation.py、test_comparisons.py、test_worker.py 和浏览器验收；比较为描述性结果，不提供统计显著性结论。
- [x] 桌面／移动管理流程、键盘焦点、真实空状态、加载、表单校验、断网恢复和只读角色。见 frontend/e2e/acceptance.cjs、business-observer.cjs、experience.cjs；体验专项使用全新独立 SQLite 数据库，延迟与断网通过浏览器注入，写入校验与权限使用真实 API。
- [x] 本地存活／就绪、Worker 健康、离线证据保留、备份恢复及配置文档。见 test_health.py、test_retention.py、test_backups.py、test_inspect_runtime.py。内部跟踪／缓存、备份及数据库有独立保留边界；需部署环境监控磁盘空间。
- [x] 自动化覆盖执行关键边界，实际 SQLite／PostgreSQL、Chrome 与 Java 制品验证。最新完整后端结果为 SQLite 132 通过／2 跳过、PostgreSQL 133 通过／1 跳过；跳过均为数据库专属路径。具体浏览器结果见 verification.md。
- [x] Podman 实际构建 Linux ARM64 镜像并启动 PostgreSQL 17.11、迁移、API、Worker 和 Caddy；TLS 证书链及 IP 校验、Secure Cookie、UID 10001／零有效能力／NoNewPrivs、受限数据库角色、秘密隔离、SDK 只读挂载和 k8s-file 日志大小限制均有运行证据。分阶段启动器真实重复运行通过。Podman 日志限制不等同 Docker 三文件保留；Docker Engine 与公网 ACME 路径未实测。见 verification.md 的远端 Podman 验收。

代码、本地功能及用户指定 Podman 内网部署的验收已完成。外部模型与实际产品接入需另行提供对应环境和业务观测实现，不能用本地合成回归替代。
