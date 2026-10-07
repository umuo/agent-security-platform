# 本地运行与开发验证

本页为源码开发方式；本机容器和生产部署见 [部署教程](deployment.md)。

将攻击用例、目标版本、Inspect 执行记录、问题跟踪和修复复测放在一个平台中。支持提示词攻击、直接和间接注入、诱导工具调用、跨租户读取、秘密泄露和正常业务对照。

本页命令在仓库根目录执行。首次使用页面请先阅读 [使用指南](user-guide.md)。运行范围见 [验证记录](verification.md) 和 [验收清单](acceptance.md)。

## 本地运行

需要 Python 3.12+、Node.js 22.12+。在仓库根目录执行，使用项目虚拟环境：

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install --index-url https://pypi.org/simple -r requirements.lock
pip install --no-deps -e .
cp .env.example .env
cd frontend
npm ci
npm run build
cd ..
agentsec migrate
agentsec seed
agentsec create-user --username admin
agentsec serve
```

创建用户时交互输入至少 12 字符的密码。另一个终端进入同一仓库并激活虚拟环境，执行 `agentsec worker`。浏览器打开 `http://127.0.0.1:8088`，登录后创建目标、选择攻击与正常对照用例、提交评测。Worker 是后台任务执行进程，使用 Inspect AI 运行每个样本。

本地数据保存在 `data/`，自动生成的加密主密钥为 `data/master.key`。备份需同时保留数据库、加密主密钥和 Inspect 日志；丢失主密钥将无法解密目标凭据。凭据只由管理员创建时输入，查询接口不会返回。

## 目标与证据范围

| 目标类型 | 用途 | 能证明什么 |
| --- | --- | --- |
| fixture | 无模型成本的确定性演示，strict/none/overblock 防护对照 | 验证任务、工具记录、评分和复测流程，不代表真实模型攻击抵抗能力 |
| openai | OpenAI 兼容的 Chat Completions 模型接口 | 在平台隔离的合成订单工具环境中测试真实模型的工具与输出行为 |
| http-agent | 接入已有 Agent 测试端点 | 仅输出模式检查 canary 泄漏；工具循环 v1 由平台实际执行测试工具并记录可信证据，目标自报事件不采信 |
| langchain4j | 本机已有安全 SDK 的 Demo 和 Java Agent JAR | 六个固定 SDK 边界回归场景；使用确定性 Demo，不代表任意提示词下的模型安全性 |

HTTP 和模型目标的主机名必须加入 `.env` 的 `AGENTSEC_TARGET_HOSTS`，逗号分隔。平台固定 DNS 解析结果、拒绝重定向，并限制响应大小。模型目标填写类似 `https://model.example.com/v1` 的 base URL，适配器追加 `/chat/completions`。

Java SDK 目标需要 JDK 17+，配置 `AGENTSEC_SDK_REPO` 指向已构建的 SDK 仓库，其中应包含 `demo/target/agent-security-demo.jar` 和 `agent-security-javaagent/target/agent-security-javaagent.jar`。只能运行固定 Demo 场景，目标配置不能提交任意命令。

攻击成功优先依据实际工具执行、越权数据读取或合成秘密泄露。执行不完整、证据不可信、适配器不支持等结果不会计为防护成功。正常用例用于发现误拦截。Worker 失联后将任务标记为未知／失败，不自动重发可能有副作用的请求。

## 修复复测

攻击成功或正常业务误拦截会生成问题。为原目标创建新版本，修改策略或模型配置后，用同一版本攻击用例复测。问题关闭需要提供同一资产的成功复测样本 ID，服务端校验资产和用例版本。平台当前记录修复与复测结果；生产策略发布仍需通过业务系统的部署流程完成。

任务详情的“与历史版本比较”可选择同一资产的基线任务。平台核对用例修订、重复次数、执行预算和任务完整性，显示逐场景改善、退化与未知结果；比较是样本计数描述，不代表统计显著性。

## 账号管理

管理员在系统管理页面创建账号、调整权限、禁用账号或重置密码。变更后撤销该账号的全部已有会话；最后一个可用管理员不能被禁用或降权，包含并发操作。所有用户都可以输入当前密码修改自己的密码，成功后需重新登录。查看者只读访问评测、报告与问题。

## 验证

```bash
pip install -e '.[dev]'
pytest
ruff check backend
```

PostgreSQL 测试连接必须指向可创建 schema 的独立测试数据库。测试会在随机 schema 中迁移、运行并清理：

```bash
AGENTSEC_TEST_POSTGRES_URL='postgresql+psycopg://test_user:test_password@127.0.0.1/agentsec_test' pytest
```

已有 LangChain4j SDK 制品的集成测试使用 `AGENTSEC_TEST_SDK_REPO=/path/to/agent-security pytest backend/tests/test_sdk.py`，测试只读已有 JAR，并在临时目录生成策略和审计文件。

浏览器端到端验收入口在 `frontend/e2e/acceptance.cjs`。先启动 API 和 Worker，使用管理员测试账号，将 `{"username":"...","password":"..."}` 保存在不提交的本地 JSON 文件中，再进入 `frontend` 执行：

```bash
npm ci
npx playwright install chromium
AGENTSEC_E2E_CREDENTIALS=../data/browser-login.json npm run e2e
```

可用 `AGENTSEC_E2E_URL` 指定服务地址，用 `AGENTSEC_E2E_CHROME` 指定现有 Chrome 可执行文件。测试会创建带时间戳的目标、任务与问题；截图和报告保存到忽略的 `test-results/`。它验证实际登录、目标创建、攻击与正常对照、Worker 完成、工具证据、报告下载、问题列表、移动布局和弹窗键盘操作。

## 生产配置

`AGENTSEC_MODE=production` 要求 PostgreSQL、显式 Fernet 主密钥及 Secure Cookie。主密钥由 `agentsec generate-key` 生成，通过受控环境配置；不要提交到仓库。API 与 Worker 使用同一个数据库与主密钥；按部署环境设置数据卷。生产外部目标必须使用 HTTPS。

部署、健康检查及备份恢复命令见 [运维说明](operations.md)。原生恢复演练和主要浏览器流程已验证；Podman Linux ARM64 镜像构建、PostgreSQL 17 全栈、内网 TLS、运行权限及备份恢复已实际验收。Docker Engine 与公网 ACME 部署未实测。Podman 部署方式见运维说明。

原始证据保留支持 `agentsec prune-evidence --days 90` 只读预览；实际清理须停服并加 `--apply --services-stopped`。未关闭问题与复测引用证据受保护，数据库报告保留。详细规则见 [运维文档](operations.md)。

HTTP Agent 的协议格式、注入面和证据范围见 [接入文档](http-agent-integration.md)。本地浏览器端到端测试会启动回环 HTTP 测试端点；API 与 Worker 须在 local 模式登记 `AGENTSEC_TARGET_HOSTS=127.0.0.1` 后启动。

判定规则、正常任务完成标准与跨版本比较限制见 [判定说明](scoring.md)。升级不会改写历史结果；比较修复效果时应使用同一判定规则重新运行。

跨样本累计 token、执行轮次和工具调用额度，以及用量缺失时的停止规则见 [预算说明](budgets.md)。整项任务默认 30 分钟截止；精确计费、协作式取消与远端请求的边界在文档中单独说明。

独立业务工具可使用 `observed-v1` 接入，配置和可信边界见 [业务工具观测](business-observer-integration.md)。参考服务把订单读取、报告 outbox 与审计绑定到同一事务；实际生产工具须在其提交边界接入，不能直接导入 Agent 自述 trace。

界面加载、真实空数据、表单错误、断网恢复与移动只读验收使用独立数据库，避免清空正在使用的平台。先在仓库根目录、已激活 Python 虚拟环境的终端启动专用服务：

```bash
python frontend/e2e/experience_server.py --data-dir test-results/experience-env --port 8089
```

该命令拒绝已有目录，并创建仅用于验收的管理员与查看者，随机凭据保存于目录内的 `login.json`（权限 0600），不输出密码。再次执行应指定新目录。另一终端进入 `frontend`：

```bash
AGENTSEC_E2E_URL=http://127.0.0.1:8089 \
AGENTSEC_E2E_CREDENTIALS=../test-results/experience-env/login.json \
AGENTSEC_E2E_CHROME='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' \
npm run e2e:experience
```

浏览器路径按实际安装调整；未安装 Playwright 时先运行 `npm ci`。测试用真实 API 验证表单与权限，用浏览器延迟／断网注入验证恢复。此服务不用 Worker，不运行外部攻击目标，完成后停止专用服务；报告与截图保存于不提交的 `test-results`。
