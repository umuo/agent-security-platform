# 部署、健康检查与恢复

首次部署请先阅读 [分环境部署教程](deployment.md)：本机 SQLite 开发与生产 PostgreSQL／HTTPS 使用独立 Compose 配置。本文补充运维约束。

## 当前验证边界

SQLite 与 PostgreSQL 原生数据库路径、pg_dump/pg_restore 恢复、HTTPS Origin 校验和 Worker 心跳检查已有测试。远端 Podman 的镜像构建、全栈启动、PostgreSQL 17、内网 TLS 与容器内备份恢复已实际验证，详见下方 Podman 部署章节。Docker Engine 和公网 ACME 路径仍只有配置校验，未声称运行通过。

## 容器配置

`Dockerfile` 构建 React 前端，安装锁定 Python 依赖，包含 PostgreSQL 客户端和 Java 运行时。API 与 Worker 以 UID/GID 10001 运行。`deploy/compose.yaml` 提供 PostgreSQL 17、一次性迁移初始化、API、Worker 与 Caddy HTTPS 代理。数据库不发布宿主端口；只有代理发布 80/443。应用数据库账号不具有超级用户、创建数据库或创建角色权限。

部署机器需要 Docker Engine、支持 Compose Specification 的 Compose CLI、可解析到服务器的域名，以及可用的 80/443 端口。在仓库根目录激活已安装的 Python 环境，执行：

```bash
python deploy/create_secrets.py
```

秘密保存于忽略的 `deploy/secrets/`，目录权限 0700；文件权限 0444 允许容器中的非 root 用户读取绑定挂载。API 只接收应用数据库密码与主密钥，数据库管理员密码不挂载到 API/Worker。已有秘密不会被覆盖。将目录内容存入独立秘密管理或受控备份，不写入公开配置。

创建不提交的 `deploy/.env`：

```dotenv
AGENTSEC_DOMAIN=security.example.com
AGENTSEC_TARGET_HOSTS=model.example.com
```

运行下列命令前，将示例域名改为真实域名；主机白名单按实际模型/Agent API 配置。

```bash
docker compose --env-file deploy/.env -f deploy/compose.yaml config --quiet
docker compose --env-file deploy/.env -f deploy/compose.yaml up -d --build
docker compose --env-file deploy/.env -f deploy/compose.yaml run --rm --no-deps api create-user --username admin
docker compose --env-file deploy/.env -f deploy/compose.yaml ps
```

创建账号时交互输入密码。访问配置的 HTTPS 域名。迁移初始化先等待数据库健康，再执行迁移与用例初始化；API/Worker 只在初始化成功后启动。Caddy 根据域名配置管理 HTTPS。`AGENTSEC_PUBLIC_ORIGIN` 固定为公开 HTTPS Origin，避免代理内部 HTTP 请求被误判为跨站请求。应用不信任任意转发头。

Java SDK 适配器需要额外只读挂载已构建 SDK 制品，并配置 `AGENTSEC_SDK_REPO`。默认 Compose 不挂载本机 SDK；模型目标及 HTTP Agent 目标不依赖此配置。

升级时先备份，停止接单并处理活动任务，再构建新镜像，重新运行 init 服务迁移。数据库初始化角色脚本只在全新数据库卷第一次启动时执行；更新秘密文件不会自动修改已有数据库账号密码。密码轮换需同步数据库角色与秘密文件，并重建应用容器。主密钥需保持稳定；此版本未提供原地更换主密钥并重加密全部凭据的命令。

## 健康检查与日志

- API：`GET /health/live` 检查进程，`GET /health/ready` 检查数据库及迁移版本。
- Worker：`agentsec worker-health` 检查数据库、当前主机心跳时效和进程存在性。空闲及任务心跳均更新健康记录；健康记录不能替代某次任务的结果。
- Compose 为 API 与 Worker 配置健康检查。Worker 失联后的任务由租约恢复逻辑标记为失败/未知，不重发有副作用的请求。
- 应用容器 stdout 日志按 10 MiB×3 文件轮转。Inspect 评测日志和 SDK 审计保存在持久化 `app_data` 卷，属于评测证据。提供离线证据清理命令，默认预览；保留期由运维明确设置，建议从 90 天开始按业务要求调整。磁盘空间告警须由部署环境配置。

## 离线备份

备份与恢复期间停止 API 和 Worker。先停止接单，等待或取消 QUEUED/RUNNING 任务；备份命令拒绝存在活动任务的数据库。`--services-stopped` 明确表示操作者已完成停服操作，不会自动终止其他进程。

```bash
agentsec backup backups/snapshot-001 --services-stopped
agentsec verify-backup backups/snapshot-001
```

目标目录必须不存在且位于数据目录之外。SQLite 使用 sqlite3 backup API 生成一致快照并检查完整性；PostgreSQL 使用 custom-format pg_dump，仅备份应用当前 schema，客户端版本不得低于服务端。运行备份命令的账号需有相应读取权限。

归档包含数据库、Inspect 与 SDK 证据文件、SHA256 校验清单以及主密钥指纹。主密钥与数据库连接密码不会写入归档。数据库含加密凭据、密码哈希与业务评测数据，备份目录限制权限；离机存储应使用受控加密存储。校验和用于发现损坏，不能证明不可信归档的真实性。只恢复自身受控备份；PostgreSQL 恢复会执行归档中的数据库定义。

容器备份可在停止 proxy/api/worker 后，通过一次性 api 容器执行同样的命令，额外挂载备份目录到 `/backups`。宿主备份目录须允许 UID 10001 写入；备份时保留数据库服务运行。主密钥文件另行保存。

## 恢复演练

恢复只允许全新的 SQLite 文件或没有用户表的 PostgreSQL 数据库，以及空的证据目录。用原主密钥校验文件后执行恢复。推荐先在隔离环境演练，不覆盖现有部署。

SQLite 示例，在原项目目录执行，原本地密钥仍位于 `data/master.key`：

```bash
AGENTSEC_MASTER_KEY_FILE=./data/master.key \
AGENTSEC_DATABASE_URL=sqlite:///restore-drill/platform.db \
AGENTSEC_DATA_DIR=restore-drill \
agentsec restore backups/snapshot-001 --services-stopped
```

如原配置含非空 `AGENTSEC_MASTER_KEY`，应保留该来源并不同时设置文件来源。PostgreSQL 先创建全新目标数据库并授予应用账号恢复权限，再将 `AGENTSEC_DATABASE_URL` 和秘密文件配置指向目标，执行相同 restore 命令。保留原应用 schema 搜索路径；自定义 schema 的备份会恢复原 schema 名称。

恢复命令校验主密钥指纹及全部文件校验和，拒绝额外文件、符号链接和覆盖已有业务数据。恢复后撤销所有已有会话，并将未结束任务标记为 RESTORED_BACKUP/INCONCLUSIVE，避免旧任务被重新发送。成功后启动 API 和 Worker，重新登录，核对目标凭据可解密、历史结果及证据一致，再运行合成 fixture 评测验证新任务。

如果恢复中途失败，保持服务停止，保留失败输出，在另一全新目标重做演练；不要直接启动部分恢复的目录或数据库。

参考：[PostgreSQL pg_dump](https://www.postgresql.org/docs/current/app-pgdump.html)、[Python sqlite3 backup](https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.backup)、[Compose 启动依赖](https://docs.docker.com/compose/how-tos/startup-order/)。生产 PostgreSQL 的持续备份、WAL/PITR 与角色全局备份应由数据库运维方案覆盖，本应用离线快照不能代替这些能力。

## 原始证据保留与清理

```bash
# 在线只读预览：列出超过保留期的候选文件、总字节数。
agentsec prune-evidence --days 90

# 先停止 API 和 Worker，确认没有 QUEUED/RUNNING 任务，再执行。
agentsec prune-evidence --days 90 --apply --services-stopped
```

保留天数范围为 1～3650；年龄按 Attempt 完成时间计算，不按文件修改时间计算。执行标志是操作人员的停服确认，命令不会自动停止服务；数据库有活动任务时拒绝执行。停服也防止清理过程中问题重开或新建复测引用。

仅删除能关联到已结束任务和超过保留期 Attempt 的 Inspect `.eval` 日志与 SDK `audit.jsonl`。任何未关闭问题（包括接受风险）的原始证据均保留；历史 VERIFIED/CLOSED 操作引用的复测证据永久保留。数据库中的评测结果、事件、目标与场景快照、问题和管理审计仍保留；SDK 策略文件也保留以便复现。未知文件、符号链接和其路径下的文件不清理。

执行前后均写入管理审计（系统操作），记录操作 ID、计划路径及成功／失败路径。部分文件删除失败时命令退出码为 1；检查清单再重试。文件删除与数据库审计并非跨介质原子事务，异常停机时用 started 记录核对实际文件，再重新预览。清理不会恢复已删除文件；如需长期原始记录，应先做备份。

清理范围不包含数据库、Inspect 内部跟踪／缓存、备份归档或密钥。数据库事件和报告也可能包含测试中的敏感内容，本命令不等于全部数据删除或隐私删除请求处理。内部文件和外部备份空间须单独监控；备份归档根据独立保留策略管理。

## Inspect 内部跟踪的进程隔离

内部跟踪写入 `data/inspect/runtime/<PID>-<随机实例ID>/trace.log`，每个 Worker 独立。实例 ID 防止多个容器都使用 PID 1 时共享同一个文件；退出压缩只处理该实例当前文件。跟踪 sink 使用 UTF-8 字节计数，单文件上限 10 MiB，最多两个轮转文件。单条记录超过 64 KiB 时省略整条载荷并写入可解析的省略提示，避免单条超大记录绕过轮转限制。文件（包括新轮转文件）权限为 0600。

这只限制内部调试跟踪，不截断正式 Inspect `.eval`、SDK 审计或数据库中的样本结果。省略的跟踪内容不能作为完整取证依据；安全结论仍以正式样本结果和可信工具事件为准。

进程退出后保留其压缩文件和轮转文件；上限针对单个实例，不是整个数据卷。历史实例目录、旧版本的 `inspect/trace.log*` 与缓存继续按独立保留策略管理，`prune-evidence` 不删除这些内部文件。清理历史跟踪前停止所有 API／Worker，确认没有活动任务并按需归档，再删除明确不用的实例目录；不要仅凭 PID 或文件年龄判断某个容器内进程已退出。磁盘监控仍由部署环境提供。

日志桥接使用固定 Inspect AI 0.3.277 的内部 logger 接口；升级 Inspect 时必须运行 `test_inspect_runtime.py` 及执行回归，不能只修改依赖版本。

## Podman 内网 TLS 部署

Podman 已在 macOS ARM64 的 Linux 虚拟机上实际验证。已验证的组合为客户端 5.4.0、服务端 5.4.2 和 podman-compose 1.3.0，应用镜像为 Linux ARM64。Docker 的 `compose.yaml` 仍保留自动依赖门槛；旧 Podman 提供程序有传递依赖与 `CMD` 数组转义问题，因此使用独立配置和分阶段启动器。

在已安装项目 Python 依赖的环境生成配置（将主机名改为内网实际地址）：

```bash
python deploy/create_secrets.py
python deploy/create_podman_local.py --host security.internal --https-port 18443
python deploy/start_podman_local.py --build
```

首次秘密创建和配置生成均拒绝覆盖已有文件。若已创建秘密，保留原文件，不再次执行 create_secrets。生成的配置被 Git 和 Docker 构建上下文忽略；主机地址不写入公共模板。可选 `--sdk-repo /absolute/path/to/sdk` 只读挂载已有 Demo／Java Agent JAR，配置服务端 SDK 目录；制品目录和文件需允许 UID 10001 读取。JAR 必须是自身受控且已构建的制品。

启动器确认数据库健康后执行一次性迁移／种子初始化，只有退出码成功才启动 API 和 Worker；两项容器健康后才启动 TLS 代理。不要绕过启动器直接对生成配置执行全部服务的 up。生成的健康命令为正确引用的 CMD-SHELL，避免旧提供程序损坏 Python 命令参数。命令须能在 PATH 找到 podman 和 podman-compose；macOS SSH 非交互环境通常需要显式加入 Homebrew bin。

内网配置发布独立 HTTPS 端口，使用 Caddy 内部 CA；IP 客户端没有 SNI 时使用配置的默认 ServerName。内部 CA 根证书可用 podman cp 从代理的 `/data/caddy/pki/authorities/local/root.crt` 取出，以 `curl --cacert` 或客户端指定受信 CA 验证。浏览器使用需按自己的信任策略导入该公开根证书；脚本不会自动更改系统信任库。本配置不声称公网 ACME 域名证书已经验证，公网部署继续按前述域名／80、443 条件执行。

Podman 配置使用 k8s-file，日志上限 10 MiB；不传不支持的 max-file 选项，保留语义不同于 Docker 的 10 MiB×3。实际独立探测容器产生 6 MiB 内容，在 1 MiB 上限下仅保留约 825 KiB 内容，验证该后端大小限制。正式 Inspect／SDK 证据与报告由数据卷／数据库保留，不依赖容器 stdout 的历史完整性。

远端实测已完成证书链／IP 校验、生产登录与 Secure Cookie、三策略工具与正常对照、桌面／移动复测比较、非 root 与能力约束，以及 PostgreSQL 17 原生备份、独立恢复库／卷、会话撤销、凭据解密和 .eval 文件恢复。具体运行证据见 verification.md。
