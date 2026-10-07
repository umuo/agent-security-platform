# 部署教程：本地开发与生产分开

[返回 README](../README.md) · [使用指南](user-guide.md) · [详细运维](operations.md) · [Compose 文件说明](../deploy/README.md)

所有命令从仓库根目录执行；示例域名与 SDK 路径须改为你的部署参数。环境已经部署时保留其原项目名、秘密和数据卷，不照抄首次初始化步骤。

## 1. 选环境

| 环境 | 用途 | 数据库／入口 | 配置 |
| --- | --- | --- | --- |
| 本机源码开发 | 改代码、前端热更新、调试与测试 | SQLite、回环 HTTP | 根目录 .env；见 development.md |
| 本机 Docker | 在容器内体验完整平台或检查构建产物 | SQLite、127.0.0.1:8088 | compose.local.yaml、deploy/.env.local |
| Docker 生产 | 部署给团队使用 | PostgreSQL 17、Caddy HTTPS | compose.yaml、deploy/.env、秘密文件 |
| Podman 内网生产模式 | 已有 Podman、内部网络使用 | PostgreSQL 17、内部 CA HTTPS | 生成的独立配置及分阶段启动器 |

本地 Compose 提供构建后界面，不带源码挂载或热更新。修改代码后重新构建；频繁开发用源码方式。Podman 内网使用 production 配置约束，仍需备份、磁盘监控与客户端信任内部 CA。

两套 Docker 示例分别用 `agentsec-dev` 与 `agentsec-prod` 项目名，卷和网络隔离。根目录 `.env` 用于源码进程；`deploy/.env*` 用于 Compose 参数，不要互相复制替代。模型凭据在平台目标中录入；数据库密码与主密钥由秘密文件提供。

## 2. 本机源码开发

需要 Python 3.12+ 与 Node.js 22.12+。按 [开发说明](development.md) 的安装命令完成前端构建、迁移、用例初始化与账号创建，再在独立终端启动 API 和 Worker：

```bash
source .venv/bin/activate
agentsec serve
```

```bash
source .venv/bin/activate
agentsec worker
```

访问 `http://127.0.0.1:8088`。改前端时可在第三个终端运行：

```bash
cd frontend
npm run dev
```

访问终端显示的 Vite 地址，`/api` 和 `/health` 由 Vite 代理给本机 8088。不要同时启动本地 Compose 占用同一 API 端口。每个后端终端都要激活同一虚拟环境；修改 Python 代码后重启对应进程。

## 3. 本机 Docker：SQLite + HTTP

需要运行中的 Docker Engine 和支持 Compose Specification 的 `docker compose`。不需要在宿主安装 Python、Node 或数据库。

```bash
docker version
docker compose version
cp deploy/.env.local.example deploy/.env.local
```

复制只用于首次配置，已有文件时直接编辑。定义本地命令简写（Bash／Zsh，在仓库根目录）：

```bash
devc() {
  docker compose -p agentsec-dev --env-file deploy/.env.local     -f deploy/compose.local.yaml "$@"
}
devc config --quiet
devc up -d --build
devc ps -a
```

`init` 应退出 0，API 和 Worker 应达到 healthy。创建账号，交互输入至少 12 字符密码：

```bash
devc run --rm --no-deps api create-user --username admin
curl --fail http://127.0.0.1:8088/health/ready
```

访问 `http://127.0.0.1:8088`，按使用指南跑 fixture。SQLite、自动主密钥和证据保存在 `agentsec-dev_dev_data` 卷，容器重建不清空它。

日常命令：

```bash
devc logs --tail 100 api worker
devc exec worker agentsec worker-health
devc stop
devc up -d
devc down
```

`down` 保留卷；`down -v` 会删除本地数据及自动主密钥，仅在明确要清空此开发环境时使用。该配置只绑定回环 HTTP，适用于本机开发验收。

## 4. Docker 生产：PostgreSQL + HTTPS

### 4.1 部署前准备

准备 Docker Engine／Compose、Python 3（用于首次秘密生成）、能拉取镜像和依赖的网络、服务器域名。域名 DNS 指向服务器，并提供可达的 80／443 端口供 Caddy 管理公网证书；已有代理占用端口时需要先设计代理和端口方案。没有公网域名的内网环境使用第 6 节。

数据库不发布宿主端口。API／Worker 使用 UID/GID 10001、移除能力并启用 no-new-privileges。PostgreSQL 数据、应用证据和 Caddy 证书分别位于持久卷。依赖健康及一次性初始化退出码控制启动顺序，参考 [Compose 官方说明](https://docs.docker.com/compose/how-tos/startup-order/)；公网 HTTPS 条件参考 [Caddy 官方说明](https://caddyserver.com/docs/automatic-https)。

### 4.2 配置与秘密

首次部署在宿主安装秘密生成脚本所需的锁定依赖；不需要安装整个平台：

```bash
python3 -m venv .venv-deploy
.venv-deploy/bin/pip install cryptography==50.0.2
.venv-deploy/bin/python deploy/create_secrets.py
cp deploy/.env.example deploy/.env
```

已有秘密时跳过生成。脚本拒绝覆盖，目录 0700、文件 0444，便于容器非 root 用户读取绑定挂载；宿主目录访问仍受限制。单独安全保存秘密目录，尤其主密钥。主密钥丢失会使已存目标凭据无法解密。

编辑 `deploy/.env`：

```dotenv
AGENTSEC_DOMAIN=security.example.com
AGENTSEC_TARGET_HOSTS=model.example.com,agent.example.com
AGENTSEC_SDK_HOST_REPO=
```

| 参数 | 含义 | 空值／格式 |
| --- | --- | --- |
| AGENTSEC_DOMAIN | 实际 HTTPS 域名，生成公开 Origin 和 Caddy 站点 | 生产基础配置必填；这里填域名，不带 https:// 或路径 |
| AGENTSEC_TARGET_HOSTS | 允许评测连接的模型／Agent／观测端主机 | 逗号分隔，不含路径、协议或端口；空值可跑 fixture／SDK |
| AGENTSEC_SDK_HOST_REPO | 可选 SDK 宿主目录 | 仅 SDK 叠加时必填，绝对路径 |

数据库连接、production 模式、Secure Cookie、秘密文件路径和数据目录在基础 Compose 中统一设置。无需在此文件填写数据库密码或主密钥。

### 4.3 启动和账号

```bash
prodc() {
  docker compose -p agentsec-prod --env-file deploy/.env     -f deploy/compose.yaml "$@"
}
prodc config --quiet
prodc up -d --build
prodc ps -a
```

期望：db healthy；init Exited (0)；API／Worker healthy；proxy running。启动失败先看 `prodc logs --tail 100 db init api worker proxy`，修好后重启，不跳过失败的迁移。

```bash
prodc run --rm --no-deps api create-user --username admin
curl --fail https://security.example.com/health/live
curl --fail https://security.example.com/health/ready
prodc exec worker agentsec worker-health
```

将 curl 域名改为实际值。账号密码由终端交互输入，不在 Compose 或命令行参数中填写。浏览器访问实际 HTTPS 域名，首次登录后在“系统管理”修改密码；先跑 fixture，再登记真实目标。

### 4.4 可选：挂载 LangChain4j SDK

宿主制品目录必须存在，且 UID 10001 可读目录与文件，包含：

```text
SDK_ROOT/
  demo/target/agent-security-demo.jar
  agent-security-javaagent/target/agent-security-javaagent.jar
```

在 `deploy/.env` 配置 `AGENTSEC_SDK_HOST_REPO=/absolute/path/to/sdk`，将 prodc 改为：

```bash
prodc() {
  docker compose -p agentsec-prod --env-file deploy/.env     -f deploy/compose.yaml -f deploy/compose.sdk.yaml "$@"
}
prodc config --quiet
prodc up -d --build
prodc exec worker test -r /opt/agentsec-sdk/demo/target/agent-security-demo.jar
prodc exec worker test -r /opt/agentsec-sdk/agent-security-javaagent/target/agent-security-javaagent.jar
```

叠加配置保留数据库、秘密和应用卷，为 init／API／Worker 增加一致的只读挂载。所有后续 prodc 命令都使用相同文件组合。合并规则见 [Compose 官方文档](https://docs.docker.com/compose/how-tos/multiple-compose-files/merge/)。

本地 Docker 可按同样方式给 devc 增加第二个 `-f deploy/compose.sdk.yaml`，SDK 路径填在 `deploy/.env.local`。挂载路径是 Docker 宿主路径；容器内 localhost 指容器自身，外部模型和业务服务须使用容器可达地址及相应白名单。

## 5. 生产维护、备份与升级

本节沿用已定义的 prodc；启用 SDK 后保留叠加文件。迁移和应用命令通过一次性容器运行，宿主不需要完整 Python 环境。

### 5.1 停服备份

先停止新建任务，在页面等待或取消所有等待／运行任务，并确认数据库无活动任务。再停止入口与执行服务，保持 db 运行：

```bash
prodc exec -T db psql -U postgres -d agentsec -At   -c "SELECT count(*) FROM evaluations WHERE status IN ('QUEUED','RUNNING')"
prodc stop proxy api worker
```

查询应为 0。备份 CLI 也拒绝存在活动任务；`--services-stopped` 是停服声明，不会替你停止进程。

使用独立备份卷，初始化写权限并创建新的快照目录：

```bash
docker volume create agentsec-prod-backups
prodc run --rm --no-deps -T --user 0 --entrypoint sh   -v agentsec-prod-backups:/backups api   -c 'chown 10001:10001 /backups && chmod 700 /backups'
prodc run --rm --no-deps -T -v agentsec-prod-backups:/backups   api backup /backups/snapshot-001 --services-stopped
prodc run --rm --no-deps -T -v agentsec-prod-backups:/backups:ro   api verify-backup /backups/snapshot-001
```

后续每次备份换新快照目录名。只有一次性权限初始化以 root 运行；备份和校验以应用用户执行。归档含数据库、证据、校验和及密钥指纹，不包含主密钥值。备份卷仍在同一宿主，需另行复制到受控离机存储，秘密单独安全备份。

备份结束且不升级时恢复服务：

```bash
prodc up -d api worker proxy
```

### 5.2 在独立数据库／卷演练恢复

保持 API／Worker 停止。使用原部署主密钥，新建独立空库和证据卷：

```bash
prodc exec -T db psql -U postgres -d agentsec -v ON_ERROR_STOP=1   -c 'CREATE DATABASE agentsec_restore_drill OWNER agentsec'
docker volume create agentsec-prod-restore-drill
prodc run --rm --no-deps -T --user 0 --entrypoint sh   -v agentsec-prod-restore-drill:/restore-data api   -c 'chown 10001:10001 /restore-data && chmod 700 /restore-data'
prodc run --rm --no-deps -T   -v agentsec-prod-backups:/backups:ro   -v agentsec-prod-restore-drill:/restore-data   -e AGENTSEC_DATA_DIR=/restore-data   -e AGENTSEC_DATABASE_URL=postgresql+psycopg://agentsec@db/agentsec_restore_drill   api restore /backups/snapshot-001 --services-stopped
prodc exec -T db psql -U postgres -d agentsec_restore_drill   -c 'SELECT count(*) FROM evaluations; SELECT count(*) FROM sessions;'
```

确认恢复报告计数与备份时一致、会话数为 0，再检查证据文件及测试凭据解密。上述命令只恢复演练库／卷，不自动切换业务服务。重复演练须使用新的空库／空卷，恢复器拒绝覆盖。实际灾后切换需将服务数据库和数据卷同时指向恢复结果，并保留原主密钥；详见 [恢复约束](operations.md)。

演练结束启动原服务并跑一轮 fixture。失败时保留失败输出，不启动部分恢复的数据。

### 5.3 升级

完成备份后，保持应用停服，更新已审核代码并构建；显式重新执行迁移与种子初始化：

```bash
prodc build
prodc run --rm --no-deps -T init
prodc up -d --force-recreate api worker proxy
prodc ps -a
```

每条命令成功后才执行下一条。迁移失败保持停服。重新检查 HTTPS、Worker、历史报告与一次 fixture。镜像回退不等于数据库迁移回退；保留旧版本源码／镜像与备份，按兼容性决定恢复路线。更新秘密文件不会自动更新已有数据库角色密码，也不能随意更换主密钥。

### 5.4 日常命令

```bash
prodc logs --tail 100 api worker proxy
prodc exec worker agentsec worker-health
prodc stop
prodc up -d
```

生产 `stop` 保留容器与卷；`down` 移除容器／网络但保留卷。不要对生产执行 `down -v`。API／Worker stdout 配置 10 MiB × 3；正式评测证据、数据库与备份独立保留，需额外监控磁盘并配置保留策略。

## 6. Podman 内网生产模式

这是已实际验收的部署路线。不要将本地 SQLite Compose 直接用于团队生产，也不要对 podman-compose 1.3 绕过分阶段启动器。

首次在部署主机准备 Python 3 虚拟环境与配置工具依赖：

```bash
python3 -m venv .venv-deploy
.venv-deploy/bin/pip install cryptography==50.0.2 PyYAML==6.0.3
.venv-deploy/bin/python deploy/create_secrets.py
.venv-deploy/bin/python deploy/create_podman_local.py   --host security.internal --https-port 18443 --project agentsec-internal
.venv-deploy/bin/python deploy/start_podman_local.py --build
```

host 改为客户端可访问的主机名或 IPv4。可在生成时加入 `--sdk-repo /absolute/path/to/sdk`。生成器拒绝覆盖已有文件；已有部署保留原配置、秘密与项目名，直接使用启动器。Podman VM 需能访问制品目录；macOS 非交互 SSH 通常要将 Homebrew bin 加入 PATH。

生成后在 deploy 目录定义同一项目的命令简写：

```bash
cd deploy
pc() {
  podman-compose -p agentsec-internal --env-file .env.podman-local     -f compose.podman-local.yaml "$@"
}
pc ps
pc run --rm api create-user --username admin
podman cp agentsec-internal_proxy_1:/data/caddy/pki/authorities/local/root.crt ../root.crt
cd ..
curl --fail --cacert root.crt https://security.internal:18443/health/ready
```

已有配置的实际项目名记录在 `deploy/podman-local.json`；不要为现有部署改用示例名称。浏览器按自己的信任策略导入公开根证书，不复制 CA 私钥。停止可用 `pc stop`；重新启动回仓库根目录运行 `python deploy/start_podman_local.py`，不要绕过健康／迁移门槛。

Podman k8s-file 日志使用 10 MiB 大小限制，没有 Docker 的三文件保留语义。备份／恢复原则同第 5 节，但提供程序参数与卷所有权处理不同：已验收 Podman 使用 `:U` 初始化备份与恢复卷权限，详细范围见 [运维说明](operations.md) 与 [验证记录](verification.md)。

## 7. 故障定位与验证范围

| 现象 | 检查 |
| --- | --- |
| 本地 8088 端口冲突 | 停掉源码 API 或另一套本地容器，再启动选定环境 |
| init 非零退出 | 看迁移日志、数据库角色与秘密读取；不要启动失败的应用 |
| API ready 失败 | 数据库连接与迁移版本；live 正常并不代表 ready 正常 |
| 任务一直等待 | Worker 容器健康、数据库／主密钥一致性 |
| 登录写入 403 | 浏览器地址是否与公开 Origin 一致，HTTPS 和 Cookie 配置是否匹配 |
| 模型／Agent 无法连接 | 目标白名单、HTTPS、容器 DNS、证书和凭据；localhost 指容器自身 |
| SDK 无法读取 | SDK 宿主目录、JAR 路径、只读挂载和 UID 10001 读取权限 |
| 公网证书失败 | 域名 DNS、80／443 可达、代理占用；看 Caddy 日志 |

已有实际运行证据覆盖 Podman Linux ARM64／PostgreSQL 17.11／内网 TLS／SDK／备份恢复。Docker 生产基础、本地 Compose 和 SDK 叠加配置会进行 Compose 解析与合并核对；当前没有 Docker Engine 运行证据，公网 ACME 也未实测。二者的文档步骤不能替代对应主机上的实际启动验收。
