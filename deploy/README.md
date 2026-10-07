# Compose 配置入口

完整步骤见 [部署教程](../docs/deployment.md)，按环境选择：

| 文件 | 环境 | 数据／入口 |
| --- | --- | --- |
| compose.local.yaml | 本机容器开发／验收 | SQLite，回环 HTTP，agentsec-dev 独立卷 |
| compose.yaml | Docker 生产 | PostgreSQL 17，Caddy HTTPS，agentsec-prod 独立卷 |
| compose.sdk.yaml | 可选 SDK 叠加配置 | 三个应用服务只读挂载已有 JAR |
| .env.local.example | 本地参数模板 | 无秘密 |
| .env.example | 生产参数模板 | 域名、目标白名单、可选 SDK 路径 |
| create_podman_local.py | Podman 内网生产模式 | 生成独立配置，使用内部 CA |
| start_podman_local.py | Podman 启动器 | 按数据库健康、迁移退出码、应用健康启动 |

Compose 使用当前 `docker compose` 命令，基础文件是 `compose.yaml`；无需再维护一份重复的 docker-compose.yml。SDK 叠加文件使用时始终放在基础文件之后。

本地快速启动（仓库根目录）：

```bash
cp deploy/.env.local.example deploy/.env.local
docker compose -p agentsec-dev --env-file deploy/.env.local -f deploy/compose.local.yaml config --quiet
docker compose -p agentsec-dev --env-file deploy/.env.local -f deploy/compose.local.yaml up -d --build
docker compose -p agentsec-dev --env-file deploy/.env.local -f deploy/compose.local.yaml run --rm --no-deps api create-user --username admin
```

生产需要域名、TLS 和首次秘密初始化，按教程执行。已经有部署时保留原项目名、秘密和卷，避免更换项目名后连接到另一组空卷。
