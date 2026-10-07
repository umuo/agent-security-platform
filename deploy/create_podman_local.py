"""生成独立的 Podman 内网 TLS 部署配置，不改写 Docker 生产配置。"""

import argparse
import copy
import json
import os
import re
import shlex
from pathlib import Path

import yaml


def create(directory, host, port, project, image, sdk_repo=None):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host):
        raise ValueError("host 必须为 IPv4 地址或 DNS 主机名")
    if not 1024 <= port <= 65535 or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", project):
        raise ValueError("端口须为 1024～65535，项目名须为小写字母、数字与连字符")
    directory = Path(directory)
    files = [
        directory / name
        for name in [
            "compose.podman-local.yaml",
            "Caddyfile.podman-local",
            ".env.podman-local",
            "podman-local.json",
        ]
    ]
    if any(path.exists() for path in files):
        raise ValueError("Podman 本地部署配置已存在，拒绝覆盖")
    data = copy.deepcopy(yaml.safe_load((directory / "compose.yaml").read_text()))
    for service in data["services"].values():
        # 旧提供程序的 --requires 会为已完成 init 构建错误的传递依赖图。
        # start_podman_local.py 用实际健康及迁移退出码实现启动门槛。
        service.pop("depends_on", None)
        test = service.get("healthcheck", {}).get("test", [])
        if test and test[0] == "CMD":
            service["healthcheck"]["test"] = ["CMD-SHELL", shlex.join(test[1:])]
    for name in ["init", "api", "worker"]:
        data["services"][name]["logging"] = {"driver": "k8s-file", "options": {"max-size": "10m"}}
        data["services"][name]["image"] = image
    if sdk_repo:
        sdk_path = Path(sdk_repo).resolve()
        data["x-app"]["environment"]["AGENTSEC_SDK_REPO"] = "/opt/agentsec-sdk"
        data["x-app"]["volumes"].append(
            {
                "type": "bind",
                "source": str(sdk_path),
                "target": "/opt/agentsec-sdk",
                "read_only": True,
            }
        )
    for name in ["db", "proxy"]:
        data["services"][name]["image"] = "docker.io/library/" + data["services"][name]["image"]
    proxy = data["services"]["proxy"]
    proxy["ports"] = [f"{port}:443"]
    proxy["volumes"][0] = "./Caddyfile.podman-local:/etc/caddy/Caddyfile:ro"
    os.umask(0o077)
    files[0].write_text(yaml.safe_dump(data, sort_keys=False))
    files[1].write_text(
        f"{{\n    default_sni {host}\n}}\nhttps://{host} {{\n    tls internal\n    encode zstd gzip\n    reverse_proxy api:8088\n}}\n"
    )
    files[2].write_text(f"AGENTSEC_DOMAIN={host}:{port}\nAGENTSEC_TARGET_HOSTS=\n")
    files[3].write_text(
        json.dumps(
            {"project": project, "image": image, "compose": files[0].name, "env": files[2].name},
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--https-port", type=int, default=18443)
    parser.add_argument("--project", default="agentsec-local")
    parser.add_argument("--image", default="localhost/agent-security-platform:local")
    parser.add_argument("--sdk-repo", type=Path, help="可选：已构建的 SDK 制品目录，只读挂载")
    args = parser.parse_args()
    create(
        Path(__file__).resolve().parent,
        args.host,
        args.https_port,
        args.project,
        args.image,
        args.sdk_repo,
    )
    print("Podman 内网 TLS 配置已生成；使用 start_podman_local.py 分阶段启动。")
