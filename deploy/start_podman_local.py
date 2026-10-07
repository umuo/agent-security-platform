"""Podman 内网部署：真实健康检查与迁移退出码控制应用启动顺序。"""

import argparse
import json
import subprocess
import time
from pathlib import Path


def start(directory, build=False):
    directory = Path(directory).resolve()
    config = json.loads((directory / "podman-local.json").read_text())
    compose = [
        "podman-compose",
        "-p",
        config["project"],
        "--env-file",
        config["env"],
        "-f",
        config["compose"],
    ]

    def run(args):
        subprocess.run(args, cwd=directory, check=True)

    def healthy(service):
        name = f"{config['project']}_{service}_1"
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            check = subprocess.run(
                ["podman", "inspect", "--format", "{{.State.Health.Status}}", name],
                capture_output=True,
                text=True,
            )
            if check.returncode == 0 and check.stdout.strip() == "healthy":
                return
            time.sleep(2)
        raise RuntimeError(f"{service} 未在 150 秒内通过容器健康检查；后续服务未启动")

    if build:
        run(["podman", "build", "-t", config["image"], str(directory.parent)])
    print("等待数据库健康", flush=True)
    run(compose + ["up", "-d", "db"])
    healthy("db")
    print("执行迁移与种子初始化", flush=True)
    run(compose + ["run", "--rm", "-T", "init"])
    print("启动 API 与 Worker，等待健康", flush=True)
    run(compose + ["up", "-d", "api", "worker"])
    healthy("api")
    healthy("worker")
    print("启动 TLS 代理", flush=True)
    run(compose + ["up", "-d", "proxy"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", action="store_true")
    args = parser.parse_args()
    start(Path(__file__).resolve().parent, args.build)
