"""生成首次部署秘密；不输出内容，不覆盖已有文件。"""
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet


def create(directory):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(directory.iterdir()):
        raise SystemExit("秘密目录非空，拒绝覆盖")
    directory.chmod(0o700)
    values = {"root_db_password": secrets.token_urlsafe(32),
              "app_db_password": secrets.token_urlsafe(32), "master_key": Fernet.generate_key().decode()}
    for name, value in values.items():
        fd = os.open(directory / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(value + "\n")
        # Compose 文件秘密使用绑定挂载；宿主目录 0700 保护访问，挂载文件可供非 root 读取。
        (directory / name).chmod(0o444)


if __name__ == "__main__":
    create(Path(__file__).resolve().parent / "secrets")
    print("首次部署秘密已生成；请单独备份，内容未输出。")
