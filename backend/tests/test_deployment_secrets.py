import runpy
import stat
from pathlib import Path

import pytest
from cryptography.fernet import Fernet


def test_first_deploy_secret_permissions_and_no_overwrite(tmp_path):
    root = Path(__file__).resolve().parents[2]
    create = runpy.run_path(str(root / "deploy/create_secrets.py"))["create"]
    directory = tmp_path / "secrets"
    create(directory)
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    for file in directory.iterdir():
        assert stat.S_IMODE(file.stat().st_mode) == 0o444
    key = (directory / "master_key").read_bytes().strip()
    fernet = Fernet(key)
    assert fernet.decrypt(fernet.encrypt(b"secret-fixture")) == b"secret-fixture"
    with pytest.raises(SystemExit, match="拒绝覆盖"):
        create(directory)
