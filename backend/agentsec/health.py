import hashlib
import json
import os
import socket
import tempfile
import time


def health_path(settings):
    host = hashlib.sha256(socket.gethostname().encode()).hexdigest()[:20]
    return settings.data_dir / "worker-health" / (host + ".json")


def write_worker_health(settings):
    path = health_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="heartbeat-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump({"pid": os.getpid(), "updated_at": time.time()}, stream)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def worker_healthy(settings):
    try:
        path = health_path(settings)
        if path.stat().st_size > 4096:
            return False
        record = json.loads(path.read_text())
        if not 0 <= time.time() - record["updated_at"] <= settings.lease_seconds + 15:
            return False
        if not isinstance(record["pid"], int) or record["pid"] <= 0:
            return False
        os.kill(record["pid"], 0)
        return True
    except (OSError, ValueError, KeyError, TypeError):
        return False
