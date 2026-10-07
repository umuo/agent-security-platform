import json
import time

from agentsec.health import health_path, worker_healthy, write_worker_health


def test_worker_health_requires_live_process_and_recent_heartbeat(settings):
    assert not worker_healthy(settings)
    write_worker_health(settings)
    assert worker_healthy(settings)
    path = health_path(settings)
    record = json.loads(path.read_text())
    record["updated_at"] = time.time() - settings.lease_seconds - 16
    path.write_text(json.dumps(record))
    assert not worker_healthy(settings)
    record["updated_at"] = time.time()
    record["pid"] = -1
    path.write_text(json.dumps(record))
    assert not worker_healthy(settings)
