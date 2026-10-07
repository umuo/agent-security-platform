import gzip
import logging
import subprocess
import sys
from pathlib import Path

import pytest
from agentsec.inspect_runtime import BoundedTraceFormatter, ByteRotatingFileHandler
from agentsec.worker import Worker
from inspect_ai._util.trace import TraceFormatter, read_trace_file

from .conftest import create_job


def test_trace_rotation_bounds_utf8_bytes_and_oversized_records(tmp_path):
    path = tmp_path / "trace.log"
    handler = ByteRotatingFileHandler(path, maxBytes=1024, backupCount=2, encoding="utf-8")
    handler.setFormatter(BoundedTraceFormatter(TraceFormatter(), max_bytes=512))
    try:
        for index in range(60):
            record = logging.LogRecord(
                "inspect_ai", logging.WARNING, "test", 1, "%s", ("中文" * 35 + str(index),), None
            )
            handler.emit(record)
        oversized = logging.LogRecord(
            "inspect_ai", logging.WARNING, "test", 1, "secret should be omitted " * 400, (), None
        )
        oversized.payload = "large structured field" * 400
        handler.emit(oversized)
    finally:
        handler.close()
    files = list(tmp_path.glob("trace.log*"))
    assert len(files) == 3
    assert all(file.stat().st_size <= 1024 for file in files)
    assert all(file.stat().st_mode & 0o777 == 0o600 for file in files)
    content = path.read_text()
    assert "oversized internal trace record omitted" in content
    assert "secret should be omitted" not in content
    assert read_trace_file(path)


def test_two_live_inspect_processes_have_independent_trace_and_exit(tmp_path):
    code = """
import logging, sys
from pathlib import Path
from agentsec.config import Settings
from agentsec.engine import configure_inspect
from agentsec.inspect_runtime import configure_trace
import agentsec.inspect_runtime as runtime
# 两个真实进程模拟各自容器均为 PID 1，仍须拥有不同目录。
runtime.os.getpid = lambda: 1
settings = Settings(data_dir=Path(sys.argv[1]))
configure_inspect(settings)
path = configure_trace(settings.data_dir.resolve() / 'inspect')
print(path, flush=True)
logging.getLogger('inspect_ai').warning('process marker %s', sys.argv[2])
sys.stdin.readline()
"""
    workers = []
    try:
        for marker in ["one", "two"]:
            process = subprocess.Popen(
                [sys.executable, "-c", code, str(tmp_path), marker],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            workers.append(process)
        paths = [Path(process.stdout.readline().strip()) for process in workers]
        assert paths[0] != paths[1]
        assert all(path.is_file() for path in paths)
        workers[1].communicate("\n", timeout=15)
        assert workers[1].returncode == 0
        assert workers[0].poll() is None
        assert paths[0].is_file()  # 第二个进程退出没有压缩／移除第一个文件。
        zipped = paths[1].with_suffix(".log.gz")
        assert zipped.stat().st_mode & 0o777 == 0o600
        assert zipped.is_file() and "process marker two" in gzip.open(zipped, "rt").read()
        assert read_trace_file(zipped)
        workers[0].communicate("\n", timeout=15)
        assert workers[0].returncode == 0
        assert "process marker one" in gzip.open(paths[0].with_suffix(".log.gz"), "rt").read()
    finally:
        for process in workers:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


@pytest.mark.asyncio
async def test_inspect_worker_evidence_logs_survive_trace_rotation(admin, db, settings):
    job = create_job(admin, guard="none")
    worker = Worker(settings, db)
    assert await worker.run_once()
    result = admin.get("/api/evaluations/" + job["id"]).json()
    assert result["status"] == "COMPLETED"
    assert (
        next(a for a in result["attempts"] if a["case_id"] == "direct-tool")["result"]["verdict"]
        == "ATTACK_SUCCEEDED"
    )
    assert list((settings.data_dir / "inspect" / "logs").glob("*.eval"))
    traces = list((settings.data_dir.resolve() / "inspect" / "runtime").glob("*/trace.log"))
    assert len(traces) == 1
    trace = traces[0]
    assert trace.is_file()
    assert trace.stat().st_mode & 0o777 == 0o600
    assert not (settings.data_dir / "inspect" / "trace.log").exists()
