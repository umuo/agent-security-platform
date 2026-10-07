"""固定 Inspect 版本的进程内日志桥接；评测 .eval 文件不经此轮转。"""

import atexit
import json
import logging
import os
import uuid
from logging.handlers import RotatingFileHandler
from pathlib import Path

TRACE_BYTES = 10 * 1024 * 1024
TRACE_BACKUPS = 2
TRACE_RECORD_BYTES = 64 * 1024
_INSTANCE_ID = uuid.uuid4().hex


class BoundedTraceFormatter(logging.Formatter):
    def __init__(self, delegate, max_bytes=TRACE_RECORD_BYTES):
        super().__init__()
        self.delegate, self.max_bytes = delegate, max_bytes

    def format(self, record):
        value = self.delegate.format(record)
        if len((value + "\n").encode("utf-8")) <= self.max_bytes:
            return value
        # 保持可解析的 JSON，避免超大消息或 structured extra 绕过单文件上限。
        return json.dumps(
            {
                "timestamp": self.formatTime(record),
                "level": record.levelname,
                "message": "[agentsec] oversized internal trace record omitted",
            }
        )


class ByteRotatingFileHandler(RotatingFileHandler):
    def _open(self):
        stream = super()._open()
        os.chmod(self.baseFilename, 0o600)
        return stream

    def shouldRollover(self, record):
        if self.stream is None:
            self.stream = self._open()
        size = len((self.format(record) + self.terminator).encode(self.encoding or "utf-8"))
        self.stream.seek(0, os.SEEK_END)
        return self.stream.tell() + size > self.maxBytes


def configure_trace(root: Path):
    # 加随机实例身份，容器 PID namespace 中多个 Worker 都可能是 PID 1。
    # 每个活进程独占一个目录；退出压缩不碰其他 Worker 的文件。
    directory = root / "runtime" / f"{os.getpid()}-{_INSTANCE_ID}"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / "trace.log"
    os.environ["INSPECT_TRACE_FILE"] = str(path)

    # Inspect 0.3.277 使用全局 logger；这里只替换内部 trace sink，保留其
    # 原生过滤、逐样本 transcript 和评分日志，版本升级时须回归此桥接。
    from inspect_ai._util.logger import _logHandler, init_logger
    from inspect_ai._util.trace import TraceFormatter, compress_trace_log

    init_logger(None)
    logger = _logHandler["handler"]
    old = logger.trace_logger
    if isinstance(old, ByteRotatingFileHandler) and Path(old.baseFilename) == path:
        return path
    old.close()
    handler = ByteRotatingFileHandler(
        path, maxBytes=TRACE_BYTES, backupCount=TRACE_BACKUPS, encoding="utf-8"
    )
    handler.setFormatter(BoundedTraceFormatter(TraceFormatter()))
    path.chmod(0o600)
    logger.trace_logger = handler
    # 原生 init_logger 已注册旧 sink 的压缩回调；新回调先关闭并压缩当前
    # sink，旧回调发现原文件不存在会跳过，不重复压缩或误删轮转文件。
    compress = compress_trace_log(handler)

    def compress_private_trace():
        compress()
        archive = path.with_suffix(".log.gz")
        if archive.is_file():
            archive.chmod(0o600)

    atexit.register(compress_private_trace)
    return path
