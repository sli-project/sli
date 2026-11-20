from __future__ import annotations

import json
import logging
import os
import contextlib
import threading
import time
import traceback
import uuid
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from server.sli.core.paths import DATA_DIR
from server.sli.ops.diagnostics import make_internal_error_id, make_structured_log_payload


LOG_DIR = DATA_DIR / "logs"
LOG_PATH = LOG_DIR / "adlog-monitor.log"
INTERNAL_ERROR_LOG_PATH = LOG_DIR / "internal-errors.log"
PERFORMANCE_LOG_PATH = LOG_DIR / "performance-events.log"
AUDIT_ACTIONS_LOG_PATH = LOG_DIR / "audit-actions.log"
_LOGGER_NAME = "adlog_monitor"
_CONFIGURED = False
_INTERNAL_LOCK = threading.Lock()
DEFAULT_LOG_MAX_BYTES = 10_000_000
DEFAULT_LOG_BACKUP_COUNT = 5

_RESERVED_LOG_RECORD_ATTRS = {
    "args", "asctime", "created", "exc_info", "exc_text", "filename", "funcName",
    "levelname", "levelno", "lineno", "module", "msecs", "message", "msg", "name",
    "pathname", "process", "processName", "relativeCreated", "stack_info", "thread",
    "threadName", "taskName",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_default(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    return str(value)


@contextlib.contextmanager
def _process_file_lock(path: Path, *, timeout_seconds: float = 2.0):
    """Serialize a short append/rollover section across local processes."""
    lock_path = path.with_name(path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+b")
    acquired = False
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            deadline = time.monotonic() + max(0.1, timeout_seconds)
            while not acquired:
                try:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    acquired = True
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"timed out acquiring log lock for {path.name}")
                    time.sleep(0.01)
        else:
            acquired = True
        yield
    finally:
        if acquired and os.name == "nt":
            import msvcrt

            try:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
        handle.close()


def _rotate_closed_log(path: Path, backup_count: int) -> None:
    for number in range(max(1, backup_count) - 1, 0, -1):
        source = path.with_name(f"{path.name}.{number}")
        target = path.with_name(f"{path.name}.{number + 1}")
        if source.exists():
            os.replace(source, target)
    first = path.with_name(f"{path.name}.1")
    if first.exists():
        first.unlink()
    if path.exists():
        os.replace(path, first)


def append_jsonl_bounded(
    path: Path,
    payload: dict[str, Any],
    *,
    max_bytes: int = DEFAULT_LOG_MAX_BYTES,
    backup_count: int = DEFAULT_LOG_BACKUP_COUNT,
) -> bool:
    """Append JSONL with closed-file rotation safe for multiple Windows workers."""
    try:
        encoded = json.dumps(payload, ensure_ascii=False, default=_json_default) + "\n"
        path.parent.mkdir(parents=True, exist_ok=True)
        with _INTERNAL_LOCK, _process_file_lock(path):
            current_size = path.stat().st_size if path.exists() else 0
            if current_size and current_size + len(encoded.encode("utf-8")) > max(1, max_bytes):
                _rotate_closed_log(path, backup_count)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(encoded)
        return True
    except Exception:
        return False


def _best_effort_append_jsonl(path: Path, payload: dict[str, Any]) -> bool:
    """Append one diagnostic record without allowing logging I/O to escape."""
    return append_jsonl_bounded(path, payload)




class WindowsSafeRotatingFileHandler(RotatingFileHandler):
    """Rotating handler that does not flood stderr when Windows locks a log file.

    The standard RotatingFileHandler uses os.rename() during rollover. On
    Windows this fails with WinError 32 when another process still has the log
    opened. In our product multiple local processes can briefly coexist during
    collector subprocesses, diagnostics or server restart. A logging failure
    must never break or spam the collector loop, so rollover failures are
    degraded to a compact internal warning and normal appending continues.
    """

    def __init__(self, *args: Any, rollover_error_log_path: Path | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.rollover_error_log_path = rollover_error_log_path
        self._rollover_suppressed_until = 0.0
        self._last_rollover_warning = 0.0
        self._rollover_failures = 0

    def shouldRollover(self, record: logging.LogRecord) -> bool:  # noqa: N802 - stdlib API name
        if time.time() < self._rollover_suppressed_until:
            return False
        return super().shouldRollover(record)

    def doRollover(self) -> None:  # noqa: N802 - stdlib API name
        try:
            super().doRollover()
            self._rollover_suppressed_until = 0.0
            self._rollover_failures = 0
        except PermissionError as exc:
            # Do not call logging.handleError(): it prints a large "Logging error"
            # traceback to the server console for every event. Keep appending and
            # retry rollover after a cooldown.
            self._rollover_failures += 1
            self._rollover_suppressed_until = time.time() + 60.0
            if self.stream is None:
                self.stream = self._open()
            self._write_rollover_warning(exc)

    def _write_rollover_warning(self, exc: BaseException) -> None:
        now = time.time()
        if now - self._last_rollover_warning < 60.0:
            return
        self._last_rollover_warning = now
        if self.rollover_error_log_path is None:
            return
        payload = {
            "ts": utc_now(),
            "level": "WARNING",
            "component": "logging",
            "event": "log_rotation_skipped",
            "message": "Log rotation skipped because log file is locked; continuing to append.",
            "pid": os.getpid(),
            "thread": threading.current_thread().name,
            "path": str(self.baseFilename),
            "internal_error_id": make_internal_error_id(),
            "error_type": type(exc).__name__,
            "error": str(exc),
            "failures": self._rollover_failures,
            "retry_after_seconds": 60,
        }
        try:
            Path(self.rollover_error_log_path).parent.mkdir(parents=True, exist_ok=True)
            with _INTERNAL_LOCK:
                with Path(self.rollover_error_log_path).open("a", encoding="utf-8") as f:
                    f.write(json.dumps(payload, ensure_ascii=False, default=_json_default) + "\n")
        except Exception:
            # Logging must stay non-fatal even if the diagnostic side-channel is
            # unavailable.
            return


class JsonLineFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = make_structured_log_payload(
            component=getattr(record, "component", record.name),
            event=getattr(record, "event", record.getMessage()),
            message=record.getMessage(),
            level=record.levelname,
        )
        # Preserve the original LogRecord thread name for exact logger context.
        payload["thread"] = record.threadName
        for key, value in record.__dict__.items():
            if key in _RESERVED_LOG_RECORD_ATTRS or key in payload:
                continue
            if value in (None, ""):
                continue
            payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=_json_default)


def configure_logging() -> logging.Logger:
    global _CONFIGURED
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if _CONFIGURED:
        return logger

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    # P-Core: both log files must exist after startup, even when there are no
    # internal errors yet. This makes diagnostics deterministic for operators.
    LOG_PATH.touch(exist_ok=True)
    internal_error_path = _internal_error_log_path()
    internal_error_path.parent.mkdir(parents=True, exist_ok=True)
    internal_error_path.touch(exist_ok=True)
    PERFORMANCE_LOG_PATH.touch(exist_ok=True)
    AUDIT_ACTIONS_LOG_PATH.touch(exist_ok=True)
    # Product logging uses append_jsonl_bounded(), which opens the file only
    # for one serialized append.  Keeping a RotatingFileHandler open in every
    # worker prevents rename-based rollover on Windows.
    logger.addHandler(logging.NullHandler())
    _CONFIGURED = True
    return logger


def get_logger(component: str) -> logging.Logger:
    return configure_logging()



def log_audit_action(action: str, status: str, **fields: Any) -> None:
    """Append an operator/destructive-action audit line.

    This is intentionally local-only and never touches AD/DC. It mirrors the
    toolkit audit log format so UI actions, manual collection requests and
    cleanup actions have one chronological evidence trail.
    """
    payload: dict[str, Any] = {
        "ts": utc_now(),
        "level": "INFO",
        "component": "audit",
        "event": "operator_action",
        "action": action,
        "status": status,
        "pid": os.getpid(),
        "thread": threading.current_thread().name,
    }
    payload.update({key: value for key, value in fields.items() if value not in (None, "")})
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    append_jsonl_bounded(AUDIT_ACTIONS_LOG_PATH, payload)


def log_event(component: str, event: str, message: str, *, level: int = logging.INFO, **fields: Any) -> None:
    try:
        payload = make_structured_log_payload(
            component=component,
            event=event,
            message=message,
            level=logging.getLevelName(level),
        )
        payload.update(
            {key: value for key, value in fields.items() if value not in (None, "")}
        )
        append_jsonl_bounded(LOG_PATH, payload)
    except Exception:
        # Logging is evidence, not part of the product transaction. In
        # particular, a locked/unwritable log must not replace the exception
        # that the caller is trying to report.
        return


def _internal_error_log_path() -> Path:
    directory = os.environ.get("ADLOG_LOG_DIR")
    return Path(directory) / "internal-errors.log" if directory else INTERNAL_ERROR_LOG_PATH


def log_internal_error(
    component: str,
    event: str,
    message: str,
    *,
    exc: BaseException | None = None,
    level: int = logging.ERROR,
    **fields: Any,
) -> str:
    """Write a structured internal diagnostic error and return its stable error id.

    The normal monitor log is optimized for the chronological event stream. This
    JSONL file is optimized for fast root-cause triage: one line per internal
    exception/failure with enough context to reproduce the failing stage.
    """
    error_id = make_internal_error_id()
    payload: dict[str, Any] = {
        "ts": utc_now(),
        "level": logging.getLevelName(level),
        "component": component,
        "event": event,
        "message": message,
        "internal_error_id": error_id,
        "pid": os.getpid(),
        "thread": threading.current_thread().name,
    }
    payload.update({key: value for key, value in fields.items() if value not in (None, "")})
    if exc is not None:
        payload["error_type"] = type(exc).__name__
        payload["error"] = str(exc)
        payload["traceback"] = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))

    _best_effort_append_jsonl(_internal_error_log_path(), payload)

    log_event(
        component,
        event,
        message,
        level=level,
        internal_error_id=error_id,
        error_type=payload.get("error_type"),
        error=payload.get("error"),
        **fields,
    )
    return error_id


def log_exception(*args: Any, component: str = "internal", event: str = "exception",
                  message: str | None = None, level: int = logging.ERROR, **fields: Any) -> str:
    """Backward-compatible exception logger kept for diagnostics/tests.

    Supports both the old positional form
    ``log_exception(component, event, message, exc, **fields)`` and the newer
    keyword form ``log_exception(exc, component=..., event=...)``.
    """
    if args and isinstance(args[0], BaseException):
        exc = args[0]
    elif len(args) >= 4 and isinstance(args[3], BaseException):
        component = str(args[0])
        event = str(args[1])
        message = str(args[2])
        exc = args[3]
    else:
        raise TypeError("log_exception expects an exception or component, event, message, exception")

    error_id = uuid.uuid4().hex[:12]
    payload: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "component": component,
        "event": event,
        "message": message or str(exc),
        "internal_error_id": error_id,
        "pid": os.getpid(),
        "thread": threading.current_thread().name,
        "error_type": type(exc).__name__,
        "error": str(exc),
        "exception": "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
    }
    payload.update({key: value for key, value in fields.items() if value not in (None, "")})

    _best_effort_append_jsonl(_internal_error_log_path(), payload)

    log_event(
        component,
        event,
        message or str(exc),
        level=level,
        internal_error_id=error_id,
        error_type=payload["error_type"],
        error=payload["error"],
        **fields,
    )
    return error_id


def tail_log_lines(limit: int = 100, path: Path = LOG_PATH) -> list[str]:
    if not path.is_file():
        return []
    limit = max(1, min(int(limit), 1000))
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return f.readlines()[-limit:]
