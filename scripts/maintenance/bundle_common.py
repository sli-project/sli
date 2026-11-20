#!/usr/bin/env python3
"""Shared helpers for operator handoff, diagnostics and safe update tools.

The helpers in this module are intentionally conservative:
- no AD/DC changes;
- no raw events / SQLite DB / .env in exported developer handoff by default;
- every bundle has a manifest and a short SUMMARY for fast triage;
- paths are normalized to avoid accidental path traversal.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping
from urllib.parse import unquote, unquote_plus, urlsplit

# Логика диагностики живёт в server/app (runtime не импортирует scripts.maintenance);
# здесь имена реэкспортируются для существующих CLI и тестов.
from server.sli.ops.diagnostics_support import (  # noqa: F401
    DATA_DIR,
    INTERNAL_ERROR_FRESHNESS_MINUTES,
    LOG_DIR,
    _jsonl_timestamp,
    assess_recent_internal_errors,
    dir_size_report,
    fmt_bytes,
    tail_lines,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
HANDOFF_DIR = DATA_DIR / "handoff"
DIAGNOSTICS_DIR = DATA_DIR / "diagnostics"
REPORT_CAPTURE_DIR = DATA_DIR / "report_captures"
UPDATE_BACKUP_DIR = DATA_DIR / "update_backups"
TMP_DIR = DATA_DIR / "tmp"
PYTEST_BASETEMP_ROOT = TMP_DIR / "pytest-runs"
PYTEST_BASETEMP = PYTEST_BASETEMP_ROOT
AUDIT_ACTIONS_LOG = LOG_DIR / "audit-actions.log"



RUNTIME_DENY_PREFIXES = (
    "data/",
    ".git/",
    ".venv/",
    "venv/",
    "env/",
    "dist/",
    "build/",
    "bin/",
    "obj/",
    ".pytest_cache/",
    ".pytest_tmp/",
    ".mypy_cache/",
    ".ruff_cache/",
    "__pycache__/",
)
RUNTIME_DENY_PATTERNS = (
    "config/domain_controllers.json",
    ".env",
    ".env.*",
    "*.sqlite",
    "*.sqlite3",
    "*.db",
    "*.db-*",
    "*.log",
    "*.jsonl",
    "*.evtx",
    "*.pem",
    "*.key",
    "*.pfx",
    "*.p12",
    "*.zip",
    "*.7z",
    "*.rar",
    "*.tar",
    "*.gz",
    "*.pyc",
    "*.pyo",
    "*.dll",
    "*.pdb",
    "*.exe",
    "*.deps.json",
    "*.runtimeconfig.json",
    "project.assets.json",
    "*/bin/*",
    "*/obj/*",
    "*/runtimes/*",
    "*/__pycache__/*",
    "*/.pytest_cache/*",
    ".pytest_tmp",
    ".pytest_tmp/*",
)
SECRET_KEYWORDS = (
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASS",
    "KEY",
    "API_KEY",
    "OPENAI_API_KEY",
    "PRIVATE",
    "CREDENTIAL",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def json_default(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    return str(value)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=json_default), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def safe_rel(path: Path, root: Path = PROJECT_ROOT) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def is_safe_archive_member(name: str) -> bool:
    name = name.replace("\\", "/").strip("/")
    if not name:
        return False
    p = PurePosixPath(name)
    return not p.is_absolute() and ".." not in p.parts and ":" not in (p.parts[0] if p.parts else "")


def should_exclude_from_dev_handoff(rel: str) -> bool:
    rel = rel.replace("\\", "/").strip("/")
    if not rel:
        return True
    parts = PurePosixPath(rel).parts
    if any(part in {"bin", "obj", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"} for part in parts):
        return True
    if any(part == "runtimes" for part in parts):
        return True
    for prefix in RUNTIME_DENY_PREFIXES:
        if rel == prefix.rstrip("/") or rel.startswith(prefix):
            return True
    name = PurePosixPath(rel).name
    for pattern in RUNTIME_DENY_PATTERNS:
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(name, pattern):
            return True
    return False


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def zip_dir(src_dir: Path, zip_path: Path, compresslevel: int = 1) -> Path:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=compresslevel) as zf:
        for file in sorted(p for p in src_dir.rglob("*") if p.is_file()):
            rel = file.relative_to(src_dir).as_posix()
            zf.write(file, rel)
    return zip_path


def copy_tree_filtered(src_root: Path, dst_root: Path, *, include_roots: Iterable[str], exclude=should_exclude_from_dev_handoff) -> list[dict[str, Any]]:
    copied: list[dict[str, Any]] = []
    for include in include_roots:
        src = src_root / include
        if not src.exists():
            continue
        if src.is_file():
            candidates = [src]
        else:
            candidates = [p for p in src.rglob("*") if p.is_file()]
        for file in candidates:
            rel = file.relative_to(src_root).as_posix()
            if exclude(rel):
                continue
            target = dst_root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file, target)
            copied.append({"path": rel, "size": file.stat().st_size, "sha256": sha256_file(file)})
    return copied


def _secret_key(key: str) -> bool:
    return key.upper() == "PWD" or any(token in key.upper() for token in SECRET_KEYWORDS)


# Connection strings are withheld as a whole: parsing them for display risks
# exposing credentials in malformed, nested or driver-specific options.
_CONNECTION_KEY = re.compile(r"DSN|DATABASE_URL|CONNECTION_?STRING", re.IGNORECASE)
_URI = re.compile(r'[a-z][a-z0-9+.-]*://[^\s"]+', re.IGNORECASE)
_CREDENTIAL_PAIR = re.compile(
    r"([a-z_][a-z0-9_-]*)\s*=\s*(?:'((?:\\.|[^'\\])*)'|"
    r'"((?:\\.|[^"\\])*)"|((?:\\.|[^\s&;])+))',
    re.IGNORECASE,
)


def _env_assignments(text: str) -> Iterable[tuple[str, str]]:
    """Read assignments without evaluating interpolation or shell commands.

    Keep quoted multiline values/continuations together. Unparsed text and
    comments are deliberately not exported: they may contain secret fragments.
    An unterminated quote consumes the remainder, which will be redacted.
    """
    key = ""
    chunks: list[str] = []
    quote = ""
    for line in text.splitlines():
        if not chunks:
            match = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$", line)
            if not match:
                continue
            key, line = match.groups()
        chunks.append(line)
        escaped = False
        for char in line:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif quote:
                if char == quote:
                    quote = ""
            elif char in "\"'":
                quote = char
            elif char == "#":
                break
        if not quote and not escaped:
            yield key, "\n".join(chunks).strip()
            chunks = []
    if chunks:
        # A newline marks even a one-line malformed quote as unsafe.
        yield key, "\n".join(chunks).strip() + "\n"


def _credential_values(value: str) -> set[str]:
    """Known DSN credential representations for the bounded handoff scan."""
    secrets: set[str] = set()
    # Remove only an outer dotenv quote; retain inner keyword-DSN quotes.
    unwrapped = value.strip()
    if len(unwrapped) >= 2 and unwrapped[0] == unwrapped[-1] and unwrapped[0] in "\"'":
        outer_quote = unwrapped[0]
        unwrapped = unwrapped[1:-1]
        if outer_quote == '"':
            unwrapped = re.sub(r'\\(["\\])', r"\1", unwrapped)
    for match in _CREDENTIAL_PAIR.finditer(unwrapped):
        if _secret_key(unquote(match[1])):
            raw = next(group for group in match.groups()[1:] if group is not None)
            secrets.update((raw, re.sub(r"\\(.)", r"\1", raw)))
    for match in _URI.finditer(unwrapped):
        try:
            uri = urlsplit(match[0])
            if uri.password:
                secrets.add(uri.password)
            # Keep wire and decoded forms even when the parameter name is
            # encoded; parse_qsl alone loses the wire representation.
            for pair in uri.query.split("&"):
                key, separator, secret = pair.partition("=")
                if separator and _secret_key(unquote_plus(key)):
                    secrets.update((secret, unquote_plus(secret)))
        except ValueError:
            # Display redaction does not depend on successful URI parsing.
            continue
    return {variant for secret in secrets for variant in (secret, unquote(secret)) if variant}


def redact_env_value(key: str, value: str) -> str:
    if (
        _secret_key(key)
        or _CONNECTION_KEY.search(key)
        or "\n" in value
        or _credential_values(value)
        or any("@" in match[0] or match[0].lower().startswith(("postgres:", "postgresql:"))
               for match in _URI.finditer(value))
    ):
        return "<REDACTED>"
    if len(value) > 180:
        return value[:80] + "...<TRUNCATED>"
    return value


def configured_env_secret_values(env_path: Path) -> list[str]:
    """Collect known secrets, including short/encoded DSN passwords.

    This is defense in depth for supported text files, not arbitrary-log DLP.
    """
    if not env_path.is_file():
        return []
    secrets: set[str] = set()
    for key, value in _env_assignments(env_path.read_text(encoding="utf-8", errors="replace")):
        secrets.update(_credential_values(value))
        if redact_env_value(key, value) == "<REDACTED>":
            secrets.add(value.strip().strip("\"'"))
    return sorted(secret for secret in secrets if secret and secret not in {"<REDACTED>", "change-me", "changeme"})


def redact_env_file(env_path: Path) -> str:
    if not env_path.exists():
        return "# .env file not found\n"
    return "".join(
        f"{key}={redact_env_value(key, value)}\n"
        for key, value in _env_assignments(env_path.read_text(encoding="utf-8", errors="replace"))
    )


def project_file_tree(root: Path = PROJECT_ROOT, *, max_entries: int = 5000) -> str:
    rows: list[str] = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if should_exclude_from_dev_handoff(rel):
            continue
        rows.append(rel + ("/" if path.is_dir() else ""))
        if len(rows) >= max_entries:
            rows.append(f"... truncated after {max_entries} entries")
            break
    return "\n".join(rows) + "\n"


def dir_size(path: Path, *, max_entries: int | None = None, max_seconds: float | None = None) -> int:
    return int(dir_size_report(path, max_entries=max_entries, max_seconds=max_seconds).get("bytes") or 0)


#: Unroutable DSN (RFC 6761 ``.invalid``): a test that reaches the real
#: database layer without its own fixture fails fast instead of finding the
#: operator's PostgreSQL.
PYTEST_UNREACHABLE_PG_DSN = "postgresql://sli-pytest.invalid:5432/sli_pytest_unreachable"


def safe_pytest_env() -> dict[str, str]:
    """Return hermetic pytest overrides that never reach the operator database."""
    TMP_DIR.mkdir(parents=True, exist_ok=True)
    basetemp = unique_pytest_basetemp("env")
    runtime_dir = TMP_DIR / "pytest_runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    # PostgreSQL is the only runtime backend.  The DSN points nowhere, and
    # ADLOG_DB_PATH moves the runtime-database sentinel (paths.DB_PATH) away
    # from the project so file-level status probes never see operator data.
    sentinel = runtime_dir / f"runtime-db-{os.getpid()}-{timestamp()}"
    return {
        "TEMP": str(TMP_DIR),
        "TMP": str(TMP_DIR),
        "PYTEST_ADDOPTS": f"-p no:cacheprovider --basetemp={basetemp}",
        "ADLOG_DB_BACKEND": "postgres",
        "ADLOG_PG_DSN": PYTEST_UNREACHABLE_PG_DSN,
        "ADLOG_DB_PATH": str(sentinel),
        "ADLOG_DISABLE_SCHEDULER": "1",
        "ADLOG_CONTINUOUS_RECOVERY": "false",
        "ADLOG_ENABLE_POSTGRES_COLLECTION": "",
        "ADLOG_SCHEDULER_CANARY": "",
        "ADLOG_CANARY_ARCHIVE": "",
    }


def sanitized_pytest_env(source_env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build a pytest child environment without production runtime settings.

    The runner intentionally preserves ordinary operating-system variables such
    as PATH and SYSTEMROOT, but no project, PostgreSQL or Python injection
    setting is inherited from the operator session. Tests receive only the
    explicit offline overrides returned by ``safe_pytest_env`` (an unreachable DSN).
    """
    source = os.environ if source_env is None else source_env
    blocked_exact = {
        "DATABASE_URL",
        "PGDATABASE",
        "PGHOST",
        "PGHOSTADDR",
        "PGOPTIONS",
        "PGPASSFILE",
        "PGPASSWORD",
        "PGPORT",
        "PGSERVICE",
        "PGSERVICEFILE",
        "PGSSLMODE",
        "PGUSER",
        "POSTGRES_DB",
        "POSTGRES_HOST",
        "POSTGRES_PASSWORD",
        "POSTGRES_PORT",
        "POSTGRES_USER",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
    }
    clean = {
        key: value
        for key, value in source.items()
        if not key.upper().startswith("ADLOG_") and key.upper() not in blocked_exact
    }
    clean.update(safe_pytest_env())
    return clean


def _safe_run_label(label: str | None) -> str:
    raw = str(label or "pytest").strip().lower()
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in raw)
    return safe.strip("-_") or "pytest"


def unique_pytest_basetemp(label: str | None = None) -> Path:
    """Return a new project-controlled pytest basetemp for one run."""
    PYTEST_BASETEMP_ROOT.mkdir(parents=True, exist_ok=True)
    name = f"{_safe_run_label(label)}-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    return PYTEST_BASETEMP_ROOT / name


def pytest_basetemp() -> Path:
    return unique_pytest_basetemp("quick")


def pytest_quick_command() -> list[str]:
    return [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--basetemp", str(pytest_basetemp())]


def _popen_kwargs_for_group() -> dict[str, Any]:
    # Keep Popen simple here. On Windows timeout cleanup uses taskkill /T by PID.
    # On POSIX this avoids rare start_new_session/fork hangs observed during
    # repeated release-check subprocesses in long-running operator sessions.
    if os.name == "nt":
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    return {}


def _terminate_process_group(proc: subprocess.Popen[Any]) -> None:
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, text=True, timeout=5)
        else:
            proc.terminate()
            time.sleep(0.2)
            if proc.poll() is None:
                proc.kill()
    except ProcessLookupError:
        pass
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

def _read_tail_file(path: Path, limit: int = 8000) -> str:
    try:
        data = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    return data[-limit:]


def run_command(
    args: list[str],
    *,
    cwd: Path = PROJECT_ROOT,
    timeout: int = 300,
    env_update: Mapping[str, str] | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Run a maintenance command without hanging on child stdout/stderr pipes.

    Use temporary files for captured output instead of subprocess pipes. This
    avoids apply_update/release_check deadlocks when helper processes create
    descendants that keep inherited stdout/stderr handles open after the direct
    child exits. Timeouts still terminate the command process group.

    ``env`` replaces the entire child environment (including when empty).
    Otherwise inherit the parent and apply legacy ``env_update`` overrides.
    Providing both mappings is an error, even if either mapping is empty.
    """
    if env is not None and env_update is not None:
        raise ValueError("env and env_update are mutually exclusive")
    started = datetime.now(timezone.utc)
    started_mono = time.monotonic()
    command = [str(item) for item in args]
    child_env = os.environ.copy() if env is None else dict(env)
    if env_update:
        child_env.update({str(k): str(v) for k, v in env_update.items()})

    TMP_DIR.mkdir(parents=True, exist_ok=True)
    stdout_path: Path | None = None
    stderr_path: Path | None = None
    capture_paths: list[Path] = []
    timed_out = False
    try:
        # mkstemp owns an open descriptor, independent of subsequent path.open.
        # Track each path before closing so a later allocation/open failure also
        # removes every file already created by this invocation.
        for stream in ("stdout", "stderr"):
            fd, name = tempfile.mkstemp(prefix=f"adlog-cmd-{stream}-", suffix=".log", dir=TMP_DIR)
            capture_paths.append(Path(name))
            os.close(fd)
        stdout_path, stderr_path = capture_paths
        with stdout_path.open("w", encoding="utf-8", errors="replace") as stdout_file, stderr_path.open("w", encoding="utf-8", errors="replace") as stderr_file:
            proc = subprocess.Popen(
                command,
                cwd=str(cwd),
                text=True,
                stdout=stdout_file,
                stderr=stderr_file,
                env=child_env,
                **_popen_kwargs_for_group(),
            )
            deadline = time.monotonic() + max(0.1, float(timeout))
            exit_code: int | None = None
            while True:
                exit_code = proc.poll()
                if exit_code is not None:
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    _terminate_process_group(proc)
                    break
                time.sleep(0.05)
            if timed_out:
                kill_deadline = time.monotonic() + 5.0
                while time.monotonic() < kill_deadline:
                    exit_code = proc.poll()
                    if exit_code is not None:
                        break
                    time.sleep(0.05)
                if exit_code is None:
                    exit_code = -2
            stdout_file.flush()
            stderr_file.flush()

        result: dict[str, Any] = {
            "command": command,
            "cwd": str(cwd),
            "started_at_utc": started.isoformat(),
            "duration_ms": int((time.monotonic() - started_mono) * 1000),
            "timeout_seconds": timeout,
            "timed_out": timed_out,
            "pipe_reader_timeout": False,
            "exit_code": -2 if timed_out else int(exit_code or 0),
            "stdout_tail": _read_tail_file(stdout_path) if stdout_path is not None else "",
            "stderr_tail": _read_tail_file(stderr_path) if stderr_path is not None else "",
        }
        if timed_out:
            result["error_type"] = "TimeoutExpired"
            result["error"] = f"Command timed out after {timeout} seconds"
        return result
    except Exception as exc:
        return {
            "command": command,
            "cwd": str(cwd),
            "started_at_utc": started.isoformat(),
            "duration_ms": int((time.monotonic() - started_mono) * 1000),
            "timeout_seconds": timeout,
            "timed_out": False,
            "pipe_reader_timeout": False,
            "exit_code": -1,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "stdout_tail": _read_tail_file(stdout_path) if stdout_path is not None else "",
            "stderr_tail": _read_tail_file(stderr_path) if stderr_path is not None else "",
        }
    finally:
        for path in capture_paths:
            try:
                path.unlink(missing_ok=True)
            except Exception:
                pass

def audit_action(action: str, status: str, **fields: Any) -> None:
    if os.environ.get("ADLOG_TOOLKIT_DISABLE_AUDIT") == "1" or os.environ.get("PYTEST_CURRENT_TEST"):
        return
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "ts": utc_now(),
        "operation_id": fields.pop("operation_id", f"OP-{timestamp()}"),
        "action": action,
        "status": status,
    }
    payload.update(fields)
    with AUDIT_ACTIONS_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False, default=json_default) + "\n")


def basic_project_snapshot() -> dict[str, Any]:
    snapshot = {
        "project_root": str(PROJECT_ROOT),
        "generated_at_utc": utc_now(),
        "python_version": sys.version,
        "platform": platform.platform(),
        "runtime_data_included": False,
        "default_data_dir": str(DATA_DIR),
    }
    try:
        from server.sli.ops.version import get_release_metadata

        snapshot["release_metadata"] = get_release_metadata(PROJECT_ROOT)
    except Exception as exc:  # pragma: no cover - diagnostics helper must stay defensive
        snapshot["release_metadata_error"] = {"error_type": type(exc).__name__, "error": str(exc)}
    return snapshot


def make_staging_dir(prefix: str) -> tempfile.TemporaryDirectory[str]:
    return tempfile.TemporaryDirectory(prefix=prefix)
