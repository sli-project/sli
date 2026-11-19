"""Progress budgets and small success histories in existing operation receipts.

Only fixed step names and numeric timings cross the diagnostic boundary.
"""
from __future__ import annotations

import json
import hashlib
import math
import os
import re
import signal
import shutil
import socket
import stat
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from contextlib import contextmanager
from functools import lru_cache

POLL_SECONDS = 30
BYTES_PER_SECOND = 1024 * 1024  # Previous portable estimate when measurement is unavailable.
MAX_HISTORY_SECONDS = 7 * 24 * 3600
MAX_HISTORY_BYTES = 4 * 1024**2  # Same metadata ceiling as a backup manifest.
_deadlines = []
_watchdog_last = None
WATCHDOG_INTERVAL = 5
PROGRESS_FD = 'SLI_OPERATION_PROGRESS_FD'
MESSAGES = {
    'operation_progress': 'Operation progress / Прогресс операции',
    'operation_stalled': 'No progress / Нет прогресса',
    'operation_deadline_exceeded': 'Safety limit reached / Достигнут страховочный предел',
}


class OperationTimeout(RuntimeError):
    def __init__(self, code, detail):
        super().__init__(code)
        self.code = code
        self.detail = detail


def history_path(backup_root=None):
    if os.environ.get('SLI_DEPLOYMENT_MODE') == 'native':
        return Path('/var/lib/sli/backup-status/summary.json')
    root = backup_root if backup_root is not None else os.environ.get('SLI_BACKUP_ROOT', '/backups')
    return Path(root) / '.status/summary.json'


def readiness_history():
    # Host launchers are stdlib-only; this directory is created by the installer.
    path = Path('/var/lib/sli/backup-status/summary.json')
    return path if Path('/var/lib/sli/state').is_dir() else None


def trusted_history_path(path):
    for item in (path, *path.parents):
        if item.is_symlink():
            return False
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        expected_type = stat.S_ISREG if item == path else stat.S_ISDIR
        if (not expected_type(info.st_mode) or info.st_uid not in {0, getattr(os, 'geteuid', lambda: 0)()}
                or os.name == 'posix' and info.st_mode & 0o022
                and not (item != path and info.st_uid == 0 and info.st_mode & stat.S_ISVTX)):
            return False
    return True


def read_history(path):
    try:
        if not trusted_history_path(path):
            print('native_operation_history_untrusted', file=sys.stderr, flush=True)
            return {}
        with path.open('rb') as stream:
            raw = stream.read(MAX_HISTORY_BYTES + 1)
        if len(raw) > MAX_HISTORY_BYTES:
            return {}
        value = json.loads(raw)
        return value if isinstance(value, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        print('native_operation_history_unavailable', file=sys.stderr, flush=True)
        return {}


def samples(path, step, *, maximum=MAX_HISTORY_SECONDS):
    document = read_history(path)
    if os.environ.get('SLI_DEPLOYMENT_MODE') == 'native':
        own = machine_id()
        if own is None or document.get('operation_machine_id') != own:
            return []  # Legacy/copied native receipts have no local provenance.
    history = document.get('operation_durations', {})
    values = history.get(step, []) if isinstance(history, dict) else []
    if not isinstance(values, list):
        return []
    return [float(value) for value in values[-5:] if type(value) in {int, float}
            and 0 < value <= maximum]


def machine_id():
    path = Path('/etc/machine-id')
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    except OSError:
        return None  # An unverifiable identity cannot contribute history.


@lru_cache(maxsize=8)
def native_rate(path):
    """Measure a private, fsynced scratch write, never inspect application data.

    The MiB is a sampling volume, NOT an assumed machine throughput. A slow
    first write lengthens the estimate; ongoing real progress renews the watch.
    Failure is reported before fencing rather than inventing a machine speed.
    """
    path = Path(path)
    while not path.exists():
        path = path.parent
    block = os.urandom(1024**2)
    started = time.perf_counter()
    with tempfile.TemporaryFile(dir=path) as stream:
        stream.write(block)
        stream.flush()
        os.fsync(stream.fileno())
    elapsed = time.perf_counter() - started
    if elapsed <= 0:
        raise RuntimeError('native_operation_rate_unavailable')
    return len(block) / elapsed


def native_samples(path, step, size, rate, stall):
    history = read_history(path).get('operation_samples', {})
    values = history.get(step, []) if isinstance(history, dict) else []
    if not isinstance(values, list):
        return []
    own = machine_id()
    result = []
    for value in values[-5:]:
        if not isinstance(value, dict) or own is None or value.get('machine_id') != own:
            continue
        seconds, old_size = value.get('seconds'), value.get('size_bytes')
        # A duration without its workload cannot estimate this operation. Reject
        # (do not clip) samples slower than a measured local transfer plus the
        # site's permitted silent interval. This prevents one corrupt/foreign
        # record from buying days of silence. CPU-heavy live work still renews
        # the watch, even when its eventual duration is unsuitable as a sample.
        if (type(old_size) is not int or not 0 <= old_size < 2**63 or type(seconds) not in {int, float}
                or not 0 < seconds <= old_size / rate + stall):
            continue
        if old_size == 0:
            if size == 0:
                result.append(float(seconds))
        else:
            result.append(min(seconds * size / old_size, size / rate + stall))
    return result


class InventoryProgress:
    """Inventory's cancellation callback is distinct from bytes actually read."""
    def __call__(self):
        pass

    def advance(self, count):
        if count:
            made_progress()


def copy_stream(source, destination):
    """Report real writes, including inside a single large file."""
    while block := source.read(1024**2):
        destination.write(block)
        made_progress()


def hash_stream(stream, check):
    digest = hashlib.sha256()
    while True:
        check()
        block = stream.read(256 * 1024)
        if not block:
            return digest.hexdigest()
        digest.update(block)
        if hasattr(check, 'advance'):
            check.advance(len(block))


def copy_file(source, destination):
    """The copyfile contract for artifacts, with bounded, observable writes."""
    try:
        same = os.path.samefile(source, destination)
    except OSError:
        same = False
    if same:
        raise shutil.SameFileError(source, destination)
    for path in (source, destination):
        try:
            mode = os.stat(path).st_mode
        except OSError:
            continue
        if stat.S_ISFIFO(mode):
            raise shutil.SpecialFileError('named pipe')
    with open(source, 'rb') as stream, open(destination, 'wb') as output:
        copy_stream(stream, output)
    made_progress()  # Empty files also represent completed work.
    return destination


def copy2(source, destination):
    """Keep copytree/restore metadata semantics while reporting file blocks."""
    if os.path.isdir(destination):
        destination = os.path.join(destination, os.path.basename(source))
    copy_file(source, destination)
    shutil.copystat(source, destination)
    return destination


def copy_tree(source, destination, *, copy_function=None, dirs_exist_ok=False):
    def scanned(directory, names):
        made_progress()  # A scanned directory counts even if it contains no files.
        return ()

    return shutil.copytree(source, destination, copy_function=copy_function or copy2,
                           dirs_exist_ok=dirs_exist_ok, ignore=scanned)


def remove_tree(path):
    """Remove entries with progress and the stdlib's fd-based link protection.

    fwalk pins each directory and checks its identity before descending. Never
    replace Linux rmtree's symlink protection with a path-based recursive walk.
    The portable fallback is for hosts where rmtree itself is path-based.
    """
    if os.path.islink(path) or not os.path.isdir(path):
        return shutil.rmtree(path)  # Preserve rmtree's refusal/error semantics.
    is_junction = getattr(os.path, 'isjunction', lambda _: False)
    if is_junction(path):
        shutil.rmtree(path)  # Windows junctions must not be traversed either.
        made_progress()
        return

    def failed(error):
        raise error

    if shutil.rmtree.avoids_symlink_attacks:
        for _, directories, files, descriptor in os.fwalk(path, topdown=False, onerror=failed):
            for name in files:
                try:
                    os.unlink(name, dir_fd=descriptor)
                except FileNotFoundError:
                    continue  # Like rmtree, tolerate entries removed concurrently.
                made_progress()
            for name in directories:
                try:
                    if stat.S_ISLNK(os.stat(name, dir_fd=descriptor, follow_symlinks=False).st_mode):
                        os.unlink(name, dir_fd=descriptor)
                    else:
                        os.rmdir(name, dir_fd=descriptor)
                except FileNotFoundError:
                    continue
                made_progress()
    else:
        with os.scandir(path) as entries:
            for entry in entries:
                try:
                    if entry.is_symlink():
                        os.unlink(entry.path)
                    elif is_junction(entry.path):
                        os.rmdir(entry.path)
                    elif entry.is_dir(follow_symlinks=False):
                        remove_tree(entry.path)
                        continue
                    else:
                        os.unlink(entry.path)
                except FileNotFoundError:
                    continue
                made_progress()
    os.rmdir(path)
    made_progress()


def record_success(path, step, seconds, *, size=None):
    """Best-effort atomic receipt update after the operation succeeded."""
    try:
        if not trusted_history_path(path):
            print('native_operation_history_untrusted', file=sys.stderr, flush=True)
            return
        document = read_history(path)
        if size is not None or os.environ.get('SLI_DEPLOYMENT_MODE') == 'native':
            own = machine_id()
            if own is None or document.get('operation_machine_id') != own:
                document['operation_durations'] = {}
                document['operation_samples'] = {}
            document['operation_machine_id'] = own
        history = document.get('operation_durations')
        if not isinstance(history, dict):
            history = document['operation_durations'] = {}
        values = history.get(step, [])
        values = ([float(value) for value in values[-5:] if type(value) in {int, float}
                   and 0 < value <= MAX_HISTORY_SECONDS] if isinstance(values, list) else [])
        history[step] = (values + [min(max(float(seconds), 0.001), MAX_HISTORY_SECONDS)])[-5:]
        if size is not None:
            records = document.get('operation_samples')
            if not isinstance(records, dict):
                records = document['operation_samples'] = {}
            previous = records.get(step, [])
            records[step] = (previous[-4:] if isinstance(previous, list) else []) + [
                {'machine_id': machine_id(), 'size_bytes': size, 'seconds': seconds}]
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=path.parent)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                json.dump(document, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644)
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)
    except (OSError, ValueError):
        print('native_operation_history_unavailable', file=sys.stderr, flush=True)


def stall_seconds(*, default=1800):
    try:
        from deploy.linux import native_clickhouse_endpoint as endpoint
    except ModuleNotFoundError:  # stdlib-only installed setup helper
        import importlib.util
        spec = importlib.util.spec_from_file_location('sli_operation_site',
            Path(__file__).with_name('native_clickhouse_endpoint.py'))
        endpoint = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(endpoint)
    return endpoint.site_configuration().get('operation_stall_minutes', default // 60) * 60


class Watch:
    def __init__(self, step, *, minimum, size=0, history=None, stall=None, native=False, work_path=None, rate=None):
        if not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', step):
            raise ValueError('native_operation_step_invalid')
        self.step = step
        self.history = history
        self.native = native
        self.size = size
        if stall is None:
            native_stall = native or os.environ.get('SLI_DEPLOYMENT_MODE') == 'native' or step.startswith('migration')
            stall = stall_seconds(default=1800 if native_stall else 900)
        self.stall = stall
        rate_path = work_path or (Path('/var/lib/sli') if native else Path(tempfile.gettempdir()))
        if rate is None:
            try:
                rate = native_rate(rate_path) if size else 1
            except (OSError, RuntimeError):
                if native:
                    raise
                rate = BYTES_PER_SECOND
        if not math.isfinite(rate) or rate <= 0:
            if native:
                raise ValueError('native_operation_rate_unavailable')
            rate = BYTES_PER_SECOND
        if self.native:
            values = native_samples(history, step, size, rate, stall) if history is not None else []
            self.usual = statistics.median(values) if values else 0
            self.limit = math.ceil(max(size / rate, self.usual) + stall)
        else:
            maximum = max(minimum, math.ceil(max(0, size) / rate))
            values = samples(history, step, maximum=maximum) if history is not None else []
            self.usual = statistics.median(values) if values else 0
            self.limit = max(minimum, math.ceil(max(0, size) / rate) * 3, self.usual * 3)
        self.started = self.progress_at = time.monotonic()
        self.previous = None
        self.reported = self.started

    def check(self, progress=None, *, components=()):
        now = time.monotonic()
        if progress is not None:
            growing = (progress > self.previous if type(progress) in {int, float}
                       and type(self.previous) in {int, float} else progress != self.previous)
            if self.previous is not None and growing:
                self.progress_at = now
                made_progress()
            if self.previous is None or growing:
                self.previous = progress
        detail = {'step': self.step, 'elapsed_seconds': int(now - self.started),
                  'usual_seconds': int(self.usual), 'last_progress_seconds_ago': int(now - self.progress_at),
                  'limit_seconds': int(self.limit)}
        if components:
            detail['unready_components'] = [name for name in components
                                            if re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', name)][:64]
        # Expected duration is diagnostic. Only confirmed silence cancels work.
        code = 'operation_stalled' if now - self.progress_at >= self.stall else None
        detail['reason_code'] = code or 'operation_progress'
        if code or now - self.reported >= POLL_SECONDS:
            print(MESSAGES[code or 'operation_progress'] + ' ' + json.dumps(detail, sort_keys=True),
                  file=sys.stderr, flush=True)
            self.reported = now
        if code:
            raise OperationTimeout(code, detail)
        return min(POLL_SECONDS, self.stall - (now - self.progress_at))

    def success(self):
        made_progress()
        if self.history is not None:
            record_success(self.history, self.step, time.monotonic() - self.started,
                           **({'size': self.size} if self.native else {}))


@contextmanager
def deadline(watch):
    """Interrupt blocked native orchestration *inside* its recovery boundary.

    No external SIGKILL: the existing coordinator must restore the accepted
    release. Disarm before raising so rollback gets its own bounded waits.
    POSIX only; portable unit tests exercise the watch without arming a timer.
    """
    if os.name != 'posix' or _deadlines:
        yield
        return
    previous = signal.getsignal(signal.SIGALRM)

    def check(signum, frame):
        signal.setitimer(signal.ITIMER_REAL, 0)
        remaining = watch.check()
        signal.setitimer(signal.ITIMER_REAL, max(0.001, remaining))

    _deadlines.append(watch)
    try:
        signal.signal(signal.SIGALRM, check)
        signal.setitimer(signal.ITIMER_REAL, max(0.001, watch.check()))
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        _deadlines.remove(watch)


def progress_fds():
    """Only an inherited pipe, never a path or arbitrary descriptor to write."""
    try:
        fd = int(os.environ.get(PROGRESS_FD, '-1'))
        return (fd,) if fd >= 3 and stat.S_ISFIFO(os.fstat(fd).st_mode) else ()
    except (OSError, ValueError):
        return ()


def made_progress():
    global _watchdog_last
    now = time.monotonic()
    for watch in _deadlines:
        watch.progress_at = now
    for fd in progress_fds():
        try:
            os.write(fd, b'.')
        except OSError:
            pass  # The supervisor may already be cancelling this child.
    address = os.environ.get('NOTIFY_SOCKET')
    pid = os.getpid()
    if not address or os.environ.get('WATCHDOG_PID', str(pid)) != str(pid):
        return  # Manual runs and children supervised through the progress pipe.
    identity = (pid, address)
    if _watchdog_last is not None and _watchdog_last[:2] == identity and now - _watchdog_last[2] < WATCHDOG_INTERVAL:
        return
    if address.startswith('@'):
        address = '\0' + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notifier:
            notifier.settimeout(1)
            notifier.sendto(b'WATCHDOG=1', address)
    except OSError:
        raise RuntimeError('native_operation_watchdog_failed') from None
    _watchdog_last = (*identity, now)


def coordinator_unit():
    """Resolve this invocation, never guess a scheduled unit for an upgrade."""
    if not re.fullmatch(r'[a-f0-9]{32}', os.environ.get('INVOCATION_ID', '')):
        return None
    try:
        lines = Path('/proc/self/cgroup').read_text(encoding='utf-8').splitlines()
    except OSError:
        return None
    for line in lines:
        hierarchy, controllers, group = (line.split(':', 2) + ['', ''])[:3]
        if (hierarchy, controllers) != ('0', '') and 'name=systemd' not in controllers.split(','):
            continue
        unit = group.rsplit('/', 1)[-1]
        if len(unit) <= 255 and re.fullmatch(r'[A-Za-z0-9_.:@-]+\.service', unit):
            return unit
    return None


def setup_command(argv, *, cwd, env, watch, failure_codes=(), diagnose_failure=None):
    """Wait across the stdlib/runtime boundary using actual child progress.

    The writer is inherited only by verified native children; diagnostics and
    arbitrary output never count as progress. Watchdog recovery runs in the
    child first; the enclosing limit includes its own recovery work allowance.
    """
    reader, writer = os.pipe()
    os.set_blocking(reader, False)
    os.set_blocking(writer, False)
    observed = 0

    def probe():
        nonlocal observed
        try:
            observed += len(os.read(reader, 65536))
        except BlockingIOError:
            pass
        return observed

    try:
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            child_env = dict(env, **{PROGRESS_FD: str(writer)})
            child = subprocess.Popen(argv, cwd=cwd, env=child_env, stdout=output, stderr=errors,
                                     pass_fds=(writer,), start_new_session=True)
            child.sli_process_group = True
            wait_process(child, watch, probe)
            if child.returncode:
                errors.seek(0, os.SEEK_END)
                errors.seek(max(0, errors.tell() - 4096))
                lines = errors.read(4096).decode('utf-8', errors='replace').splitlines()
                for code in ('operation_stalled', 'operation_deadline_exceeded'):
                    if code in lines or any('(reason_code=' + code + ')' in line for line in lines):
                        raise RuntimeError(code)
                if diagnose_failure is not None:
                    diagnose_failure(lines)
                for line in reversed(lines):
                    if line in failure_codes:
                        raise RuntimeError(line)
                raise RuntimeError('native_setup_install_failed')
            output.seek(0)
            return output.read().decode('utf-8')
    finally:
        os.close(reader)
        os.close(writer)


def file_bytes(path):
    if not path.exists():
        return 0
    if path.is_file():
        return path.stat().st_size
    return sum(item.stat().st_size for item in path.rglob('*') if item.is_file() and not item.is_symlink())


def wait_process(process, watch, probe, *, check=None):
    """Reap cancelled clients before restore cleanup or transaction recovery."""
    try:
        while process.poll() is None:
            remaining = watch.check(probe())
            if check is not None:
                remaining = min(remaining, check())
            try:
                process.wait(timeout=max(0.001, remaining))
            except subprocess.TimeoutExpired:
                pass
        if check is not None:
            check()
        return process.returncode
    finally:
        if process.poll() is None:
            if os.name == 'posix' and getattr(process, 'sli_process_group', False):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
        process.wait()


def postgres_probe(passfile, application, database='sli', *, files=None):
    """Only this client's sessions; changing age/monitor sessions are not progress.

    Query text is compared inside PostgreSQL and returned only as an MD5.
    A stable lock wait therefore stalls even while its elapsed time increases.
    """
    from deploy.linux import backup
    progress = file_bytes(files) if files is not None else 0
    try:
        with backup.pg_connect(passfile, database, autocommit=True) as connection:
            connection.execute('SET statement_timeout=5000')
            row = connection.execute(
                "SELECT pg_database_size(%s), COALESCE((SELECT md5(string_agg("
                "concat_ws(':', pid, state, wait_event_type, wait_event, query_start, md5(query)), ',' ORDER BY pid)) "
                "FROM pg_stat_activity WHERE application_name=%s AND pid<>pg_backend_pid()), ''), "
                "(SELECT sum(p.blocks_done + p.tuples_done) FROM pg_stat_progress_create_index p "
                "JOIN pg_stat_activity a USING(pid) WHERE a.application_name=%s), "
                "(SELECT sum(p.bytes_processed) FROM pg_stat_progress_copy p "
                "JOIN pg_stat_activity a USING(pid) WHERE a.application_name=%s)",
                (database, application, application, application)).fetchone()
            ledger = 0
            if connection.execute("SELECT to_regclass('public.schema_migrations')").fetchone()[0] is not None:
                ledger = connection.execute('SELECT coalesce(max(version), 0) FROM public.schema_migrations').fetchone()[0]
            return progress, row, ledger
    except Exception:  # noqa: BLE001 - failed probes are not evidence of progress
        return progress if files is not None else None
