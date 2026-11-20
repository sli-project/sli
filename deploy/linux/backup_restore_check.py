"""Check one complete PG/CH backup set using only disposable databases."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import uuid
import zipfile
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

from psycopg import sql

from deploy.linux import backup, backup_policy, restore_sandbox

RESTORE_TIMEOUT = 1800
RESTORE_RESERVE_BYTES = 1024**3



def postgres_admission(root: Path, point: dict, component: dict) -> dict:
    """Unknown capacity is not permission. Compressed archives are not DB sizes."""
    unavailable = {"status": "skipped", "reason": "postgres_capacity_unavailable"}
    try:
        source_size, live_size = component.get("database_size_bytes"), point["database_size_bytes"]
        if any(type(size) is not int or not 0 < size < 2**63 for size in (source_size, live_size)):
            return {"status": "skipped", "reason": "postgres_size_estimate_unavailable"}
        path = root / ".postgres-capacity.json"
        if path.is_symlink():
            return unavailable
        with path.open("rb") as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            return unavailable
        receipt = json.loads(raw)
        age = (backup.utc_now() - datetime.fromisoformat(receipt["observed_at_utc"])).total_seconds()
        if receipt.get("format_version") != 1 or not 0 <= age <= 30:
            return unavailable
        expected = backup.pg_capacity_receipt(point, receipt["filesystems"], observed_at=receipt["observed_at_utc"])
        if receipt != expected:
            return unavailable
        required = backup_policy.space_estimate(max(source_size, live_size))['postgres_bytes']
        return backup_policy.volume_admission(root, backup_policy.work_root(root), receipt["filesystems"], required)
    except (KeyError, TypeError, ValueError, OSError):
        return unavailable


# All restore helpers connect to the same maintenance database (sli); advisory
# locks are session-scoped and release even if the process dies. Different backup
# roots cannot restore concurrently to this cluster through this protocol.
RESTORE_LOCK = 0x534C49524553544F


@contextmanager
def postgres_restore_lock(admin):
    acquired = admin.execute("SELECT pg_try_advisory_lock(%s)", (RESTORE_LOCK,)).fetchone()[0] is True
    try:
        yield acquired
    except BaseException:
        if acquired:
            try:
                admin.execute("SELECT pg_advisory_unlock(%s)", (RESTORE_LOCK,))
            except Exception:  # noqa: BLE001 - closing the enclosing connection releases the lock
                print("linux_backup_restore_unlock_unavailable", flush=True)
        raise
    else:
        if acquired:
            admin.execute("SELECT pg_advisory_unlock(%s)", (RESTORE_LOCK,))


def _owned_directory(root: Path) -> Path:
    path = root / ".restore-runs"
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise ValueError("linux_backup_restore_invalid_ownership")
    return path


def _ownership_marker(run: dict) -> str:
    return "sli_restore_v1:" + hashlib.sha256(json.dumps(run, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def drop_owned_restore(root: Path, admin, point: dict, run: dict) -> bool:
    """Never use a name prefix as deletion authority, nor force-close sessions."""
    if (set(run) != {"format_version", "token", "database", "oid", "cluster_id"}
            or run["format_version"] != 1 or not isinstance(run["token"], str)
            or not re.fullmatch(r"[0-9a-f]{32}", run["token"])
            or run["database"] != "sli_backup_check_" + run["token"]
            or type(run["oid"]) is not int or run["oid"] <= 0
            or run["cluster_id"] != point["cluster_id"]):
        return False
    path = _owned_directory(root) / (run["token"] + ".json")
    if path.is_symlink():
        return False
    row = admin.execute(
        "SELECT d.oid, shobj_description(d.oid, 'pg_database'), "
        "d.datdba = (SELECT oid FROM pg_roles WHERE rolname = current_user), "
        "EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.datid = d.oid) "
        "FROM pg_database d WHERE d.datname = %s", (run["database"],)).fetchone()
    if row is not None:
        if row != (run["oid"], _ownership_marker(run), True, False):
            return False
        admin.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(run["database"])))
    path.unlink(missing_ok=True)
    return True


def cleanup_owned_restores(root: Path, admin, point: dict) -> dict:
    directory = _owned_directory(root)
    removed, retained = 0, 0
    if not directory.exists():
        return {"removed": 0, "retained": 0}
    paths = sorted(directory.glob("*.json"))
    if len(paths) > 1024:
        raise ValueError("linux_backup_restore_invalid_ownership")
    for path in paths:
        try:
            if path.is_symlink() or not re.fullmatch(r"[0-9a-f]{32}\.json", path.name):
                raise ValueError
            with path.open("rb") as stream:
                raw = stream.read(4097)
            if len(raw) > 4096:
                raise ValueError
            run = json.loads(raw)
            if run.get("token") != path.stem or not drop_owned_restore(root, admin, point, run):
                raise ValueError
            removed += 1
        except (ValueError, TypeError, KeyError, OSError):
            retained += 1
    if removed or retained:
        print(f"linux_backup_restore_cleanup removed={removed} retained={retained}", flush=True)
    return {"removed": removed, "retained": retained}


def create_owned_restore(root: Path, admin, point: dict) -> dict:
    token = uuid.uuid4().hex
    database = "sli_backup_check_" + token
    directory = _owned_directory(root)
    directory.mkdir(mode=0o700, exist_ok=True)
    admin.execute(sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(sql.Identifier(database)))
    oid = admin.execute("SELECT oid FROM pg_database WHERE datname = %s", (database,)).fetchone()[0]
    run = {"format_version": 1, "token": token, "database": database, "oid": oid, "cluster_id": point["cluster_id"]}
    # Durable proof plus database-side matching marker. A crash before both exist
    # retains the unproven DB for the operator, rather than guessing ownership.
    backup.write_json(directory / (token + ".json"), run)
    admin.execute(sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(sql.Identifier(database)))
    admin.execute(sql.SQL("COMMENT ON DATABASE {} IS {}").format(sql.Identifier(database), sql.Literal(_ownership_marker(run))))
    return run


def startup_restore_cleanup(root: Path) -> None:
    # Legacy live-cluster artifacts need operator handling. New drills never
    # create a database there, and automatic startup must not touch that volume.
    return None


def verified_daily_backup(root: Path) -> dict:
    """Admit a checked daily set, with a weekly full drill for light receipts."""
    try:
        receipt_path = root / "restore_check.json"
        if receipt_path.is_symlink():
            raise ValueError
        receipt = json.loads(receipt_path.read_bytes())
        identifier = receipt["backup_id"]
        if not isinstance(identifier, str) or not backup.BACKUP_NAME.fullmatch(identifier):
            raise ValueError
        path = root / identifier
        if path.is_symlink() or (path / "manifest.json").is_symlink():
            raise ValueError
        raw = (path / "manifest.json").read_bytes()
        manifest = json.loads(raw)
        last_result = backup.read_result(root)
        # The name is capture start, rather than completion hours later on HDD.
        started = datetime.strptime(identifier, "%Y%m%dT%H%M%S.%fZ").replace(tzinfo=backup.utc_now().tzinfo)
        completed = datetime.fromisoformat(manifest["completed_at_utc"])
        # Receipts written by releases before restorelight carry neither field;
        # those releases only ran full restore checks, timed by the file write.
        legacy = "verification" not in receipt and "completed_at_utc" not in receipt
        if legacy:
            checked = datetime.fromtimestamp(receipt_path.stat().st_mtime, tz=started.tzinfo)
        else:
            checked = datetime.fromisoformat(receipt["completed_at_utc"])
        now = backup.utc_now()
        verification = "full" if legacy else receipt.get("verification")
        if (receipt.get("status") != "verified" or verification not in {"full", "light"}
                or (verification == "light" and (not receipt.get("manifest_sha256") or not recent_full_check(root)))
                or set(receipt["components"]) != {"postgres", "history", "warm"}
                or any(item.get("status") != "verified" for item in receipt["components"].values())
                or manifest.get("status") != "success" or manifest.get("backup_id") != identifier
                or last_result.get("last_result") != "success" or last_result.get("last_success") != identifier
                or set(manifest["components"]) != set(backup.default_components())
                or not manifest.get("content_checksums")
                # restorelight receipts identify the exact checked set but predate
                # this optional digest. Pin the current manifest in either case.
                or ("manifest_sha256" in receipt and receipt["manifest_sha256"] != hashlib.sha256(raw).hexdigest())
                or not started <= completed <= checked <= now
                or now - started > timedelta(hours=26)
                or path not in {item[0] for item in backup.complete_backups(root, backup.default_components())}):
            raise ValueError
        return {"backup_id": identifier, "backup_started_at_utc": started.isoformat(),
                "backup_completed_at_utc": completed.isoformat(),
                "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                "installed_release": receipt.get("installed_release"),
                "migration_ledger_max_version": manifest["migration_ledger_max_version"]}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise RuntimeError("update_fresh_daily_backup_required") from None


def recent_full_check(root: Path) -> bool:
    """Legacy, incomplete, failed and future receipts never admit the fast path."""
    return _recent_full_receipt(root) is not None


def _recent_full_receipt(root: Path) -> dict | None:
    results = []
    for name in ("restore_check.json", "last_full_restore_check.json"):
        result = _read_recent_full_receipt(root / name)
        if result is not None:
            results.append(result)
    return max(results, key=lambda item: datetime.fromisoformat(item["completed_at_utc"]), default=None)


def _read_recent_full_receipt(receipt: Path) -> dict | None:
    try:
        if receipt.is_symlink():
            return None
        result = json.loads(receipt.read_bytes())
        completed = datetime.fromisoformat(result["completed_at_utc"])
        if (result.get("verification") == "full" and result["status"] == "verified"
                and completed.tzinfo is not None
                and timedelta(0) <= backup.utc_now() - completed <= timedelta(days=7)
                and set(result["components"]) == {"postgres", "history", "warm"}
                and all(item["status"] == "verified" for item in result["components"].values())):
            return result
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        pass
    return None


def _preserve_full_check(root: Path) -> None:
    # Failed nightly attempts and manual light checks must not erase a success.
    result = _recent_full_receipt(root)
    if result is not None:
        backup.write_json(root / "last_full_restore_check.json", result)


class StartupCheckDeferred(RuntimeError):
    """A budget/cancellation is not evidence of a damaged backup."""


@contextmanager
def _record_failure(root: Path, result: dict):
    try:
        yield
    except StartupCheckDeferred:
        raise
    except Exception as error:
        result.update(status="failed", diagnostic=backup.failure_diagnostic(error, "restore_check"),
                      completed_at_utc=backup.utc_now().isoformat())
        if hasattr(error, "cleanup_diagnostic"):
            result["cleanup_diagnostic"] = error.cleanup_diagnostic
        try:
            backup.write_json(root / "restore_check.json", result)
        except OSError:
            pass  # Preserve the tool failure if receipt storage itself failed.
        raise


def startup_capture(root: Path) -> dict:
    """Select only the legacy gap: newer capture, intact older successful drill.

    Never recheck damaged/failed receipts or clear a durable cycle failure.
    An already bound light receipt needs no scan; heartbeat merging handles it.
    """
    if backup.native_mode() or backup.read_cycle_failure(root):
        return {}
    capture = backup.read_result(root)
    cycle = backup.read_cycle_result(root)
    if (capture.get("last_result") != "success" or not capture.get("receipt_id")
            or cycle.get("status") != "success"
            or capture.get("last_success") == cycle.get("backup_id")
            or backup.light_evidence(root, capture)):
        return {}
    full = _read_recent_full_receipt(root / "restore_check.json")
    try:
        if (full and full.get("backup_id") == cycle["backup_id"]
                and full["completed_at_utc"] == cycle["completed_at_utc"]
                and datetime.fromisoformat(full["started_at_utc"])
                <= datetime.fromisoformat(full["completed_at_utc"])
                <= datetime.fromisoformat(capture["completed_at_utc"]) <= backup.utc_now()):
            return capture
    except (ValueError, KeyError, TypeError):
        pass
    return {}


def startup_light_check(root: Path, capture: dict) -> Path | None:
    """Check existing bytes only, using the scheduler's single worker lane."""
    if startup_capture(root) != capture:
        return None
    path = root / capture["last_success"]
    from server.sli.ops import shutdown

    from deploy.linux.operation_wait import OperationTimeout, Watch
    watch = Watch('startup_check', minimum=21600, size=backup.size_bytes(path),
                  history=root / '.status/summary.json')
    processed = 0

    def advance(count):
        nonlocal processed
        processed += count

    def check():
        if shutdown.requested():
            raise StartupCheckDeferred("linux_backup_startup_check_deferred")
        try:
            return watch.check(processed)
        except OperationTimeout:
            raise StartupCheckDeferred('linux_backup_startup_check_deferred') from None

    check.advance = advance

    try:
        receipt = light_check(root, selected=path, expected_capture=capture, check=check)
    except StartupCheckDeferred:
        print("Копия ещё не проверена: проверка при запуске прервана или превысила лимит / "
              "Backup not yet checked: startup check cancelled or time budget exceeded "
              "[linux_backup_startup_check_deferred]", flush=True)
        return None
    if not receipt:  # A concurrent capture won the lock; do not check/overwrite it.
        return None
    if not backup.light_evidence(root, capture, receipt):
        raise RuntimeError("linux_backup_restore_check_failed")
    backup.report_assurance(root, "full_check_pending")
    watch.success()
    return path


def light_check(root: Path, *, selected: Path, publish_receipt: bool = True,
                expected_capture: dict | None = None, check=None) -> dict:
    """Publish evidence only after hashing, listing PG and checking ZIP CRCs."""
    with backup.backup_lock(root, **({"check": check} if check is not None else {})):
        # Startup selection occurs outside this lock. Revalidate before touching
        # receipts so a concurrent manual capture or failed drill cannot be healed.
        if expected_capture is not None and startup_capture(root) != expected_capture:
            return {}
        if publish_receipt and check is None:
            _preserve_full_check(root)
        result = {"status": "failed", "verification": "light", "components": {},
                  "started_at_utc": backup.utc_now().isoformat()}
        if publish_receipt and check is None:
            backup.write_json(root / "restore_check.json", result)
        with _record_failure(root, result):
            if (selected.is_symlink() or selected.parent.resolve() != root.resolve()
                    or not backup.BACKUP_NAME.fullmatch(selected.name)
                    or (selected / "manifest.json").is_symlink()):
                raise RuntimeError("linux_backup_restore_invalid_backup_id")
            try:
                raw = (selected / "manifest.json").read_bytes()
                integrity_check(selected, **({"check": check} if check is not None else {}))
                if check is not None:
                    check()  # Never publish success after expiry/cancellation.
                result.update(status="verified", backup_id=selected.name,
                              capture_receipt_id=backup.read_result(root).get("receipt_id"),
                              components={name: {"status": "verified"} for name in ("postgres", "history", "warm")},
                              manifest_sha256=hashlib.sha256(raw).hexdigest(),
                              completed_at_utc=backup.utc_now().isoformat())
                if publish_receipt:
                    if check is not None:
                        _preserve_full_check(root)
                    backup.write_json(root / "restore_check.json", result)
            except StartupCheckDeferred:
                raise
            except Exception:
                # Keep capture health consistent without overwriting a newer capture.
                if backup.read_result(root).get("last_success") == selected.name:
                    try:
                        backup.record_result(root, backup.default_components(), "failed")
                    except OSError:
                        pass  # Preserve the original integrity/write diagnostic.
                raise
            return result


def integrity_check(path: Path, *, check=None) -> dict:
    """Read every artifact and ZIP CRC without creating databases or indexes."""
    from deploy.linux.operation_wait import InventoryProgress

    explicit_check = check is not None
    if check is None:
        check = InventoryProgress()
    manifest = json.loads((path / "manifest.json").read_bytes())
    if (manifest.get("status") != "success" or manifest.get("backup_id") != path.name
            or set(manifest["components"]) != set(backup.default_components())
            or not manifest.get("content_checksums")
            or manifest["content_checksums"] != backup.content_inventory(path, check=check)):
        raise RuntimeError("linux_backup_integrity_mismatch")
    with backup.pg_passfile() as passfile:
        backup.pg_tool(["pg_restore", "--list", "--format=directory", str(path / "postgres")], passfile,
                       **({"check": check} if explicit_check else {}))
    for name in ("history", "warm"):
        component = manifest["components"][name]
        if component.get("archive") != name + ".zip" or not component.get("databases"):
            raise RuntimeError("linux_backup_integrity_clickhouse_invalid")
        with zipfile.ZipFile(path / (name + ".zip")) as archive:
            if ".backup" not in archive.namelist():
                raise RuntimeError("linux_backup_integrity_clickhouse_invalid")
            try:
                # Reading to EOF validates each member CRC, like testzip(), but
                # observes the one startup budget between bounded reads.
                for member in archive.infolist():
                    check()
                    with archive.open(member) as stream:
                        while True:
                            check()
                            chunk = stream.read(256 * 1024)
                            if not chunk:
                                break
                            if hasattr(check, 'advance'):
                                check.advance(len(chunk))
                    if hasattr(check, 'advance'):
                        check.advance(1)  # Completed CRC validation, including empty members.
            except zipfile.BadZipFile:
                if explicit_check:
                    raise
                raise RuntimeError("linux_backup_integrity_clickhouse_invalid") from None
    return {"status": "verified"}


def archive_statistics(target: backup.ClickHouse, names: list[str], disk_path: str, *, storage_policy: str = 'default') -> dict:
    """Read immutable ZIP metrics from physical, disposable reference databases.

    Backup-engine scans seek through compressed entries, which deflated native
    backups cannot support. RESTORE expands those entries before statistics.
    Callers admit archive size/free space before entering this helper.
    """
    temporary = {name: "sli_backup_manifest_" + uuid.uuid4().hex for name in names}
    objects = ", ".join("DATABASE " + backup.ch_identifier(name) + " AS "
                        + backup.ch_identifier(destination) for name, destination in temporary.items())
    try:
        rows = target.query(f"RESTORE {objects} FROM Disk('backups', {backup.ch_literal(disk_path)}) "
                            "SETTINGS max_threads=2, "
                            "timeout_before_checking_execution_speed=0, max_memory_usage=536870912, "
                            f"storage_policy={backup.ch_literal(storage_policy)}")
        if not rows or rows[0].get("status") != "RESTORED":
            raise RuntimeError("linux_backup_restore_clickhouse_incomplete")
        return {name: target.statistics(destination) for name, destination in temporary.items()}
    finally:
        # Even failed RESTORE can leave multiple partial databases. A failed
        # DROP must not prevent attempts for the remaining generated names.
        cleanup = replace(target, timeout=30, deadline=None)
        failed = False
        for destination in temporary.values():
            try:
                cleanup.query(f"DROP DATABASE IF EXISTS {backup.ch_identifier(destination)} SYNC "
                              "SETTINGS max_table_size_to_drop=0, max_partition_size_to_drop=0")
            except Exception:  # noqa: BLE001 - fixed diagnostic only
                failed = True
        if failed:
            raise RuntimeError("linux_backup_restore_clickhouse_cleanup_failed")


def restore_clickhouse(target: backup.ClickHouse, newest: Path, component: dict) -> dict:
    """Restore with explicit database renames; archive expansion bounds admission."""
    archive_name = target.name + ".zip"
    if not backup.BACKUP_NAME.fullmatch(newest.name):
        raise ValueError("linux_backup_restore_invalid_backup_id")
    if component.get("archive") != archive_name:
        raise ValueError("linux_backup_restore_invalid_archive")
    archive = newest / archive_name
    if archive.is_symlink() or not archive.is_file():
        raise ValueError("linux_backup_restore_invalid_archive")
    names = component["databases"]
    expected = component.get("tables")
    table_names = component.get("table_names")
    inventory = expected if expected is not None else table_names
    if (not names or len(names) != len(set(names)) or inventory is None or set(names) != set(inventory)
            or any(not isinstance(name, str) or not name or name.startswith("sli_backup_") for name in names)):
        raise ValueError("linux_backup_restore_invalid_databases")
    with zipfile.ZipFile(archive) as handle:
        expanded = sum(item.file_size for item in handle.infolist())
    # MergeTree files are already compressed; allow two copies plus a metadata reserve.
    required = backup_policy.space_estimate(expanded_ch_bytes=expanded)['clickhouse_bytes']
    live = target.query("SELECT free_space FROM system.disks WHERE name='default'")
    if not live or int(live[0]["free_space"]) < backup_policy.DATA_RESERVE:
        if live:
            backup_policy.report_refusal({'reason': 'insufficient_data_disk_space',
                                          'volume': 'clickhouse:' + target.name + '/default',
                                          'required_bytes': backup_policy.DATA_RESERVE,
                                          'free_bytes': int(live[0]['free_space'])})
        return {"status": "skipped_insufficient_data_space"}
    # Metadata, temporary files and table data all belong to a dedicated server
    # whose entire data directory is bound to the backup volume.
    target = replace(target, host='clickhouse-restore', port=8123,
                     user=os.environ.get('SLI_HISTORY_CLICKHOUSE_USER', 'sli_history'),
                     password_setting='SLI_HISTORY_CLICKHOUSE_PASSWORD', archive_root=None, disk_root=None)
    target = replace(target, timeout=RESTORE_TIMEOUT, deadline=None, operation_size=required)
    disks = target.query("SELECT free_space, path FROM system.disks WHERE name='restore_check'")
    if not disks or disks[0].get("path") != '/var/lib/clickhouse/restore-check/':
        return {"status": "skipped_volume_mismatch"}
    if int(disks[0]["free_space"]) < required:
        free = int(disks[0]['free_space'])
        backup_policy.report_refusal({'reason': 'insufficient_backup_disk_space', 'volume': disks[0]['path'],
                                      'required_bytes': required, 'free_bytes': free})
        return {"status": "skipped_insufficient_space", "required_bytes": required, "free_bytes": free}
    with target.readable_archive(archive, backup.backup_root()) as disk_path:
        return verify_clickhouse_archive(target, names, expected, table_names, disk_path, required)


def verify_clickhouse_archive(target, names, expected, table_names, disk_path, required) -> dict:
    if expected is None:
        # Scan the same immutable ZIP, never changing live tables. This shares
        # only the drill's deadline, not the production backup capture window.
        expected = archive_statistics(target, names, disk_path, storage_policy='restore_check')
        if any(set(expected[name]) != set(table_names[name]) for name in names):
            raise RuntimeError("linux_backup_restore_clickhouse_mismatch")
    temporary = {name: "sli_backup_check_" + uuid.uuid4().hex for name in names}
    objects = ", ".join("DATABASE " + backup.ch_identifier(name) + " AS "
                        + backup.ch_identifier(destination) for name, destination in temporary.items())
    try:
        rows = target.query(f"RESTORE {objects} FROM Disk('backups', {backup.ch_literal(disk_path)}) "
                            f"SETTINGS max_execution_time={target.timeout:.3f}, max_threads=2, "
                            "timeout_before_checking_execution_speed=0, "
                            "storage_policy='restore_check'")
        if not rows or rows[0].get("status") != "RESTORED":
            raise RuntimeError("linux_backup_restore_clickhouse_incomplete")
        for name, destination in temporary.items():
            if target.statistics(destination) != expected[name]:
                raise RuntimeError("linux_backup_restore_clickhouse_mismatch")
    finally:
        # RESTORE is not transactional: even an error can leave partial databases.
        # Attempt every cleanup if one fails, and never generate a live DROP name.
        failed = False
        cleanup = replace(target, timeout=30, deadline=None)
        for destination in temporary.values():
            try:
                cleanup.query(f"DROP DATABASE IF EXISTS {backup.ch_identifier(destination)} SYNC "
                             "SETTINGS max_table_size_to_drop=0, max_partition_size_to_drop=0")
            except Exception:  # noqa: BLE001 - fixed diagnostic only
                failed = True
        if failed:
            raise RuntimeError("linux_backup_restore_clickhouse_cleanup_failed")
    return {"status": "verified", "required_bytes": required, "tables": expected}


def restore_check(root: Path, *, selected: Path | None = None) -> dict:
    with backup.backup_lock(root):
        _preserve_full_check(root)
        result = {"status": "failed", "verification": "full", "components": {},
                  "started_at_utc": backup.utc_now().isoformat()}
        backup.write_json(root / "restore_check.json", result)
        with _record_failure(root, result):
            backups = backup.successful_backups(root)
            if selected is None and not backups:
                raise RuntimeError("linux_backup_restore_no_dump")
            newest = selected if selected is not None else backups[-1]
            if (not newest.resolve().is_relative_to(root.resolve()) or newest.is_symlink()
                    or not backup.BACKUP_NAME.fullmatch(newest.name)):
                raise RuntimeError("linux_backup_restore_invalid_backup_id")
            raw = (newest / "manifest.json").read_bytes()
            manifest = json.loads(raw)
            result.update(backup_id=newest.name, components={"postgres": {"status": "failed"}})
            backup.write_json(root / "restore_check.json", result)
            expected = manifest["components"]["postgres"]["row_counts"]
            if set(expected) != set(backup.KEY_TABLES):
                raise RuntimeError("linux_backup_restore_invalid_counts")
            # Legacy runs on the data volume require operator intervention.
            # Refuse without querying/deleting their databases, even if fresh
            # capacity evidence is unavailable and the drill would be deferred.
            legacy = _owned_directory(root)
            if legacy.exists() and any(legacy.iterdir()):
                raise RuntimeError("linux_backup_restore_cleanup_required")
            # Read-only probe of the working cluster; never CREATE/DROP there.
            with backup.pg_passfile() as passfile, backup.pg_connect(passfile, autocommit=True) as admin:
                admin.execute('BEGIN READ ONLY')
                with postgres_restore_lock(admin) as acquired:
                    point = admin.execute(backup.PG_CAPACITY_SQL).fetchone()[0]
                    admission = (postgres_admission(root, point, manifest["components"]["postgres"])
                                 if acquired else {'status': 'skipped', 'reason': 'postgres_restore_busy'})
            if admission["status"] != "admitted":
                result.update(status="skipped", reason=admission["reason"],
                              completed_at_utc=backup.utc_now().isoformat(),
                              manifest_sha256=hashlib.sha256(raw).hexdigest())
                result["components"]["postgres"] = admission
                backup.write_json(root / "restore_check.json", result)
                backup_policy.report_refusal(admission)
                return result
            installed = restore_sandbox.restore(backup_policy.work_root(root), newest / "postgres",
                                                expected, manifest["migration_ledger_max_version"],
                                                manifest['components']['postgres'].get('database_size_bytes', 0), root)
            if installed is not None:
                result["installed_release"] = installed
            result["components"]["postgres"] = {"status": "verified"}
            for target in backup.clickhouse_targets():
                component = manifest["components"].get(target.name)
                if not component or not ({"tables", "table_names"} & component.keys()):
                    result["components"][target.name] = {"status": "skipped_missing_manifest_metrics"}
                else:
                    try:
                        result["components"][target.name] = restore_clickhouse(target, newest, component)
                    except Exception:
                        result["components"][target.name] = {"status": "failed"}
                        backup.write_json(root / "restore_check.json", result)
                        raise
                backup.write_json(root / "restore_check.json", result)
            result["status"] = ("verified" if all(item["status"] == "verified"
                                               for item in result["components"].values()) else "skipped")
            result["completed_at_utc"] = backup.utc_now().isoformat()
            result["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
            backup.write_json(root / "restore_check.json", result)
            if result["status"] == "verified":
                backup.write_json(root / "last_full_restore_check.json", result)
            backup.publish_summary(root)
            return result


def main() -> int:
    try:
        result = restore_check(backup.backup_root())
    except Exception:  # noqa: BLE001 - never expose SQL, dump contents or credentials
        print("linux_backup_restore_check_failed", file=sys.stderr)
        return 1
    if result["status"] == "skipped":
        print("linux_backup_restore_check_skipped")
        return 2
    print("linux_backup_restore_check_verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

