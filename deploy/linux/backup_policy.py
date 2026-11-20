"""Calendar retention and read-only volume admission for backup/restore jobs."""
from __future__ import annotations

import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

GIB = 1024**3
# Small explicit allowance for live writes during a bounded backup/drill.
DATA_RESERVE = GIB


def space_estimate(pg_bytes: int = 0, *, backup_bytes: int | None = None,
                   expanded_ch_bytes: int = 0, files_bytes: int = 0,
                   archive_staging_bytes: int = 0, companion_bytes: int = 0) -> dict:
    """Additional free bytes, excluding sets already present on disk.

    First-copy estimate: P + C + F + companion, with no assumed compression ratio because
    this machine has no measured history yet. This one-time conservative budget
    is rechecked against actual set/archive sizes by the drill before restore.
    The drill's existing 20% PG allowance and 10 GiB workspace reserve remain.
    One explicit GiB for live-data growth is checked separately on data volumes.
    """
    sizes = (pg_bytes, expanded_ch_bytes, files_bytes, archive_staging_bytes, companion_bytes)
    if any(type(size) is not int or size < 0 for size in sizes):
        raise ValueError('linux_backup_size_unavailable')
    if backup_bytes is None:
        backup_bytes = pg_bytes + expanded_ch_bytes + files_bytes + companion_bytes
    if type(backup_bytes) is not int or backup_bytes < 0:
        raise ValueError('linux_backup_size_unavailable')
    pg_restore = pg_bytes * 12 // 10
    ch_restore = expanded_ch_bytes * 2
    # One B is the private snapshot beside the set. The other B belongs to
    # restored files/companion and temporary archives on the work filesystem.
    work = backup_bytes + pg_restore + ch_restore + 10 * GIB
    return {'backup_bytes': backup_bytes,
            'capture_bytes': backup_bytes + files_bytes + archive_staging_bytes + GIB,
            # Work, not free-space reserves: capture reads live sources and
            # writes the set; drill snapshots/verifies the set and writes/reads
            # restored data. The two passes name actual copy/verification work.
            'source_bytes': pg_bytes + expanded_ch_bytes + files_bytes + companion_bytes,
            'capture_io_bytes': pg_bytes + expanded_ch_bytes + files_bytes + companion_bytes + backup_bytes,
            'drill_io_bytes': backup_bytes + backup_bytes + pg_bytes + pg_bytes
                              + expanded_ch_bytes + expanded_ch_bytes + files_bytes + files_bytes
                              + companion_bytes + companion_bytes,
            'postgres_bytes': (pg_bytes * 12 + 9) // 10 + 10 * GIB,
            'clickhouse_bytes': ch_restore + GIB,
            'drill_copy_bytes': backup_bytes, 'work_bytes': work,
            'drill_bytes': backup_bytes + work,
            'checkpoint_bytes': backup_bytes * 2 + work,
            'data_growth_bytes': DATA_RESERVE}


def last_backup_size(root: Path, *, machine_id: str | None = None,
                     companion_bytes: int | None = None) -> int | None:
    """Measured local sets plus positive growth; legacy sets predate machine IDs."""
    if companion_bytes is not None and (type(companion_bytes) is not int or companion_bytes < 0):
        raise ValueError('linux_backup_size_unavailable')
    sizes = []
    paths = list(root.glob('*/manifest.json')) + list(root.glob('upgrade-checkpoints/*/*/manifest.json'))
    for path in sorted(paths, key=lambda p: p.parent.name, reverse=True):
        if (not re.fullmatch(r'\d{8}T\d{6}\.\d{6}Z', path.parent.name)
                or any(item.is_symlink() for item in (path, path.parent, *path.parents))):
            continue
        try:
            # Manifests are untrusted metadata, never instructions or credentials.
            with path.open('rb') as stream:
                raw = stream.read(4 * 1024**2 + 1)
            if len(raw) > 4 * 1024**2:
                continue
            value = json.loads(raw)
            size = value.get('size_bytes')
            if (value.get('status') in {'success', 'backup_created'}
                    and value.get('backup_id') == path.parent.name
                    and value.get('machine_id') in (None, machine_id)
                    and type(size) is int and 0 < size < 2**63):
                measured = tree_bytes(path.parent)
                if measured <= 0:
                    continue  # A disappeared/unmeasurable set is not a zero-byte sample.
                sample = max(size, measured)
                if companion_bytes is not None:
                    # Compare historical data growth with the same current
                    # protected companion, rather than counting its growth twice.
                    sample = sample - tree_bytes(path.parent / 'companion') + companion_bytes
                sizes.append(sample)
                if len(sizes) == 2:
                    return sizes[0] + max(0, sizes[0] - sizes[1])
        except (OSError, ValueError, TypeError, AttributeError):
            continue
    return sizes[0] if sizes else None


def tree_bytes(root: Path, *, excluded: tuple | set = ()) -> int:
    """Metadata only; never follow directory/file links into other data trees."""
    total = 0
    try:
        root.stat()
    except FileNotFoundError:
        return 0  # Fresh setup has no database/application tree yet.

    def failed(error):
        raise error  # Unknown size is not permission to write.

    for parent, directories, files in os.walk(root, followlinks=False, onerror=failed):
        directories[:] = [name for name in directories
                          if not (Path(parent) == root and name in excluded)
                          and not (Path(parent) / name).is_symlink()]
        total += sum((Path(parent) / name).stat().st_size for name in files
                     if not (Path(parent) / name).is_symlink())
    return total


def space_requirements(root: Path, work: Path, estimate: dict, *, device=None, include_drill=True) -> dict:
    """Capture uses its own volume; only explicit drills need expanded DBs."""
    if include_drill is False:
        return {root: estimate['capture_bytes']}
    device = device or (lambda path: existing_parent(path).stat().st_dev)
    copies = estimate['backup_bytes'] + estimate['drill_copy_bytes']
    if device(root) == device(work):
        return {root: copies + estimate['work_bytes']}
    return {root: copies, work: estimate['work_bytes']}


def retention_settings(daily: int | None = None) -> tuple[int, int]:
    try:
        daily = int(os.environ.get("SLI_BACKUP_RETENTION", "7")) if daily is None else daily
        weekly = int(os.environ.get("SLI_BACKUP_WEEKLY_RETENTION", "4"))
        if daily < 1 or weekly < 0:
            raise ValueError
        return daily, weekly
    except (TypeError, ValueError):
        raise ValueError("linux_backup_invalid_retention") from None


def retained_sets(paths: list[Path], daily: int, weekly: int) -> set[Path]:
    """One latest set per UTC day/week; weekly slots are completed ISO weeks."""
    days, weeks = {}, {}
    paths = sorted(paths)
    if not paths:
        return set()
    current_week = datetime.strptime(paths[-1].name, "%Y%m%dT%H%M%S.%fZ").replace(tzinfo=timezone.utc).isocalendar()[:2]
    for path in paths:
        stamp = datetime.strptime(path.name, "%Y%m%dT%H%M%S.%fZ").replace(tzinfo=timezone.utc)
        days[stamp.date()] = path
        week = stamp.isocalendar()[:2]
        if week != current_week:
            weeks[week] = path
    return set(list(days.values())[-daily:]) | (set(list(weeks.values())[-weekly:]) if weekly else set())


def existing_parent(path: Path) -> Path:
    if not path.is_absolute() or path != path.resolve() or path == Path(path.anchor):
        raise ValueError("linux_backup_invalid_settings")
    while not path.exists():
        path = path.parent
    if not path.is_dir():
        raise ValueError("linux_backup_invalid_settings")
    return path


def device(path: Path) -> int:
    """Device of an existing directory or the nearest existing parent."""
    return existing_parent(path).stat().st_dev


def filesystem(path: Path) -> str:
    # GNU stat -f %i (the host witness) uses the hexadecimal statvfs fsid.
    return format(os.statvfs(existing_parent(path)).f_fsid, "x")


def work_root(root: Path) -> Path:
    return Path(os.environ.get("SLI_RESTORE_CHECK_ROOT", str(root / ".restore-check")))


def volume_admission(root: Path, work: Path, data_filesystems: dict, required: int,
                     *, work_required: int | None = None) -> dict:
    return _volume_admission(root, work, data_filesystems, required, local_copy=False, work_required=work_required)


def local_copy_admission(root: Path, work: Path, data_filesystems: dict, required: int,
                         *, work_required: int | None = None) -> dict:
    """Beta local copies only; never used to authorize restoration to live data."""
    return _volume_admission(root, work, data_filesystems, required, local_copy=True, work_required=work_required)


def _volume_admission(root: Path, work: Path, data_filesystems: dict, required: int, *, local_copy: bool,
                      work_required: int | None = None) -> dict:
    """No mkdir, chmod, database creation or cleanup before admission."""
    backup_device, work_device = filesystem(root), filesystem(work)
    devices = {item["device"] for item in data_filesystems.values()}
    colocated = backup_device in devices or work_device in devices
    if (work_required is None and backup_device != work_device or colocated and not local_copy
            or filesystem(work / 'clickhouse') != work_device):
        return {"status": "skipped", "reason": "restore_volume_mismatch"}
    data_role = min(data_filesystems, key=lambda role: data_filesystems[role]['free_bytes'])
    data_free = data_filesystems[data_role]['free_bytes']
    free = shutil.disk_usage(existing_parent(root)).free
    if data_free < DATA_RESERVE:
        return {"status": "skipped", "reason": "insufficient_data_disk_space",
                "required_bytes": DATA_RESERVE, "free_bytes": data_free,
                "volume": data_role + ':' + str(data_filesystems[data_role]['device'])}
    if work_required is not None:
        volumes = [(root, backup_device, required), (work, work_device, work_required)]
        if backup_device == work_device:
            volumes = [(root, backup_device, required + work_required)]
        for path, identity, needed in volumes:
            available = shutil.disk_usage(existing_parent(path)).free
            if identity in devices:
                needed += DATA_RESERVE  # One GiB of growth per live-data volume.
                available = min(available, min(item['free_bytes'] for item in data_filesystems.values()
                                                if item['device'] == identity))
            if available < needed:
                return {'status': 'skipped', 'reason': 'insufficient_backup_disk_space',
                        'required_bytes': needed, 'free_bytes': available, 'volume': str(path)}
        return {'status': 'admitted', 'required_bytes': required + work_required, 'free_bytes': free,
                'volume': str(root)}
    if colocated:
        required += DATA_RESERVE
        free = min(free, data_free)
    if free < required:
        return {"status": "skipped", "reason": "insufficient_backup_disk_space",
                "required_bytes": required, "free_bytes": free, "volume": str(root)}
    return {"status": "admitted", "required_bytes": required, "free_bytes": free, "volume": str(root)}


def capacity_days(free: int, sizes: list[int], reserve: int = GIB) -> int | None:
    """Conservative runway at one full set/day, without promising future deletion."""
    sizes = [size for size in sizes[-7:] if type(size) is int and size > 0]
    return max(0, free - reserve) // max(sizes) if sizes else None


def report_refusal(admission: dict) -> None:
    messages = {
        "restore_volume_mismatch": "Проверка требует том копий — исправьте путь / Restore check requires backup volume; correct the path",
        "insufficient_backup_disk_space": "На томе копий мало места — освободите место / Backup volume low on space; free space",
        "insufficient_data_disk_space": "На томе данных мало места — освободите место / Data volume low on space; free space",
    }
    detail = ''
    if 'required_bytes' in admission and 'free_bytes' in admission:
        detail = (f"; том / volume={admission.get('volume', 'unknown')}; "
                  f"нужно / required={admission['required_bytes']} bytes "
                  f"({admission['required_bytes'] / GIB:.2f} GiB); "
                  f"свободно / free={admission['free_bytes']} bytes "
                  f"({admission['free_bytes'] / GIB:.2f} GiB)")
        if admission['reason'] != 'insufficient_data_disk_space':
            detail += '; удалите старые наборы копий / remove old backup sets'
    print(messages.get(admission["reason"], "Проверка отложена / Restore check deferred")
          + " [" + admission["reason"] + "]" + detail, flush=True)
