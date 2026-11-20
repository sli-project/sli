"""Read-only backup activity probe, also usable with older installed images."""
from __future__ import annotations

import json
from pathlib import Path


def activity(root: Path) -> dict:
    import fcntl

    # The scheduled lock spans capture AND its restore drill. The capture lock
    # also covers manual jobs and older images which have no scheduled lock.
    for name in (".scheduled-backup.lock", ".backup.lock"):
        try:
            with (root / name).open("rb") as stream:
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return {"busy": True, "next_backup_at_utc": None}
        except FileNotFoundError:
            pass
    beat = json.loads((root / "heartbeat.json").read_bytes())
    if not isinstance(beat, dict) or beat.get("status") not in {"waiting", "running", "success", "failed"}:
        raise ValueError("backup_activity_unavailable")
    return {"busy": beat["status"] == "running", "next_backup_at_utc": beat.get("next_backup_at_utc")}


if __name__ == "__main__":
    print(json.dumps(activity(Path("/backups"))))
