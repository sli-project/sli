"""Local pipeline janitor and offline guard; never operate on application services."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path

QUEUE_KINDS = {"run_qmv3", "codex_task_v3"}
ROOT_KINDS = QUEUE_KINDS | {"watchdog", "ci_fix", "conflict_fix", "worker"}
NETWORK_KINDS = {"curl", "git", "gh"}
LOCK_TTLS = {"watchdog.lock": 1800, "heavy.lock": 2400, "update.lock": 43260}


def descendants(rows: list[dict], root: dict) -> list[dict]:
    found = {root["pid"]}
    result = []
    while True:
        children = [row for row in rows if row["pid"] not in found
                    and row["parent"] in found and row["started"] >= root["started"]]
        if not children:
            return result
        result.extend(children)
        found.update(row["pid"] for row in children)


def process_plan(rows: list[dict], now: int, orphan_since: dict,
                 guard: bool = False, known_scope: set[str] | None = None) -> tuple[list[dict], dict]:
    protected = set()
    for row in rows:
        if row["kind"] == "update":
            protected.update(item["pid"] for item in [row, *descendants(rows, row)])
    selected = {}
    observed = {}
    for row in rows:
        identity = f'{row["pid"]}:{row["ticks"]}'
        if (identity in (known_scope or set()) and (guard or row["kind"] in NETWORK_KINDS)
                and now - row["started"] > (900 if guard else 600) and row["pid"] not in protected):
            selected[row["pid"]] = row
    for root in rows:
        if root["kind"] not in ROOT_KINDS or root["pid"] in protected:
            continue
        children = descendants(rows, root)
        if guard:
            if root["kind"] != "watchdog":
                continue
            candidates = [root, *children]
            limit = 900
        else:
            candidates = [row for row in children if row["kind"] in NETWORK_KINDS]
            limit = 600
            if root["kind"] in QUEUE_KINDS:
                key = f'{root["pid"]}:{root["ticks"]}'
                if not any(row["kind"] == "codex" for row in children):
                    since = max(root["started"], min(now, orphan_since.get(key, now)))
                    observed[key] = since
                    if now - since > 1200:
                        # An active Codex anywhere below the wrapper always vetoes removal.
                        for row in [root, *children]:
                            if row["pid"] not in protected:
                                selected[row["pid"]] = row
        for row in candidates:
            if now - row["started"] > limit and row["pid"] not in protected:
                selected[row["pid"]] = row
    # Children first; individual termination never kills younger descendants implicitly.
    return sorted(selected.values(), key=lambda row: row["started"], reverse=True), observed


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def write_json(path: Path, value) -> None:
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value), encoding="utf-8")
    os.replace(temporary, path)


def stale_status(home: Path, now: int) -> bool:
    try:
        return now - (home / "STATUS.md").stat().st_mtime > 1200
    except FileNotFoundError:
        return True


def reclaim_lock(path: Path, ttl: int, now: int, owner_alive,
                 fallback_alive: bool = False, dry: bool = False) -> bool:
    """Only remove the known lock/owner files; never recursively delete a directory."""
    try:
        stamp = path.stat().st_mtime
        owner = path / "owner" if path.is_dir() else path
        text = owner.read_text(encoding="utf-8").strip() if owner.is_file() else ""
        fields = text.split()
        pid = int(fields[0]) if fields and fields[0].isdigit() else None
        if len(fields) > 1 and fields[1].isdigit():
            stamp = max(stamp, int(fields[1]))
        if now - stamp <= ttl or (pid and owner_alive(pid)) or (not pid and fallback_alive):
            return False
        if dry:
            return True
        # Recheck before mutation in case an owner published its identity meanwhile.
        if path.stat().st_mtime > stamp or (pid and owner_alive(pid)):
            return False
        if path.is_dir():
            if any(item.name != "owner" for item in path.iterdir()):
                return False
            owner.unlink(missing_ok=True)
            path.rmdir()
        else:
            path.unlink()
        return True
    except FileNotFoundError:
        return False


class Runtime:
    def __init__(self, home: Path, root: Path, bash: str):
        self.home, self.root, self.bash = home, root, bash

    def snapshot(self) -> list[dict]:
        output = subprocess.run([
            "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(self.root / "snapshot.ps1"), "-WatchdogRoot", str(self.root),
        ], capture_output=True, timeout=25, check=True)
        return json.loads(output.stdout.decode("utf-8-sig"))

    def owner_alive(self, pid: int) -> bool:
        try:
            result = subprocess.run([self.bash, "-c", 'kill -0 "$1" 2>/dev/null',
                                     "lock-owner", str(pid)], capture_output=True, timeout=10)
            return result.returncode != 1
        except (OSError, subprocess.TimeoutExpired):
            return True  # Unknown ownership must never authorize deletion.

    def stop(self, row: dict) -> None:
        subprocess.run([
            "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(self.root / "processes.ps1"), "-Mode", "stop",
            "-WinPid", str(row["pid"]), "-StartTicks", str(row["ticks"]),
        ], capture_output=True, timeout=25, check=True)

    def restart(self) -> None:
        subprocess.run(["schtasks.exe", "/Run", "/TN", "SLI Watchdog"],
                       capture_output=True, timeout=25, check=True)

    def log(self, text: str) -> None:
        path = self.home / "logs" / "guard.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as stream:
            stream.write(time.strftime("%Y-%m-%d %H:%M:%S %z") + " " + text + "\n")


def guard_pass(runtime: Runtime, now: int, dry: bool = False) -> str:
    home = runtime.home
    state_path = home / "guard-state.json"
    if not stale_status(home, now):
        if not dry:
            write_json(state_path, {"failures": 0, "restart": 0})
            runtime.log("fresh: no action")
        return "fresh"
    rows = runtime.snapshot()
    pending_path = home / "guard-processes.json"
    pending = set(read_json(pending_path, []))
    for root in rows:
        if root["kind"] == "watchdog":
            pending.update(f'{item["pid"]}:{item["ticks"]}'
                           for item in [root, *descendants(rows, root)])
    plan, _ = process_plan(rows, now, {}, guard=True, known_scope=pending)
    if dry:
        return f"DRY-RUN: stale status; stop={len(plan)}; restart planned"
    for row in plan:
        runtime.stop(row)
        runtime.log(f'stopped kind={row["kind"]} pid={row["pid"]}')
    remaining = runtime.snapshot()
    # Do not unlock or restart while a younger watchdog/child still owns this pass.
    still_pending = {f'{row["pid"]}:{row["ticks"]}' for row in remaining
                     if f'{row["pid"]}:{row["ticks"]}' in pending}
    write_json(pending_path, sorted(still_pending))
    if still_pending:
        runtime.log("deferred: live watchdog descendants remain")
        return "deferred"
    lock = home / "watchdog.lock"
    if lock.is_file():
        fields = lock.read_text(encoding="utf-8").split()
        if fields and fields[0].isdigit() and runtime.owner_alive(int(fields[0])):
            runtime.log("deferred: live lock owner")
            return "deferred"
        lock.unlink()
    directory = home / "watchdog.lock.guard"
    if directory.is_dir():
        directory.rmdir()
    state = read_json(state_path, {})
    # Count failed previous recoveries only after the status had time to become stale.
    failures = int(state.get("failures", 0)) + int(bool(state.get("restart")))
    if failures >= 2:
        (home / "ALERT.txt").write_text("ALERT: надзор дважды не восстановил сторожа.\n", encoding="utf-8")
    write_json(state_path, {"failures": failures, "restart": now})
    notice = "Надзор перезапустил сторожа: " + time.strftime("%Y-%m-%d %H:%M:%S %z") + ", устаревший STATUS.md"
    (home / "guard-notice.txt").write_text(notice + "\n", encoding="utf-8")
    runtime.restart()
    runtime.log("restart: stale STATUS.md")
    return "restarted"


def janitor_pass(runtime: Runtime, now: int, heavy: Path, update: Path,
                 dry: bool = False) -> list[str]:
    rows = runtime.snapshot()
    state_path = runtime.home / "orphan-since.json"
    scope_path = runtime.home / "scoped-processes.json"
    prior_scope = set(read_json(scope_path, []))
    plan, observed = process_plan(rows, now, read_json(state_path, {}), known_scope=prior_scope)
    # Keep identities of observed pipeline clients even if their parent later exits.
    scoped = {f'{row["pid"]}:{row["ticks"]}' for row in rows
              if f'{row["pid"]}:{row["ticks"]}' in prior_scope}
    for root in rows:
        if root["kind"] in ROOT_KINDS:
            scoped.update(f'{row["pid"]}:{row["ticks"]}' for row in descendants(rows, root)
                          if row["kind"] in NETWORK_KINDS)
    for root in rows:
        if root["kind"] == "update":
            scoped.difference_update(f'{row["pid"]}:{row["ticks"]}'
                                     for row in [root, *descendants(rows, root)])
    notes = []
    for row in plan:
        if not dry:
            runtime.stop(row)
        notes.append(f'Уборщик: {"DRY-RUN " if dry else ""}остановка {row["kind"]}, PID {row["pid"]}.')
    if not dry:
        write_json(state_path, observed)
        write_json(scope_path, sorted(scoped))
        rows = runtime.snapshot()
    locks = [(runtime.home / "watchdog.lock", "watchdog"),
             (heavy / "heavy.lock", "queue"), (update / "update.lock", "update")]
    for path, kind in locks:
        alive = any(row["kind"] in QUEUE_KINDS and Path(row.get("directory", "")) == heavy
                    if kind == "queue" else row["kind"] == kind for row in rows)
        if reclaim_lock(path, LOCK_TTLS[path.name], now, runtime.owner_alive, alive, dry):
            notes.append(f'Уборщик: {"DRY-RUN " if dry else ""}снята блокировка {path.name}.')
            if path.name == "watchdog.lock" and not dry:
                companion = path.with_name("watchdog.lock.guard")
                if companion.is_dir():
                    companion.rmdir()
    return notes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("guard", "janitor"))
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--bash", required=True)
    parser.add_argument("--heavy", type=Path)
    parser.add_argument("--update", type=Path)
    parser.add_argument("--dry", action="store_true")
    args = parser.parse_args()
    runtime = Runtime(args.home, args.root, args.bash)
    try:
        now = int(time.time())
        if args.mode == "guard":
            print(guard_pass(runtime, now, args.dry))
        else:
            if args.heavy is None or args.update is None:
                parser.error("janitor requires --heavy and --update")
            for note in janitor_pass(runtime, now, args.heavy, args.update, args.dry):
                print(note)
        return 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        # Raw command lines/exception output can contain credentials; only a safe code.
        runtime.log(f"{args.mode}: failed; no new work authorized")
        print("ERROR: уборщик/надзор не завершён; запуск новых задач заблокирован.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
