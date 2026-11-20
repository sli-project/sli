"""Publish a bounded, public snapshot; never copy raw process or journal data."""
from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


def read(path: Path) -> str:
    try:
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            stream.seek(max(0, size - 2_000_000))
            raw = stream.read()
            try:
                data = raw.decode("utf-8")
            except UnicodeDecodeError:
                data = raw.decode("cp1251", errors="replace")
            return data if size <= 2_000_000 else data.partition("\n")[2]
    except OSError:
        return ""


def public_text(value: str) -> str:
    # Titles/report names only. Raw journals are classified below, never exported.
    value = re.sub(r"(?i)(?:bearer\s+\S+|(?:password|token|secret|api[_-]?key|пароль)\s*[:=]\s*\S+|gh[pousr]_\w+|github_pat_\w+)", "[…]", value)
    value = re.sub(r"(?:https?://\S+|[\w.+-]+@[\w.-]+|(?:[A-Za-z]:[/\\]|/)[\w/\\.:-]+|\b(?:[\w-]+\.)+[A-Za-z]{2,}\b)", "[…]", value)
    return " ".join(value.split())[:240]


def number(value: str) -> int | None:
    return int(value) if re.fullmatch(r"[0-9]{1,12}", value) else None


def link(value: str, pr: int | None) -> str | None:
    parsed = urlsplit(value)
    if (pr and parsed.scheme == "https" and parsed.netloc == "github.com"
            and not parsed.query and not parsed.fragment
            and re.fullmatch(r"/[\w.-]+/[\w.-]+/pull/" + str(pr), parsed.path)):
        return value
    return None


def log_code(line: str) -> str:
    if re.search(r"(?i)error|failed|failure|ошиб|rc=[1-9]", line):
        return "log.error"
    if re.search(r"(?i)restart|перезапуск|дерево заверш", line):
        return "log.restart"
    if re.search(r"(?i)merged|слит", line):
        return "log.merged"
    if re.search(r"(?i)updated_ready_200|обновлено", line):
        return "log.updated"
    if re.search(r"(?i)dispatch|запущен|started", line):
        return "log.started"
    if re.search(r"(?i)passed|success|rc=0|завершена", line):
        return "log.success"
    return "log.hidden"


def action_code(text: str) -> str:
    if "DRY-RUN" in text:
        return "action.dry"
    if "слит:" in text:
        return "action.merged"
    if "ERROR" in text:
        return "action.error"
    if "нужен человек" in text:
        return "action.human"
    if "уже выполняется" in text or "запущен" in text:
        return "action.repair"
    if "слот" in text:
        return "action.slot"
    return "action.wait"


def reports(path: Path) -> list[dict]:
    result = []
    for line in read(path).splitlines():
        cells = [cell.strip().strip("`") for cell in line.strip().strip("|").split("|")]
        if len(cells) < 3 or not re.fullmatch(r"[\d ,_]+", cells[1]):
            continue
        count = number(re.sub(r"[ ,_]", "", cells[1]))
        if count is not None:
            result.append({"title": public_text(cells[0]), "rows": count,
                           "freshness": public_text(cells[2])})
    return result


def generate(home: Path, work: Path, update: Path, report: Path, now: int,
             dry: bool, result: str) -> dict:
    status = read(home / "STATUS.md")
    try:
        metadata = json.loads(read(work / "dashboard-prs.json") or "[]")
    except (ValueError, TypeError):
        metadata = []
    meta = {item["number"]: item for item in metadata
            if isinstance(item, dict) and isinstance(item.get("number"), int)} if isinstance(metadata, list) else {}
    attempts = {}
    for line in read(home / "attempts.tsv").splitlines():
        cells = line.split("\t")
        if len(cells) == 2 and number(cells[0]) and number(cells[1]) is not None:
            attempts[int(cells[0])] = int(cells[1])
    prs = []
    for line in read(work / "prs").splitlines():
        cells = line.split("\t")
        if len(cells) != 9 or not number(cells[0]):
            continue
        pr = int(cells[0]); info = meta.get(pr, {})
        ci = "unknown" if cells[5] == "0" else "running" if cells[6] != "true" else "red" if cells[8] == "true" else "green" if cells[7] == "true" else "unknown"
        action = next((row.rsplit("|", 2)[1] for row in status.splitlines()
                       if row.startswith(f"| #{pr} |")), "")
        prs.append({"number": pr, "title": public_text(str(info.get("title", ""))),
                    "url": link(str(info.get("url", "")), pr), "ci": ci,
                    "conflict": "yes" if cells[2] == "CONFLICTING" else "no" if cells[2] == "MERGEABLE" else "unknown",
                    "attempts": attempts.get(pr, 0), "action": action_code(action)})
    titles = {}
    queue = []
    for line in read(home / "queue.txt").splitlines():
        cells = line.split("|")
        if len(cells) == 4 and re.fullmatch(r"[\w-]+", cells[0]) and not cells[2]:
            titles[cells[0]] = public_text(cells[1])
            queue.append({"title": titles[cells[0]]})
    jobs = []
    for line in read(home / "state.tsv").splitlines():
        cells = line.split("\t")
        if len(cells) != 8 or not re.fullmatch(r"[\w-]+", cells[7]) or number(cells[6]) is None:
            continue
        key, name, kind, _, _, _, started, token = cells
        directory = home / "jobs" / token
        if read(directory / "result").strip():
            continue
        task = read(directory / "queue.txt").split("|")
        title = public_text(task[1]) if len(task) == 4 else titles.get(name, "")
        pr = number(key) or number(read(directory / "pr").strip())
        info = meta.get(pr, {})
        if not title:
            title = public_text(str(info.get("title", "")))
        journal = read(directory / "queue.log") if kind == "queue" else ""
        if not journal.strip():
            journal = read(home / "logs" / f"{token}.log")
        jobs.append({"title": title, "kind": kind if kind in ("ci_fix", "conflict_fix", "queue") else "queue",
                     "started_at": int(started), "pr": pr, "url": link(str(info.get("url", "")), pr),
                     "logs": [log_code(row) for row in journal.splitlines()[-12:]]})
    # Include external repairs found by the watchdog without publishing identities.
    for line in read(work / "processes").splitlines():
        cells = line.split("\t")
        if len(cells) < 5 or cells[0] not in ("ci_fix", "conflict_fix") or not number(cells[1]):
            continue
        pr = int(cells[1])
        if any(job["pr"] == pr for job in jobs):
            continue
        info = meta.get(pr, {})
        jobs.append({"title": public_text(str(info.get("title", ""))), "kind": cells[0],
                     "started_at": number(cells[4]), "pr": pr,
                     "url": link(str(info.get("url", "")), pr), "logs": []})
    events = []
    try:
        previous = json.loads(read(home / "dashboard/data.json") or "{}")
        for event in previous.get("history", [])[-30:]:
            if (isinstance(event, dict) and isinstance(event.get("time"), int)
                    and event.get("code") in ("log.error", "log.restart", "log.merged", "log.updated", "log.started", "log.pass")):
                events.append({"time": event["time"], "code": event["code"]})
    except (ValueError, TypeError, AttributeError):
        pass
    for path in (home / "logs" / "history.log", update / "history.log"):
        for line in read(path).splitlines()[-60:]:
            try:
                stamp = line.split(" mode=")[0] if " mode=" in line else line.split()[0]
                dt = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S %z") if " mode=" in line else datetime.fromisoformat(stamp)
                code = "log.error" if re.search(r"result=(?:failed|\w*error)", line) else "log.updated" if "updated_ready_200" in line else "log.pass"
                events.append({"time": int(dt.timestamp()), "code": code})
            except (ValueError, IndexError):
                continue
    for row in status.splitlines():
        code = log_code(row)
        if code in ("log.error", "log.restart", "log.merged", "log.started"):
            events.append({"time": now, "code": code})
    commit = read(update / "deployed.commit").strip()
    commit = commit if re.fullmatch(r"[0-9a-f]{40}", commit) else None
    deployed_pr = number(read(work / "dashboard-deployed-pr").strip())
    update_result = re.search(r"^Результат:\s*(\w+)", read(update / "LAST.md"), re.M)
    ready = "up" if "SLI ready: HTTP 200." in status else "down" if "ALERT: SLI ready HTTP" in status else "unknown"
    return {"schema_version": 1, "last_pass": now, "generated_at": int(datetime.now(timezone.utc).timestamp()),
            "dry_run": dry, "result": result if result in ("ok", "network_error", "github_error", "process_error", "state_error", "error") else "error",
            "network": "offline" if "Сеть: нет ответа (перезапустите VPN)" in status else "online" if "Сеть: доступна." in status else "unknown",
            "sli": {"health": ready, "commit": commit, "pr": deployed_pr,
                    "url": link(read(work / "dashboard-deployed-url").strip(), deployed_pr)},
            "update": "success" if update_result and update_result[1] == "verified" else "failed" if update_result and update_result[1] == "failed" else "unknown",
            "jobs": jobs, "queue": queue, "prs": prs, "prs_available": (work / "prs").is_file() and result != "github_error",
            "reports": reports(report), "reports_available": report.is_file(),
            "history": sorted({(item["time"], item["code"]): item for item in events}.values(),
                              key=lambda item: item["time"], reverse=True)[:30]}


def atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".data-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("home", "work", "update", "reports", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--now", type=int, required=True)
    parser.add_argument("--dry", choices=("0", "1"), required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args()
    atomic_write(args.output, generate(args.home, args.work, args.update, args.reports,
                                      args.now, args.dry == "1", args.result))


if __name__ == "__main__":
    main()
