#!/usr/bin/env python3
"""Run Claude edits in a disposable frontend copy and emit a guarded patch."""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import time
import uuid


ROOT = Path(__file__).resolve().parents[2]
TMP_ROOT = (ROOT / "data" / "tmp").resolve()
ARTIFACT_ROOT = (ROOT / "artifacts" / "claude").resolve()
MUTABLE_ROOT = "frontend/src"
COPY_ENTRIES = (
    "frontend/src",
    "frontend/README.md",
    "frontend/package.json",
    "frontend/tsconfig.json",
    "frontend/tsconfig.app.json",
    "frontend/vite.config.ts",
    "AGENTS.md",
    "PROJECT_RULES.md",
)
IMMUTABLE_PREFIXES = tuple(item for item in COPY_ENTRIES if item != MUTABLE_ROOT)
REPARSE_POINT = 0x400


def _relative(path: Path, base: Path) -> str:
    return path.relative_to(base).as_posix()


def _is_reparse(path: Path) -> bool:
    return bool(getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0) & REPARSE_POINT)


def _walk_files(base: Path) -> list[Path]:
    files: list[Path] = []
    for current, directories, names in os.walk(base, followlinks=False):
        current_path = Path(current)
        for name in [*directories, *names]:
            item = current_path / name
            if item.is_symlink() or _is_reparse(item):
                raise RuntimeError(f"candidate_reparse_point_forbidden:{_relative(item, base)}")
        files.extend(current_path / name for name in names)
    return sorted(files)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _snapshot(base: Path) -> dict[str, str]:
    return {_relative(path, base): _sha256(path) for path in _walk_files(base)}


def _manifest_hash(snapshot: dict[str, str]) -> str:
    digest = hashlib.sha256()
    for path, value in sorted(snapshot.items()):
        digest.update(path.encode("utf-8") + b"\0" + value.encode("ascii") + b"\n")
    return digest.hexdigest()


def _normalize_scope(raw: str) -> str:
    value = raw.replace("\\", "/").strip().strip("/")
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts:
        raise ValueError("candidate_may_touch_invalid")
    normalized = path.as_posix()
    if normalized != MUTABLE_ROOT and not normalized.startswith(MUTABLE_ROOT + "/"):
        raise ValueError("candidate_may_touch_outside_frontend_src")
    return normalized


def _under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix + "/")


def _copy_workspace(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    for relative in COPY_ENTRIES:
        source = ROOT / relative
        if not source.exists():
            raise FileNotFoundError(f"candidate_input_missing:{relative}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            _walk_files(source)
            shutil.copytree(source, target)
        else:
            if source.is_symlink() or _is_reparse(source):
                raise RuntimeError(f"candidate_input_reparse_forbidden:{relative}")
            shutil.copy2(source, target)


def _guard(before: dict[str, str], after: dict[str, str], scopes: tuple[str, ...]) -> dict[str, list[str]]:
    changed = sorted(path for path in before.keys() | after.keys() if before.get(path) != after.get(path))
    violations: list[str] = []
    accepted: list[str] = []
    for path in changed:
        immutable = any(_under(path, prefix) for prefix in IMMUTABLE_PREFIXES)
        allowed = any(_under(path, scope) for scope in scopes)
        if immutable or not allowed:
            violations.append(path)
        else:
            accepted.append(path)
    return {"changed": changed, "accepted": accepted, "violations": violations}


def _text(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        return path.read_text(encoding="utf-8").splitlines(keepends=True)
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"candidate_binary_change_forbidden:{path.name}") from exc


def _patch(workspace: Path, changed: list[str]) -> str:
    sections: list[str] = []
    for relative in changed:
        before = _text(ROOT / relative)
        after = _text(workspace / relative)
        sections.extend(difflib.unified_diff(
            before,
            after,
            fromfile=f"a/{relative}",
            tofile=f"b/{relative}",
        ))
    return "".join(sections)


def _claude_executable() -> Path:
    candidate = shutil.which("claude.exe")
    if not candidate:
        local = os.environ.get("LOCALAPPDATA")
        candidate = str(Path(local) / "Microsoft" / "WinGet" / "Links" / "claude.exe") if local else ""
    path = Path(candidate).resolve(strict=True) if candidate else None
    if path is None or not path.is_file():
        raise FileNotFoundError("claude_cli_not_found")
    return path


def _safe_environment() -> dict[str, str]:
    allowed = {
        "APPDATA", "COMSPEC", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA",
        "PATH", "PATHEXT", "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "TMP",
        "USERPROFILE", "WINDIR",
    }
    return {key: value for key, value in os.environ.items() if key.upper() in allowed and value}


def _run_claude(workspace: Path, task: str, scopes: tuple[str, ...], args: argparse.Namespace) -> dict[str, object]:
    prompt = (
        "You are editing a disposable SLI frontend candidate, not the working repository.\n"
        f"Edit only these relative paths: {', '.join(scopes)}.\n"
        "Do not edit immutable configs, reference files, rules, or files outside those paths. "
        "Do not execute commands, tests, builds, Git, network tools, MCP tools, or runtime actions.\n"
        "Return a compact summary; the wrapper will independently refuse every out-of-scope change.\n\n"
        + task
    )
    command = [
        str(_claude_executable()), "--print", "--output-format", "json",
        "--model", args.model, "--effort", args.effort,
        "--max-budget-usd", f"{args.budget_usd:.2f}",
        "--permission-mode", "acceptEdits", "--no-session-persistence",
        "--disable-slash-commands", "--setting-sources", "user",
        "--allowedTools", "Read,Glob,Grep,Edit,Write",
        "--disallowedTools", "Bash,NotebookEdit,WebFetch,WebSearch",
    ]
    completed = subprocess.run(
        command,
        cwd=workspace,
        env=_safe_environment(),
        input=prompt,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=args.timeout_seconds,
    )
    return {
        "exit_code": completed.returncode,
        "stdout_tail": completed.stdout[-4000:],
        "stderr_tail": completed.stderr[-2000:],
    }


def _result_path(raw: str, task_file: Path) -> Path:
    if raw:
        path = Path(raw)
        path = path if path.is_absolute() else ROOT / path
    else:
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        path = ARTIFACT_ROOT / f"frontend-candidate-{task_file.stem}-{stamp}.json"
    path = path.resolve()
    if path.parent != ARTIFACT_ROOT or path.suffix.lower() != ".json":
        raise ValueError("candidate_result_must_be_direct_artifacts_claude_json")
    return path


def _remove_workspace(workspace: Path) -> bool:
    resolved = workspace.resolve(strict=True)
    if resolved.parent != TMP_ROOT or not resolved.name.startswith("claude-frontend-candidate-"):
        raise RuntimeError("candidate_cleanup_target_invalid")
    shutil.rmtree(resolved)
    return not resolved.exists()


def _self_test() -> int:
    workspace = TMP_ROOT / f"claude-frontend-candidate-selftest-{uuid.uuid4().hex}"
    removed = False
    try:
        _copy_workspace(workspace)
        before = _snapshot(workspace)
        probe = workspace / MUTABLE_ROOT / "__guard_probe__.ts"
        probe.write_text("export const probe = true;\n", encoding="utf-8")
        immutable = workspace / "frontend" / "tsconfig.app.json"
        immutable.write_text(immutable.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        outcome = _guard(before, _snapshot(workspace), (MUTABLE_ROOT,))
        passed = outcome["accepted"] == [f"{MUTABLE_ROOT}/__guard_probe__.ts"] and outcome["violations"] == ["frontend/tsconfig.app.json"]
    finally:
        removed = _remove_workspace(workspace) if workspace.exists() else True
    print(json.dumps({"status": "passed" if passed and removed else "failed", "guard": outcome, "workspace_removed": removed}))
    return 0 if passed and removed else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-file", type=Path)
    parser.add_argument("--may-touch", action="append", default=[])
    parser.add_argument("--result", default="")
    parser.add_argument("--model", choices=("haiku", "sonnet"), default="sonnet")
    parser.add_argument("--effort", choices=("low", "medium"), default="low")
    parser.add_argument("--budget-usd", type=float, default=0.30)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--self-test-guard", action="store_true")
    args = parser.parse_args()
    TMP_ROOT.mkdir(parents=True, exist_ok=True)
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    if args.self_test_guard:
        return _self_test()
    if args.task_file is None or not args.may_touch:
        raise ValueError("candidate_task_and_may_touch_required")
    task_file = args.task_file.resolve(strict=True)
    if ROOT not in task_file.parents or task_file.stat().st_size > 20_000:
        raise ValueError("candidate_task_file_invalid")
    if not 0.05 <= args.budget_usd <= 0.50 or not 60 <= args.timeout_seconds <= 1800:
        raise ValueError("candidate_budget_or_timeout_invalid")
    scopes = tuple(sorted(set(_normalize_scope(item) for item in args.may_touch)))
    result_path = _result_path(args.result, task_file)
    workspace = TMP_ROOT / f"claude-frontend-candidate-{uuid.uuid4().hex}"
    evidence: dict[str, object] = {}
    removed = False
    try:
        _copy_workspace(workspace)
        before = _snapshot(workspace)
        run = _run_claude(workspace, task_file.read_text(encoding="utf-8"), scopes, args)
        after = _snapshot(workspace)
        guard = _guard(before, after, scopes)
        accepted = not guard["violations"] and run["exit_code"] == 0
        patch_path = result_path.with_suffix(".patch")
        if accepted:
            patch_path.write_text(_patch(workspace, guard["accepted"]), encoding="utf-8")
        else:
            patch_path.unlink(missing_ok=True)
        evidence = {
            "status": "accepted_candidate" if accepted else "refused_candidate",
            "workspace": str(workspace),
            "copied_entries": list(COPY_ENTRIES),
            "may_touch": list(scopes),
            "input_manifest_sha256": _manifest_hash(before),
            "guard": guard,
            "claude": run,
            "patch": str(patch_path) if accepted else None,
            "project_tree_changed": False,
            "tests_or_build_run": False,
            "tsc_run": False,
        }
    finally:
        removed = _remove_workspace(workspace) if workspace.exists() else True
    evidence["workspace_removed"] = removed
    if not removed:
        evidence["status"] = "cleanup_failed"
    result_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": evidence["status"], "result": str(result_path), "workspace_removed": removed}))
    return 0 if evidence["status"] == "accepted_candidate" else 2


if __name__ == "__main__":
    raise SystemExit(main())
