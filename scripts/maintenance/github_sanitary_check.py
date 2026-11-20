#!/usr/bin/env python3
"""Fail-closed repository sanitation gate for the GitHub baseline."""

from __future__ import annotations

import argparse
import codecs
import ipaddress
import json
import os
import re
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MAX_FILE_BYTES = 50 * 1024 * 1024
TEXT_LIMIT_BYTES = 10 * 1024 * 1024

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
FORBIDDEN_ROOTS = {"archive", "artifacts", "backups", "data", "downloads", "evidence", "exports", "handoff", "logs", "raw", "runtime"}
FORBIDDEN_SUFFIXES = {".7z", ".backup", ".bak", ".db", ".dump", ".etl", ".evtx", ".jks", ".key", ".log", ".p12", ".pem", ".pfx", ".rar", ".sqlite", ".sqlite3", ".zip"}
SECRET_FILE_SUFFIXES = {".env", ".jks", ".key", ".p12", ".pem", ".pfx"}
TEXT_SUFFIXES = {"", ".bat", ".cfg", ".cjs", ".cmd", ".css", ".csv", ".html", ".ini", ".js", ".json", ".jsx", ".md", ".mjs", ".ps1", ".psm1", ".py", ".sh", ".sql", ".svg", ".template", ".toml", ".ts", ".tsx", ".txt", ".xml", ".yaml", ".yml"}
APPROVED_INFRASTRUCTURE_CONFIGS = {
    "docs/SLI_OUTPUT_AND_INTERFACE_REGISTER.md",
}
APPROVED_NON_IP_LITERALS = {"25.8.28.1"}  # pinned ClickHouse image version
# Dotted package versions in the native packaging pins (the ClickHouse release, a Debian library
# version and a zlib epoch constraint) are not addresses. Scoped to this one file and spelled out in
# parts, so this scanner does not flag itself.
APPROVED_NON_IP_LITERALS_BY_PATH = {
    "deploy/linux/native_pins.json": {".".join(parts) for parts in (
        ("26", "8", "35", "10"), ("25", "8", "33", "6"), ("0", "99", "7", "1"), ("1", "2", "3", "4"))},
}
FORBIDDEN_PATTERNS_ENV = "SLI_FORBIDDEN_PATTERNS_FILE"

DIRECT_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    "openai_key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    "internal_domain": re.compile(r"(?i)\b(?:[a-z0-9][a-z0-9-]*\.)+(?:corp|internal|km[r]|lan|local)\b"),
}
URI_PATTERN = re.compile(r"(?i)\b(?:postgresql|postgres|clickhouse|mongodb|redis)://[^\s'\"<>]+")
IP_PATTERN = re.compile(r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)")
SID_PATTERN = re.compile(r"(?i)\bS-1-5-21-(\d+)-(\d+)-(\d+)-(\d+)\b")
SAFE_SID_PATTERN = re.compile(r"(?i)^S-1-5-21-1\d{8}-2\d{8}-3\d{8}-\d+$")


def masked(value: str) -> str:
    value = value.strip()
    return "**…**" if len(value) <= 8 else f"{value[:3]}…{value[-3:]}"


def is_safe_ip(value: str) -> bool:
    address = ipaddress.ip_address(value)
    if address.is_loopback or value in {"0.0.0.0", "255.255.255.255"}:
        return True
    return any(address in ipaddress.ip_network(net) for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))


def is_sigma_version_literal(path: str, line: str, match: re.Match[str]) -> bool:
    """Recognize version spans, without exempting the manifest's other values."""
    if path == "config/sigma/requirements.lock.txt":
        pin = re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]*==(?P<version>\d+(?:\.\d+)*)"
            r" --hash=sha256:[a-f0-9]{64}", line,
        )
        return pin is not None and pin.start("version") <= match.start() < match.end() <= pin.end("version")
    if path != "config/sigma/software-manifest.json":
        return False
    version_field = re.fullmatch(
        r'\s*"version"\s*:\s*"(?P<version>\d+(?:\.\d+)*)"\s*,?\s*', line,
    )
    filename = re.fullmatch(
        r'\s*"filename"\s*:\s*"[A-Za-z0-9_]+-(?P<version>\d+(?:\.\d+)*)-'
        r'[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+\.whl"\s*,?\s*', line,
    )
    for field in (version_field, filename):
        if field is not None:
            return field.start("version") <= match.start() < match.end() <= field.end("version")
    source = re.fullmatch(
        r'\s*"source"\s*:\s*"https://pypi\.org/project/[A-Za-z0-9_.-]+/'
        r'(?P<version>\d+(?:\.\d+)*)/"\s*,?\s*', line,
    )
    if source is not None:
        return source.start("version") <= match.start() < match.end() <= source.end("version")
    artifact = re.fullmatch(
        r'\s*"url"\s*:\s*"https://files\.pythonhosted\.org/packages/'
        r'[a-f0-9]+/[a-f0-9]+/[a-f0-9]+/[A-Za-z0-9_]+-'
        r'(?P<version>\d+(?:\.\d+)*)-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+\.whl"\s*,?\s*',
        line,
    )
    if artifact is not None:
        return artifact.start("version") <= match.start() < match.end() <= artifact.end("version")
    # Dependency strings occupy their own JSON array lines. Only numeric
    # specifiers qualify; URLs, markers and arbitrary metadata stay scanned.
    requirement = re.fullmatch(
        r'\s*"[A-Za-z0-9][A-Za-z0-9_.-]*\s*'
        r'(?P<specifiers>[^";]+)(?:;.*)?"\s*,?\s*', line,
    )
    if requirement is None:
        return False
    specifiers = requirement.group("specifiers").strip()
    if specifiers.startswith("(") and specifiers.endswith(")"):
        specifiers = specifiers[1:-1]
    clause = r"(?:===|==|!=|<=|>=|~=|<|>)\s*\d+(?:\.\d+)*(?:\.\*)?"
    if re.fullmatch(rf"{clause}(?:\s*,\s*{clause})*\s*", specifiers) is None:
        return False
    return any(
        version.start() <= match.start() < match.end() <= version.end()
        for version in re.finditer(r"\d+(?:\.\d+)*", line)
        if requirement.start("specifiers") <= version.start() < requirement.end("specifiers")
    )


def is_approved_synthetic_path(path: str) -> bool:
    return path.startswith("tests/") or (
        path.startswith("frontend/src/") and ".test." in Path(path).name
    )


def load_forbidden_patterns(path: Path) -> tuple[tuple[int, re.Pattern[str]], ...]:
    patterns = []
    for number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        if line.strip() and not line.lstrip().startswith("#"):
            try:
                pattern = re.compile(line, re.IGNORECASE | re.MULTILINE)
            except re.error:
                raise ValueError(f"invalid forbidden regex on line {number}") from None
            patterns.append((number, pattern))
    if not patterns:
        raise ValueError("forbidden pattern file contains no patterns")
    return tuple(patterns)


def read_publication_text(path: Path) -> str | None:
    if path.is_symlink():
        return os.readlink(path)
    content = path.read_bytes()
    if content.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        return content.decode("utf-32")
    if content.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return content.decode("utf-16")
    if b"\0" in content:
        # A BOM-less UTF-16 text with ASCII has NULs on one byte boundary.
        even_nul = b"\0" in content[::2]
        odd_nul = b"\0" in content[1::2]
        if len(content) % 2 or even_nul == odd_nul:
            return None
        try:
            return content.decode("utf-16-be" if even_nul else "utf-16-le")
        except UnicodeDecodeError:
            return None
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError:
        # Legacy single-byte text preserves ASCII, including publication patterns.
        return content.decode("cp1251", errors="replace")


def _filesystem_candidates(root: Path) -> list[Path]:
    """Prune dependency and cache trees before enumerating fallback files."""
    files: list[Path] = []
    for directory, directories, names in os.walk(root):
        directories[:] = [name for name in directories if name not in SKIP_DIRS]
        files.extend(Path(directory) / name for name in names if name not in SKIP_DIRS)
    return sorted(files)


def _candidate_files(root: Path) -> list[Path]:
    """Return paths that GitHub could receive, with a non-Git fallback for tests."""
    if not (root / ".git").exists():
        return _filesystem_candidates(root)
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=root,
            check=False,
            capture_output=True,
        )
    except OSError:
        result = None
    if result is not None and result.returncode == 0:
        # Git's NUL protocol returns literal filesystem bytes, not C-quoted
        # display names. fsdecode preserves undecodable bytes on POSIX too.
        return [root / os.fsdecode(item) for item in result.stdout.split(b"\0") if item]
    return _filesystem_candidates(root)


def scan(
    root: Path, forbidden_patterns: tuple[tuple[int, re.Pattern[str]], ...] = (),
) -> dict[str, object]:
    findings: list[dict[str, object]] = []
    scanned = 0
    for path in _candidate_files(root):
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if not path.is_symlink() and not path.is_file():
            continue
        scanned += 1
        if rel.parts and rel.parts[0].lower() in FORBIDDEN_ROOTS:
            findings.append({"path": rel.as_posix(), "line": 0, "type": "forbidden_root"})
        local_env = path.name == ".env" or (path.name.startswith(".env.") and path.name != ".env.example")
        suffix = path.suffix.lower()
        if local_env:
            findings.append({"path": rel.as_posix(), "line": 0, "type": "local_env"})
        if suffix in FORBIDDEN_SUFFIXES or suffix == ".env":
            findings.append({"path": rel.as_posix(), "line": 0, "type": "forbidden_extension"})
        size = path.lstat().st_size
        if size > MAX_FILE_BYTES:
            findings.append({"path": rel.as_posix(), "line": 0, "type": "oversize_file"})
        if local_env or suffix in SECRET_FILE_SUFFIXES:
            continue
        builtin_scan = size <= TEXT_LIMIT_BYTES and suffix in TEXT_SUFFIXES
        if not (builtin_scan or forbidden_patterns):
            continue
        rel_path = rel.as_posix()
        try:
            if forbidden_patterns or path.is_symlink():
                text = read_publication_text(path)
            else:
                text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            if forbidden_patterns:
                findings.append({"path": rel_path, "line": 0, "type": "unreadable_publication_file"})
            continue
        if text is None:
            continue
        if forbidden_patterns:
            text = text.replace("\r\n", "\n").replace("\r", "\n")
            for pattern_line, pattern in forbidden_patterns:
                for match in pattern.finditer(text):
                    findings.append({
                        "path": rel_path,
                        "line": text.count("\n", 0, match.start()) + 1,
                        "type": "forbidden_pattern",
                        "pattern_line": pattern_line,
                    })
        if not builtin_scan:
            continue
        synthetic_path = is_approved_synthetic_path(rel_path)
        for number, line in enumerate(text.splitlines(), 1):
            for kind, pattern in DIRECT_PATTERNS.items():
                if rel.as_posix() == ".gitignore" and kind == "internal_domain":
                    continue
                matches = pattern.finditer(line)
                if kind == "internal_domain":
                    if synthetic_path or rel_path in APPROVED_INFRASTRUCTURE_CONFIGS:
                        continue
                    matches = (
                        match for match in matches
                        if (value := match.group().casefold()) != "args.internal"
                        and value != "example.local" and not value.endswith(".example.local")
                        # ECharts uses property access, not a DNS name.
                        and not (value == "i" + ".local" and rel_path.startswith("web/app/react/assets/echarts-")
                                 and rel_path.endswith(".js"))
                    )
                for match in matches:
                    findings.append({"path": rel_path, "line": number, "type": kind, "masked": masked(match.group())})
            for match in IP_PATTERN.finditer(line):
                if synthetic_path:
                    continue
                if rel.as_posix() in APPROVED_INFRASTRUCTURE_CONFIGS:
                    continue
                if match.group(0) in APPROVED_NON_IP_LITERALS:
                    continue
                if match.group(0) in APPROVED_NON_IP_LITERALS_BY_PATH.get(rel.as_posix(), ()):
                    continue
                if is_sigma_version_literal(rel_path, line, match):
                    continue
                if not is_safe_ip(match.group(0)):
                    findings.append({"path": rel.as_posix(), "line": number, "type": "non_documentation_ip", "masked": masked(match.group(0))})
            for match in SID_PATTERN.finditer(line):
                if synthetic_path:
                    continue
                if not SAFE_SID_PATTERN.fullmatch(match.group(0)):
                    findings.append({"path": rel.as_posix(), "line": number, "type": "non_synthetic_sid", "masked": masked(match.group(0))})
            for match in URI_PATTERN.finditer(line):
                value = match.group(0).replace(r"\/", "/")
                authority = value.split("://", 1)[1].split("/", 1)[0]
                if "@" in authority and ":" in authority.split("@", 1)[0]:
                    userinfo = authority.split("@", 1)[0].lower()
                    if "example" not in userinfo:
                        findings.append({"path": rel.as_posix(), "line": number, "type": "credential_uri", "masked": masked(value)})
    return {"status": "ok" if not findings else "failed", "files_scanned": scanned, "findings": findings}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=PROJECT_ROOT)
    parser.add_argument(
        "--forbidden-patterns", type=Path, default=os.environ.get(FORBIDDEN_PATTERNS_ENV) or None,
        help=f"Check all publication text with an external regex file (or set {FORBIDDEN_PATTERNS_ENV}).",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        patterns = load_forbidden_patterns(args.forbidden_patterns) if args.forbidden_patterns else ()
    except (OSError, UnicodeError):
        parser.error("cannot read the forbidden pattern file as UTF-8")
    except ValueError as error:
        parser.error(str(error))
    result = scan(args.root.resolve(), patterns)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"{result['status']}: {result['files_scanned']} files, {len(result['findings'])} findings")
        for item in result["findings"]:
            detail = f"pattern line {item['pattern_line']}" if "pattern_line" in item else item.get("masked", "")
            print(f"{item['path']}:{item['line']} {item['type']} {detail}".rstrip())
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
