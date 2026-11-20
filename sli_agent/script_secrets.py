"""Conservative literal-secret masking; never execute or decode PowerShell."""
from __future__ import annotations

import hashlib
import re

SCRIPT_BYTES = 8192
MASK_FAILED = "[скрыто:mask_failed]"


def bounded_utf8(value, limit):
    return value.encode("utf-8")[:limit].decode("utf-8", errors="ignore")


# Match contexts only. Literal endpoints are indexed once, without regex
# backtracking or repeatedly searching the remaining untrusted input.
_OPTIONS = r"(?:[ \t]+-(?:AsPlainText|Force)\b)*"
_PATTERNS = [
    ("password", "connection", re.compile(r'''(?i)(?<=[;'"\n])(?:Password|Pwd)[ \t]*=[ \t]*''')),
    ("password", "value", re.compile(r"(?i)(?<![\w-])-(?:Password|Pwd)\b[ \t]*:?[ \t]*")),
    ("credential", "value", re.compile(r"(?i)(?<![\w-])-Credential\b[ \t]*:?[ \t]*")),
    ("password", "value", re.compile(r'''(?i)\b(?:Password|Pwd)\b['"]?[ \t]*[=:][ \t]*''')),
    ("cloud_key", "value", re.compile(
        r'''(?i)\b(?:aws_secret_access_key|SecretAccessKey|AccountKey|client_secret|ClientSecret|SharedAccessKey)\b['"]?[ \t]*[=:][ \t]*''')),
    ("token", "value", re.compile(
        r'''(?i)\b(?:access_token|refresh_token|api_key|ApiKey|token)\b['"]?[ \t]*[=:][ \t]*''')),
    ("plaintext", "plain_after", re.compile(
        r"(?i)\bConvertTo-SecureString\b(?:[ \t]+-Force\b)*[ \t]+(?:-String[ \t]+)?")),
    ("plaintext", "value", re.compile(
        rf"(?i)\bConvertTo-SecureString\b(?:[ \t]+-Force\b)*[ \t]+-AsPlainText\b{_OPTIONS}[ \t]+(?:-String[ \t]+)?")),
]
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?P<label>(?:[A-Z0-9]+ )*PRIVATE KEY)-----"
    r"(?P<value>[\s\S]*?)(?=-----END (?P=label)-----|\Z)")
_AUTH = re.compile(r"(?i)\b(?P<kind>Basic|Bearer)[ \t]+(?P<value>[A-Za-z0-9+/_\-.=]+)(?![\w+/.=\-])")
_AWS = re.compile(r"\b(?P<value>AKIA[A-Z0-9]{16})\b")
_CMDLET = re.compile(r"[A-Za-z][A-Za-z0-9]*-[A-Za-z][A-Za-z0-9_-]*\Z")
_PIPE = re.compile(r"(?i)\|[ \t]*ConvertTo-SecureString\b")
_PLAIN = re.compile(r"(?i)-AsPlainText\b")


def _literal_index(text):
    """O(n) endpoint tables, including escaped and cut-off string literals."""
    n = len(text)
    single, double, bare, connection, values = ([n] * (n + 2) for _ in range(5))
    here = {"'": n, '"': n}
    quoted = {}
    for i in range(n - 1, -1, -1):
        c = text[i]
        single[i] = single[i + 2] if text.startswith("''", i) else i + 1 if c == "'" else single[i + 1]
        double[i] = double[i + 2] if c == "`" else i + 1 if c == '"' else double[i + 1]
        bare[i] = i if c.isspace() or c in ";'\"|,)}]&" else bare[i + 1]
        connection[i] = i if c in ";'\"\r\n" else connection[i + 1]
        if c in "'\"":
            values[i] = (single if c == "'" else double)[i + 1]
            quoted[values[i]] = i
        elif c == "@" and i + 2 < n and text[i + 1] in here and (
                text[i + 2] == "\n" or text.startswith("\r\n", i + 2)):
            values[i] = here[text[i + 1]]
            quoted[values[i]] = i
        else:
            values[i] = bare[i]
        for quote in here:
            if text.startswith("\n" + quote + "@", i):
                here[quote] = i + 3
    return values, bare, connection, quoted


def _mask(script):
    bounded = bounded_utf8(script, SCRIPT_BYTES)
    values, bare, connection, quoted = _literal_index(bounded)
    n = len(bounded)
    expression = [n] * (n + 1)
    for i in range(n - 1, -1, -1):
        expression[i] = i if bounded[i] in "$`(" else expression[i + 1]
    inside = bytearray(n)
    i = 0
    while i < n:
        if bounded[i] in "'\"" or bounded.startswith(("@'\n", '@"\n', "@'\r\n", '@"\r\n'), i):
            end = values[i]
            inside[i:end] = b"\1" * (end - i)
            i = end
        else:
            i += 1
    # Nearest -AsPlainText within each command segment, looked up in O(1).
    plain_starts = {m.start() for m in _PLAIN.finditer(bounded)}
    plain_after = [False] * (n + 1)
    for i in range(n - 1, -1, -1):
        plain_after[i] = i in plain_starts or bounded[i] not in ";\r\n|" and plain_after[i + 1]

    def literal(start, mode="value"):
        if start >= n:
            return start
        if bounded[start] in "'\"" or bounded.startswith(("@'\n", '@"\n', "@'\r\n", '@"\r\n'), start):
            return values[start]
        end = bare[start]
        if (end == start or bounded[start] in "$@(-[" or expression[start] < end
                or _CMDLET.fullmatch(bounded, start, end) and not (mode == "connection" and inside[start])):
            return start
        return connection[start] if mode == "connection" else end

    spans = []
    occupied = bytearray(n)

    def add(kind, start, end):
        if start >= end or occupied[start]:
            return
        value = bounded[start:end]
        prefix = suffix = ""
        if kind == "private_key":
            prefix = value[:len(value) - len(value.lstrip())]
            suffix = value[len(value.rstrip()):]
        elif value.startswith(("@'", '@"')):
            prefix = value[:2] + "\n"
            suffix = "\n" + value[1] + "@" if value.endswith(value[1] + "@") else ""
        elif value.startswith(("'", '"')):
            prefix = value[0]
            suffix = value[0] if len(value) > 1 and value.endswith(value[0]) else ""
        if not value or value.removeprefix(prefix).startswith("[скрыто:") or any(occupied[start:end]):
            return
        occupied[start:end] = b"\1" * (end - start)
        spans.append((start, end, f"{prefix}[скрыто:{kind}]{suffix}"))

    for match in _PRIVATE_KEY.finditer(bounded):
        add("private_key", *match.span("value"))
    for kind, mode, pattern in _PATTERNS:
        for match in pattern.finditer(bounded):
            start = match.end()
            if start < n and occupied[start]:
                continue
            end = literal(start, mode)
            if mode != "plain_after" or plain_after[end]:
                add(kind, start, end)
    for match in _AUTH.finditer(bounded):
        value = match.group("value")
        # A long base64/base64url/JWT-like value; ordinary prose is not a token.
        kind = match.group("kind").lower()
        core = value.rstrip("=")
        valid = len(value) - len(core) <= 2 and "=" not in core
        if kind == "basic":
            valid = valid and len(value) % 4 == 0 and not any(c in core for c in "-_.")
        else:
            valid = valid and ("." not in core or core.count(".") == 2 and all(core.split(".")))
        if valid and len(value) >= 16 and (len(value) >= 32 or any(c.isdigit() or c in "+/=." for c in value)
                                         or sum(c.isupper() for c in value) >= 3 and any(c.islower() for c in value)):
            add(kind, *match.span("value"))
    for match in _AWS.finditer(bounded):
        add("aws_access_key", *match.span("value"))
    for match in _PIPE.finditer(bounded):
        if not plain_after[match.end()]:
            continue
        end = match.start()
        while end and bounded[end - 1] in " \t":
            end -= 1
        start = quoted.get(end)
        if start is None:
            start = end
            while start and not bounded[start - 1].isspace():
                start -= 1
        if literal(start) == end:
            add("plaintext", start, end)
    pieces, previous = [], 0
    for start, end, replacement in sorted(spans):
        pieces.extend((bounded[previous:start], replacement))
        previous = end
    pieces.append(bounded[previous:])
    masked = "".join(pieces)
    result = bounded_utf8(masked, SCRIPT_BYTES)
    return result, len(spans), bounded != script or result != masked


def mask_script_secrets(script: str) -> tuple[str, int, bool]:
    """Keep the event on any masking failure; never return its native text."""
    try:
        return _mask(script)
    except Exception:
        raw = script.encode("utf-8", errors="replace")
        return f"{MASK_FAILED} bytes={len(raw)} sha256={hashlib.sha256(raw).hexdigest()}", 1, True
