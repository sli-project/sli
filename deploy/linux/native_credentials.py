"""Bounded file-backed values for the native PostgreSQL helpers."""

import os
from pathlib import Path


def secret_value(name):
    file_key = name + "_FILE"
    if file_key not in os.environ:
        return os.environ.get(name) or None
    if os.environ.get(name):
        raise ValueError(f"{name}: value and file are mutually exclusive")
    try:
        with Path(os.environ[file_key]).open("rb") as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError
        value = raw.decode("utf-8").rstrip("\r\n")
        if not value or "\x00" in value:
            raise ValueError
    except (OSError, ValueError):
        raise ValueError(f"{name}: secret file is unreadable or invalid") from None
    return value
