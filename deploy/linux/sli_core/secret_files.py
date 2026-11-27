"""Read file-backed secrets without exporting them to the environment."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path


def secret_value(name: str, *, environ: Mapping[str, str] | None = None) -> str | None:
    """Support NAME_FILE, retaining NAME for existing installations.

    A configured file fails closed. Errors contain neither its path nor its
    contents. Only final line endings are removed; password spaces are kept.
    """
    source = os.environ if environ is None else environ
    file_key = f"{name}_FILE"
    if file_key not in source:
        return source.get(name) or None
    if source.get(name):
        raise ValueError(f"{name}: value and file are mutually exclusive")
    try:
        filename = source[file_key]
        if not filename:
            raise ValueError
        with Path(filename).open("rb") as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError
        value = raw.decode("utf-8").rstrip("\r\n")
        if not value or "\x00" in value:
            raise ValueError
    except (OSError, UnicodeError, ValueError):
        raise ValueError(f"{name}: secret file is unreadable or invalid") from None
    return value


def postgres_secret_parts(name: str) -> dict[str, str]:
    """Read a DSN and its separate password without exporting either value."""
    from psycopg.conninfo import conninfo_to_dict

    dsn = secret_value(name)
    if not dsn or not dsn.strip():
        return {}
    parts = conninfo_to_dict(dsn)
    password_name = name.removesuffix("_DSN") + "_PASSWORD"
    password = secret_value(password_name)
    if password is not None:
        if parts.get("password"):
            raise ValueError(f"{name}: DSN password and separate password are mutually exclusive")
        parts["password"] = password
    return parts
