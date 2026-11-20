"""Discover forward SQL files independently of the bootstrap's SQL marker parser."""
import re
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "config/postgres_migrations"
# Older releases have gaps and forward-only scripts. From 299 onward every
# migration has a production rollback; unused version numbers are allowed.
REVERSIBLE_CHAIN_START = 299


def migration_inventory(directory: Path = MIGRATIONS_DIR, *, starting_at: int = 0) -> list[tuple[int, str]]:
    migrations = []
    for path in directory.glob("*.sql"):
        match = re.fullmatch(r"(\d+)_([a-z0-9_]+)\.sql", path.name)
        if match is None or match[2].endswith("_rollback"):
            continue
        version = int(match[1])
        if version >= starting_at:
            migrations.append((version, match[2]))
    return sorted(migrations)
