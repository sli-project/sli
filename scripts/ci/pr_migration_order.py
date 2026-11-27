"""Reject added PostgreSQL migration files at or below the live base version."""

import argparse
import re
import subprocess
import sys


MIGRATIONS = "config/postgres_migrations/"
MIGRATION = re.compile(rb"config/postgres_migrations/([0-9]+)_[a-z0-9_]+(?:\.rollback)?\.sql")


def git_paths(*args: str) -> list[bytes]:
    return subprocess.check_output(["git", *args, "--", MIGRATIONS]).split(b"\0")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", help="Base commit from the PR or merge group event")
    parser.add_argument("head", help="PR or merge group head commit")
    parser.add_argument("live_base", help="Current tip of the base branch")
    args = parser.parse_args()

    base_paths = git_paths("ls-tree", "-r", "--name-only", "-z", args.live_base)
    maximum = max((int(match[1]) for path in base_paths
                   if not path.endswith((b".rollback.sql", b"_rollback.sql"))
                   and (match := MIGRATION.fullmatch(path))), default=0)
    # Keep the event's diff separate from the live base inventory. Disable rename
    # detection so a new version created by renaming a migration is checked too.
    added = git_paths("diff", "--name-only", "--no-renames", "--diff-filter=A", "-z",
                      f"{args.base}...{args.head}")
    rejected = [path.decode("ascii") for path in added
                if (match := MIGRATION.fullmatch(path)) and int(match[1]) <= maximum]
    for path in rejected:
        print(f"{path} must have a version greater than the current base maximum ({maximum})", file=sys.stderr)
    return int(bool(rejected))


if __name__ == "__main__":
    raise SystemExit(main())
