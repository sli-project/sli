"""Run native database migration and restore commands."""

from __future__ import annotations

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("service", choices=("migrate", "restore"))
    args, remaining = parser.parse_known_args()
    from deploy.linux.migrate import migrate

    try:
        if args.service == "restore":
            from deploy.linux.restore_existing import main as restore

            return restore(remaining)
        migrate()
    except Exception as error:  # noqa: BLE001 - SQL errors can include private data
        from deploy.linux.operation_wait import OperationTimeout

        print(error.code if isinstance(error, OperationTimeout) else "linux_migration_failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
