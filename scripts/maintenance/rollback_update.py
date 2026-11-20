#!/usr/bin/env python3
"""Compatibility entry point for the shared journaled Docker updater."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from deploy.linux import sli_update

rollback = sli_update.rollback_update


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    return sli_update.main(["rollback", *args])


if __name__ == "__main__":
    raise SystemExit(main())
