"""Explicit acquisition gate for workers hosted outside Windows."""

from __future__ import annotations

import os
import sys


def acquisition_disabled() -> bool:
    return sys.platform != "win32" or os.environ.get("ADLOG_ACQUISITION_DISABLED", "0") == "1"
