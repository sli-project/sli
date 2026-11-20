from __future__ import annotations

import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CONFIG_DIR = ROOT / "config"
DEFAULT_SLI_DATA_DIR = ROOT.parent / "sli_data"
DEFAULT_DATA_DIR = DEFAULT_SLI_DATA_DIR if DEFAULT_SLI_DATA_DIR.is_dir() else ROOT / "data"


def _configured_path(env_name: str, default: Path) -> Path:
    raw = (os.getenv(env_name) or "").strip()
    if not raw:
        return default
    path = Path(raw).expanduser()
    return path if path.is_absolute() else ROOT / path


DATA_DIR = _configured_path("ADLOG_DATA_DIR", _configured_path("SLI_DATA_DIR", DEFAULT_DATA_DIR))
DB_PATH = _configured_path("ADLOG_DB_PATH", DATA_DIR / "processed" / "ad_logs.sqlite")
DEFAULT_RAW_SPOOL_DIR = DATA_DIR / "raw"
RAW_SPOOL_DIR = _configured_path("ADLOG_RAW_SPOOL_DIR", _configured_path("SLI_RAW_SPOOL_DIR", DEFAULT_RAW_SPOOL_DIR))
REPORTS_DIR = DATA_DIR / "reports"
LOG_DIR = DATA_DIR / "logs"
WEB_DIR = ROOT / "web" / "app"

