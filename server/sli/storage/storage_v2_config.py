"""Storage V2 feature configuration for pre-cutover runtime routing.

A valid configured V2 read mode selects V2 only before a transition state is
declared. A declared transition remains controller-authorized.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping

READ_MODES = ("v1", "shadow", "v2")
WRITE_MODES = ("v1", "v1_outbox", "v2_primary_compat", "v2")


class StorageV2ConfigurationError(ValueError):
    """Raised when strict configuration validation rejects unsafe routing."""


@dataclass(frozen=True)
class StorageV2Settings:
    read_mode: str = "v2"
    write_mode: str = "v1"
    shadow_sample_rate: float = 0.0
    valid: bool = True
    diagnostics: tuple[str, ...] = ()

    @property
    def v2_read_enabled(self) -> bool:
        return self.valid and self.read_mode == "v2"

    @property
    def shadow_read_enabled(self) -> bool:
        return self.valid and self.read_mode == "shadow" and self.shadow_sample_rate > 0

    @property
    def outbox_enabled(self) -> bool:
        return self.valid and self.write_mode in {"v1_outbox", "v2_primary_compat", "v2"}

    @property
    def v2_primary_write_enabled(self) -> bool:
        return self.valid and self.write_mode in {"v2_primary_compat", "v2"}

    def public_dict(self) -> dict[str, object]:
        return {
            "read_mode": self.read_mode,
            "write_mode": self.write_mode,
            "shadow_sample_rate": self.shadow_sample_rate,
            "valid": self.valid,
            "diagnostics": list(self.diagnostics),
        }


def load_storage_v2_settings(
    env: Mapping[str, str] | None = None,
    *,
    strict: bool = False,
) -> StorageV2Settings:
    """Load feature flags with an explicit fail-closed V1 result.

    In non-strict mode invalid input returns V1/V1 and a critical diagnostic.
    Startup gates that require valid configuration should use ``strict=True``.
    """
    source = env if env is not None else os.environ
    raw_read = str(source.get("ADLOG_STORAGE_READ_MODE", "v2")).strip().lower()
    raw_write = str(source.get("ADLOG_STORAGE_WRITE_MODE", "v1")).strip().lower()
    diagnostics: list[str] = []

    if raw_read not in READ_MODES:
        diagnostics.append(f"invalid ADLOG_STORAGE_READ_MODE={raw_read!r}")
    if raw_write not in WRITE_MODES:
        diagnostics.append(f"invalid ADLOG_STORAGE_WRITE_MODE={raw_write!r}")

    raw_rate = str(source.get("ADLOG_STORAGE_V2_SHADOW_SAMPLE_RATE", "0")).strip()
    try:
        rate = float(raw_rate)
    except ValueError:
        rate = -1.0
    if not 0.0 <= rate <= 1.0:
        diagnostics.append("ADLOG_STORAGE_V2_SHADOW_SAMPLE_RATE must be between 0 and 1")

    if raw_read == "shadow" and rate <= 0:
        diagnostics.append("shadow read mode requires a positive sample rate")

    if raw_write in {"v1_outbox", "v2_primary_compat"}:
        diagnostics.append("ADLOG_STORAGE_WRITE_MODE cannot select V2 publication; controller authorization is required")

    if diagnostics:
        message = "Storage V2 configuration rejected; fail-closed V1 routing: " + "; ".join(diagnostics)
        if strict:
            raise StorageV2ConfigurationError(message)
        return StorageV2Settings(
            read_mode="v2",
            write_mode="v1",
            shadow_sample_rate=0.0,
            valid=False,
            diagnostics=(message,),
        )

    return StorageV2Settings(
        read_mode=raw_read,
        write_mode=raw_write,
        shadow_sample_rate=rate,
        valid=True,
        diagnostics=(),
    )
