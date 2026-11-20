"""Deterministic scheduling of whole test groups by descending duration."""
from __future__ import annotations

import json
import math
from pathlib import Path
from statistics import median


def read_durations(path: Path) -> dict[str, float]:
    try:
        durations = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    if not isinstance(durations, dict) or any(
        type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds < 0
        for seconds in durations.values()
    ):
        raise ValueError(f"Invalid test durations in {path}")
    return durations


def estimated_weights(groups, durations: dict[str, float]) -> dict[str, float]:
    fallback = median(durations.values()) if durations else 1.0
    # Some reporters round very fast tests down to zero. Keep every group
    # positive so those tests also spread across runners.
    return {name: max(durations.get(name, fallback), 0.000001) for name in groups}


def balance(weights: dict[str, float], count: int) -> list[set[str]]:
    if not 1 <= count <= len(weights):
        raise ValueError("invalid shard count")
    loads = [0.0] * count
    shards: list[set[str]] = [set() for _ in loads]
    for name in sorted(weights, key=lambda name: (-weights[name], name)):
        target = min(range(count), key=loads.__getitem__)
        shards[target].add(name)
        loads[target] += weights[name]
    return shards
