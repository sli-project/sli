"""Select one duration-balanced shard of the already filtered pytest suite."""
from __future__ import annotations

from pathlib import Path

import pytest

from .shard_balance import balance, estimated_weights, read_durations


def pytest_addoption(parser):
    parser.addoption("--postgres-shard", nargs=2, type=int, metavar=("SHARD", "COUNT"))


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_collection_modifyitems(config, items):
    yield
    selection = config.getoption("--postgres-shard")
    if selection is None:
        return
    shard, count = selection
    paths = {item.nodeid.split("::", 1)[0] for item in items}
    try:
        if not 1 <= shard <= count:
            raise ValueError("invalid shard number")
        durations = read_durations(Path(__file__).with_name("postgres_test_durations.json"))
        selected = balance(estimated_weights(paths, durations), count)[shard - 1]
    except ValueError as error:
        raise pytest.UsageError(str(error)) from error

    kept, deselected = [], []
    for item in items:
        path = item.nodeid.split("::", 1)[0]
        (kept if path in selected else deselected).append(item)
    items[:] = kept
    config.hook.pytest_deselected(items=deselected)
