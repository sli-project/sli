from scripts.maintenance.stage7_control_benchmark import _p95


def test_p95_uses_nearest_rank_without_understating_tail() -> None:
    values = [float(value) for value in range(1, 101)]

    assert _p95(values) == 95.0
