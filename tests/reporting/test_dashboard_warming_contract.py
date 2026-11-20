from server.sli.reporting import dashboard_snapshot


def test_warming_snapshot_does_not_claim_healthy_data() -> None:
    payload = dashboard_snapshot._warming_response()

    assert payload["status"] == "warming"
    assert payload["health"]["status"] == "warming"
