from __future__ import annotations

import pytest

from server.sli.reporting.sli_v4_fixture import evaluate_fixture_actor


def test_fixture_access_composition_is_server_evaluated() -> None:
    alex = evaluate_fixture_actor({"actor": "alex", "fixture": "sli-universal-prototype-v4"})
    assert [item["key"] for item in alex["packages"]] == ["sec-operators", "ad-auditors"]
    assert "privileged-accounts" in alex["direct_reports"]
    assert {"security-queue", "ad-summary", "gpo-review", "privileged-accounts"} <= set(alex["reports"])
    assert alex["server_evaluated"] is True
    privileged = next(item for item in alex["report_decisions"] if item["report"] == "privileged-accounts")
    assert privileged["allowed"] is True
    assert privileged["trace"][0]["source_type"] == "direct"
    assert {"identity.basic", "pii.contact", "pii.hr", "ad.attributes"} <= set(alex["fields"])
    assert "host5.example.invalid" in alex["scopes"]


def test_access_admin_has_no_implicit_ad_or_security_report() -> None:
    admin = evaluate_fixture_actor({"actor": "admin", "fixture": "sli-universal-prototype-v4"})
    assert set(admin["reports"]) == {"project-readiness", "technical-events"}
    assert "ad-summary" not in admin["reports"]
    assert "security-queue" not in admin["reports"]


def test_invalid_fixture_actor_fails_closed() -> None:
    with pytest.raises(ValueError, match="invalid_sli_v4_fixture_actor"):
        evaluate_fixture_actor({"actor": "root", "fixture": "sli-universal-prototype-v4"})
