"""The pinned history profile keeps review-only detection rules out of admission."""
from __future__ import annotations

from scripts.dev.verify_sigma_package import load_config


def test_pinned_profile_keeps_unvalidated_rules_in_test_mode():
    lock, profile = load_config()
    assert [row["id"] for row in profile["rules"]] == [row["id"] for row in lock["rules"]]
    assert profile["review"]["mode"] == "test"
    assert profile["review"]["admission"] == "blocked"
    assert profile["review"]["exclusions"] == []
