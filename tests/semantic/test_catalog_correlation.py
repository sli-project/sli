from __future__ import annotations

import copy

import pytest

from server.sli.semantic.catalog_correlation import compile_catalog_pair_rules, get_catalog_pair_rule
from server.sli.events.event_catalog import all_event_catalog_entries




def test_descriptor_lifecycle_does_not_reenable_generic_catalog_pair() -> None:
    assert compile_catalog_pair_rules() == ()


def test_generic_catalog_pair_route_is_unavailable() -> None:
    with pytest.raises(ValueError, match="catalog_pair_rule_not_unique"):
        get_catalog_pair_rule("sli.windows.ad-dc", "Security", "4624")


def test_duplicate_v2_identity_fails_closed() -> None:
    entries = copy.deepcopy(all_event_catalog_entries())
    entries.append(copy.deepcopy(entries[0]))

    with pytest.raises(ValueError, match="catalog_pair_duplicate_identity"):
        compile_catalog_pair_rules(entries)
