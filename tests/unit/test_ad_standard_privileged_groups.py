"""Standard AD groups are identified independently of localized display names."""
import pytest

from server.sli.plugins.ad.directory_projection import _group_reference, _memberships


@pytest.mark.parametrize("sid", [
    "S-1-5-21-1-2-3-512", "S-1-5-21-1-2-3-518", "S-1-5-21-1-2-3-519", "S-1-5-21-1-2-3-520",
    "S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551",
])
def test_standard_admin_sid_is_watched_with_localized_name(sid):
    group = _group_reference(10, {"display_name": "Synthetic localized group"}, {"object_sid": sid}, watch_group=False)
    assert group["watchGroup"] is True


def test_dns_admins_has_domain_assigned_sid_and_stable_account_name():
    group = _group_reference(10, {"sam_account_name": "DnsAdmins"}, {"object_sid": "S-1-5-21-1-2-3-1300"}, watch_group=False)
    assert group["watchGroup"] is True


@pytest.mark.parametrize("sid,name", [("S-1-5-21-1-2-3-1512", "Synthetic group"), ("S-1-5-32-512", "Domain Admins"),
                                      ("S-1-5-21-1-2-3-1300", "DnsAdmins copy")])
def test_ordinary_groups_do_not_become_privileged_from_display_names(sid, name):
    assert not _group_reference(10, {"display_name": name}, {"object_sid": sid}, watch_group=False)["watchGroup"]


def test_nested_membership_retains_standard_privilege_and_path():
    group = _group_reference(10, {}, {"object_sid": "S-1-5-32-544"}, watch_group=False)
    child = _group_reference(11, {"display_name": "Synthetic child"}, {}, watch_group=False)
    memberships = _memberships(user_id=1, user_name="Synthetic account", user_attrs={}, graph_status="observed",
                              graph={"references": {10: group, 11: child}, "user_edges": {1: [(11, "direct")]},
                                     "parent_edges": {11: [10]}, "query_truncated": False})
    assert any(item["watchGroup"] and item["relation"] == "nested" for item in memberships["effective"])
    assert any(path["groupId"] == "group:10" and len(path["nodes"]) == 3 for path in memberships["paths"])
