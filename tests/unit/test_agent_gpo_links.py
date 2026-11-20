"""Lossless link assertions with a fake pinned-DC LDAP connection."""
import pytest

from sli_agent.gpo_links import LinkConflict, LinkSnapshot, compare_exchange_link, edit_link


GPO = "10000000-0000-4000-8000-000000000001"
FOREIGN = "20000000-0000-4000-8000-000000000001"
DOMAIN = "DC=directory,DC=invalid"
OU = "30000000-0000-4000-8000-000000000001"
OWN = f"[LDAP://CN={{{GPO}}},CN=Policies,CN=System,{DOMAIN};0]"
OTHER = f"[LDAP://CN={{{FOREIGN}}},CN=Policies,CN=System,{DOMAIN};3]"


class Connection:
    def __init__(self, value=None):
        self.current = LinkSnapshot(value, "1")
        self.calls = []
        self.race = False
        self.response_lost = False
        self.readback_drift = False

    def read_link(self, ou):
        assert ou == OU
        return self.current

    def assert_link(self, ou, expected, desired):
        self.calls.append((ou, expected, desired))
        if self.race:
            self.current = LinkSnapshot((self.current.value or "") + OTHER, "2")
        if self.current != expected:
            return False
        self.current = LinkSnapshot(desired + (OTHER if self.readback_drift else ""), "3")
        if self.response_lost:
            raise TimeoutError("synthetic-private-native-error")
        return True


@pytest.mark.parametrize("value", [None, "", OTHER, OTHER.lower(), OTHER + "[LDAP://CN=semi\\;colon,DC=invalid;2]"])
def test_append_and_compensation_preserve_foreign_bytes_order_and_options(value):
    updated = edit_link(value, GPO, DOMAIN)
    assert updated == (value or "") + OWN
    assert edit_link(updated, GPO, DOMAIN) == updated
    assert edit_link(updated, GPO, DOMAIN, remove=True) == (value or "")


def test_existing_own_link_keeps_case_position_and_other_links_exactly():
    value = OTHER + OWN.lower() + "[LDAP://CN=another,DC=invalid;1]"
    assert edit_link(value, GPO.upper(), DOMAIN.upper()) == value
    assert edit_link(value, GPO, DOMAIN, remove=True) == OTHER + "[LDAP://CN=another,DC=invalid;1]"


@pytest.mark.parametrize("value", [
    OWN + OWN, OWN.replace(";0]", ";1]"), OWN.replace(";0]", ";2]"), OWN.replace(";0]", ";3]"),
    OWN.replace(";0]", ";4]"), OWN + "suffix", "prefix" + OWN, OWN + "\n", "[]", "[LDAP://;0]",
    OWN.replace("CN=Policies", "CN= Policies"), OWN.replace("LDAP://", "LDAPS://"),
    OWN.replace("CN=Policies", "CN=Pol\x00icies"), 42,
])
@pytest.mark.parametrize("remove", [False, True])
def test_drift_duplicate_or_ambiguous_values_fail_closed_without_repair(value, remove):
    with pytest.raises(LinkConflict, match="^gpo_link_conflict$"):
        edit_link(value, GPO, DOMAIN, remove=remove)


@pytest.mark.parametrize("guid,domain", [("not-a-guid", DOMAIN), ("00000000-0000-0000-0000-000000000000", DOMAIN),
    (GPO, "DC=invalid][LDAP://CN=foreign;0]"), (GPO, "DC=invalid\n"), (GPO, None)])
def test_invalid_target_cannot_inject_a_link(guid, domain):
    with pytest.raises(LinkConflict):
        edit_link(OTHER, guid, domain)


def test_single_atomic_assertion_includes_absence_and_revision_and_readback():
    connection = Connection()
    expected = connection.current
    result = compare_exchange_link(connection, OU, expected, GPO, DOMAIN)
    assert connection.calls == [(OU, LinkSnapshot(None, "1"), OWN)]
    assert result == LinkSnapshot(OWN, "3")
    # Repeat is read-only and retains the current revision.
    assert compare_exchange_link(connection, OU, result, GPO, DOMAIN) == result
    assert len(connection.calls) == 1


@pytest.mark.parametrize("changed", [LinkSnapshot(None, "2"), LinkSnapshot("", "1"), LinkSnapshot(OTHER, "1")])
def test_preview_drift_never_replaces_an_attribute(changed):
    connection = Connection()
    expected = connection.current
    connection.current = changed
    with pytest.raises(LinkConflict):
        compare_exchange_link(connection, OU, expected, GPO, DOMAIN)
    assert connection.calls == [] and connection.current == changed


def test_race_between_read_and_replace_preserves_concurrent_foreign_link_without_retry():
    connection = Connection(OTHER)
    connection.race = True
    with pytest.raises(LinkConflict):
        compare_exchange_link(connection, OU, connection.current, GPO, DOMAIN)
    assert len(connection.calls) == 1
    assert connection.current.value == OTHER + OTHER


def test_lost_response_is_ambiguous_and_must_not_trigger_a_second_write():
    connection = Connection(OTHER)
    connection.response_lost = True
    with pytest.raises(TimeoutError):
        compare_exchange_link(connection, OU, connection.current, GPO, DOMAIN)
    assert len(connection.calls) == 1 and connection.current.value == OTHER + OWN


def test_foreign_readback_change_is_reported_as_conflict():
    connection = Connection()
    connection.readback_drift = True
    with pytest.raises(LinkConflict):
        compare_exchange_link(connection, OU, connection.current, GPO, DOMAIN)
    assert len(connection.calls) == 1


def test_compensation_removes_only_own_link_after_new_read_preserving_later_foreign_change():
    connection = Connection(OTHER + OWN + OTHER.lower())
    current = connection.read_link(OU)
    result = compare_exchange_link(connection, OU, current, GPO, DOMAIN, remove=True)
    assert result.value == OTHER + OTHER.lower()
    assert connection.calls[0][1] == current


@pytest.mark.parametrize("expected", [None, LinkSnapshot(OTHER, ""), LinkSnapshot(OTHER, None)])
def test_missing_assertion_evidence_is_rejected(expected):
    connection = Connection(OTHER)
    with pytest.raises(LinkConflict):
        compare_exchange_link(connection, OU, expected, GPO, DOMAIN)
    assert not connection.calls
