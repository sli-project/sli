"""The optional AD contract exposes only exact SID state and group provenance."""
from datetime import datetime, timezone

import pytest

from server.sli.plugins.ad.file_audit_enrichment import principals
from tests.unit.test_file_audit_rules import GROUP, SID, START


class Cursor:
    def __init__(self, *, fresh=True, complete=True, enabled=False):
        self.calls = []
        self.fresh, self.complete, self.enabled = fresh, complete, enabled

    def execute(self, sql, args):
        self.calls.append((sql, args))

    def fetchall(self):
        if "with recursive" in self.calls[-1][0]:
            return [{"depth": 0, "sid": SID.lower(), "complete": self.complete},
                    {"depth": 1, "sid": GROUP.lower(), "complete": self.complete}]
        return [{"entity_id": 1, "source_run_id": "00000000-0000-4000-8000-000000000005",
                 "valid_from_utc": datetime(2026, 1, 4, tzinfo=timezone.utc),
                 "last_observed_at_utc": datetime(2026, 1, 5 if self.fresh else 1, tzinfo=timezone.utc),
                 "attributes_json": {"identity": {"kind": "ad_user", "object_sid": SID},
                     "attributes": {"enabled": self.enabled, "primary_group_id": 513, "private": "synthetic"}}}]


def test_exact_fresh_sid_state_and_groups_without_personal_fields():
    cur = Cursor()
    row = principals(cur, domain_id=1, sids=[SID], at=START)[SID]
    assert row["kind"] == "user" and row["enabled"] is False and row["complete"] is True
    assert GROUP in row["group_sids"] and row["evidence_ref"].startswith("ad-context:")
    assert "private" not in row
    assert all(args[0] == 1 for _, args in cur.calls)
    assert "limit 2049" in cur.calls[0][0] and "m.depth<16" in cur.calls[-1][0]


@pytest.mark.parametrize("fresh,complete", [(False, True), (True, False)])
def test_stale_or_partial_directory_never_proves_absent_membership(fresh, complete):
    cur = Cursor(fresh=fresh, complete=complete)
    row = principals(cur, domain_id=1, sids=[SID], at=START)[SID]
    assert row["complete"] is False
    if not fresh:
        assert row["enabled"] is None


@pytest.mark.parametrize("domain,sids", [(None, [SID]), (True, [SID]), (1, ["invalid"]), (1, [SID] * 2049)])
def test_invalid_contract_never_reads_directory(domain, sids):
    cur = Cursor()
    with pytest.raises(ValueError, match="enrichment_invalid"):
        principals(cur, domain_id=domain, sids=sids, at=START)
    assert not cur.calls
