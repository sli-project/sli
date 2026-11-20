"""Directory names survive supplemental observations; no database is used."""
import json

import pytest

from server.sli.entities.context_identity import persist_entity_identity
from server.sli.plugins.ad.context.repository import _upsert_entity


class CatalogCursor:
    rowcount = 1
    def __init__(self):
        self.name = "Synthetic directory name"
        self.details = {}

    def execute(self, sql, params=()):
        sql = " ".join(sql.split())
        if sql.startswith("update entities_v2") and "display_name=%s" in sql:
            self.name = params[0]
        if sql.startswith("insert into entity_details_v2"):
            self.details = json.loads(params[1])

    def fetchone(self):
        return {"id": 1}


@pytest.mark.parametrize("section", ["directory_exact_logon", "directory_group_graph", "privileged_membership", "vpn_membership"])
@pytest.mark.parametrize("incoming_name", [None, "Supplemental name"])
def test_supplemental_account_record_cannot_rename_directory_entity(section, incoming_name):
    cursor = CatalogCursor()
    attrs = {"exact_last_logon_status": "observed"}
    if incoming_name:
        attrs["display_name"] = incoming_name
    record = {"identity": {"kind": "ad_user"}, "section": section,
              "record_key": "synthetic-account:exact-logon", "observed_at_utc": "2026-10-16T00:00:00Z", "attributes": attrs}
    persist_entity_identity(cursor, 7, record, entity_id=1, attributes=attrs)
    assert cursor.name == "Synthetic directory name"
    assert cursor.details["exact_last_logon_status"] == "observed"


def test_directory_record_can_rename_existing_entity():
    cursor = CatalogCursor()
    attrs = {"display_name": "Updated directory name"}
    record = {"identity": {"kind": "ad_user"}, "section": "directory_accounts",
              "record_key": "synthetic-account", "observed_at_utc": "2026-10-16T00:00:00Z", "attributes": attrs}
    persist_entity_identity(cursor, 7, record, entity_id=1, attributes=attrs)
    assert cursor.name == attrs["display_name"]


def test_supplemental_upsert_preserves_materialized_directory_name():
    class Cursor(CatalogCursor):
        def execute(self, sql, params=()):
            self.reading_details = sql.startswith("select attributes_json")
            super().execute(sql, params)

        def fetchone(self):
            if self.reading_details:
                return {"attributes_json": {"display_name": "Synthetic directory name", "enabled": True}}
            return super().fetchone()

    cursor = Cursor()
    record = {"identity": {"kind": "ad_user", "object_guid": "synthetic-guid"}, "section": "directory_exact_logon",
              "record_key": "synthetic-account:exact-logon", "observed_at_utc": "2026-10-16T00:00:00Z",
              "attributes": {"display_name": "Supplemental name", "exact_last_logon_status": "observed"}}
    _upsert_entity(cursor, 7, "synthetic-run", record, existing_entity_id=1, lookup_complete=True)
    assert cursor.name == cursor.details["display_name"] == "Synthetic directory name"
    assert cursor.details["enabled"] is True
    assert cursor.details["exact_last_logon_status"] == "observed"
