"""Hermetic source identity regression tests; runnable with unittest or pytest."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from server.sli.core import database


def source(domain=None, fqdn=None, hostname="DC01"):
    return {"hostname": hostname, "domain_fqdn": domain, "fqdn": fqdn}


def inventory(domain=None, fqdn=None, address="192.0.2.1"):
    return {
        "display_key": "dc01", "sam_key": "dc01", "dns_key": "dc01",
        "domain_fqdn": domain, "fqdn": fqdn,
        "ip_addresses": [address], "logical_disks": ["C:|100|5"],
        "technical_inventory_status": "complete", "os_name": "Windows",
        "last_observed_at_utc": "2026-10-21T00:00:00Z",
    }


class SourceInventoryIdentityTests(unittest.TestCase):
    def enrich(self, rows, items):
        with patch.object(database, "query_rows_bounded", return_value=items):
            return database._enrich_sources_from_current_ad_context(rows)

    def test_collision_keeps_each_domain_inventory(self):
        a, b = source("a.test"), source("b.test")
        result = self.enrich([a, b], [
            inventory("b.test", "dc01.b.test", "192.0.2.2"),
            inventory("a.test", "dc01.a.test"),
        ])
        self.assertEqual([r["ip_addresses"] for r in result], [["192.0.2.1"], ["192.0.2.2"]])
        self.assertEqual(a, source("a.test"))

    def test_other_domain_alone_is_not_a_fallback(self):
        row = source("a.test")
        self.assertEqual(self.enrich([row], [inventory("b.test", "dc01.b.test")]), [row])

    def test_same_domain_without_dns_can_match(self):
        self.assertEqual(self.enrich([source(" A.TEST. ")], [inventory("a.test")])[0]["os_name"], "Windows")

    def test_fqdn_matches_without_domain_and_with_fqdn_hostname(self):
        for row in [source(fqdn=" DC01.A.TEST. "), source(hostname="dc01.a.test")]:
            with self.subTest(row=row):
                self.assertEqual(self.enrich([row], [inventory(fqdn="dc01.a.test")])[0]["os_name"], "Windows")

    def test_explicit_fqdn_conflict_is_not_replaced_by_short_name(self):
        row = source("a.test", "dc01.child.a.test")
        self.assertEqual(self.enrich([row], [inventory("a.test", "dc01.a.test")]), [row])

    def test_same_domain_can_have_a_different_dns_suffix(self):
        result = self.enrich([source("a.test")], [inventory("a.test", "dc01.child.a.test")])
        self.assertEqual(result[0]["fqdn"], "dc01.child.a.test")

    def test_missing_domain_cannot_override_conflicting_dns_identity(self):
        row = source("a.test")
        self.assertEqual(self.enrich([row], [inventory(fqdn="dc01.b.test")]), [row])

    def test_unique_unqualified_fallback(self):
        self.assertEqual(self.enrich([source()], [inventory()])[0]["os_name"], "Windows")

    def test_ambiguous_inventory_is_unknown_even_with_same_domain(self):
        for domain in [None, "a.test"]:
            row = source(domain)
            self.assertEqual(self.enrich([row], [inventory(domain), inventory(domain)]), [row])

    def test_unqualified_inventory_cannot_fill_multiple_registered_domains(self):
        rows = [source("a.test"), source("b.test")]
        self.assertEqual(self.enrich(rows, [inventory()]), rows)

    def test_missing_identity_does_not_match(self):
        rows = [source(hostname=""), source()]
        self.assertEqual(self.enrich(rows, [{"ip_addresses": ["192.0.2.99"]}]), rows)

    def test_truncated_candidates_fail_closed(self):
        row = source("a.test", "dc01.a.test")
        with patch.object(database, "query_rows_bounded", side_effect=lambda sql, params, **kw: [
            inventory("a.test", "dc01.a.test")
        ] * params[-1]):
            self.assertEqual(database._enrich_sources_from_current_ad_context([row]), [row])

    def test_query_fetches_full_dns_and_domain_with_overflow_sentinel(self):
        with patch.object(database, "query_rows_bounded", return_value=[]) as query:
            database._enrich_sources_from_current_ad_context([source("a.test", "alias.a.test")])
        sql, params = query.call_args.args
        self.assertIn("join ad_context_runs", sql)
        self.assertIn("domain_fqdn", sql)
        self.assertIn("alias.a.test", params[0])
        self.assertEqual(sql.count("?"), len(params))
        self.assertEqual(params[-1], 5)

    def test_get_sources_serializes_honest_unknown(self):
        with patch.object(database, "query_rows", return_value=[source("a.test")]), \
                patch.object(database, "query_rows_bounded", return_value=[inventory("b.test")]), \
                patch.object(database, "_configured_source_addresses", return_value={}):
            result = json.loads(json.dumps(database.get_sources()))[0]
        self.assertEqual(result["ip_addresses"], [])
        self.assertEqual(result["disks"], [])
        self.assertEqual(result["disk_state"], "not_collected")
        self.assertNotIn("inventory_source", result)
        self.assertNotIn("last_observed_at_utc", result)


if __name__ == "__main__":
    unittest.main()
