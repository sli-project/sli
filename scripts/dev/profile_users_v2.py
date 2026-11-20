"""Profile a cold active Users V2 response with synthetic, bulk SQL fakes.

Export the two baseline modules on the host with ``git archive --format=zip``;
pass that archive as ``--baseline-archive`` when the worktree's Git directory
is not mounted in the container. Run in the dev container:
/opt/venv/bin/python -m scripts.dev.profile_users_v2 --accounts 1500
--baseline-archive tmp/users-v2-before.zip --repeat 3. No database is used.
This times the report query and JSON serialization, without network I/O.
Optional --query-delay-ms models round-trip latency, not real SQL execution.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import cProfile
import hashlib
import io
import json
import pstats
import statistics
import subprocess
import time
from types import ModuleType
from unittest.mock import patch
from zipfile import ZipFile

from server.sli.core import platform_settings
from server.sli.entities import users_v2_directory_projection as projection
from server.sli.reporting.v2.definition import QueryContext
from server.sli.reporting.v2.reports import users as report
from server.sli.reports import users_reporting as legacy
from server.sli.reports import users_v2_reporting as engine

OBSERVED = "2026-10-09T00:00:00Z"
GROUP_ID = 1_000_001


class SyntheticDirectory:
    """Only synthetic accounts, missing facts, direct/primary/nested groups."""

    def __init__(self, accounts: int, query_delay_ms: float = 0):
        self.calls = Counter()
        self.query_delay = query_delay_ms / 1000
        self.accounts = []
        self.versions = []
        self.relations = []
        self.privileges = []
        for entity_id in range(1, accounts + 1):
            attrs = {
                "object_class": "user", "sam_account_name": f"fixture-{entity_id}" + ("$" if entity_id % 113 == 0 else ""),
                "enabled": None if entity_id % 97 == 0 else entity_id % 5 != 0,
                "locked_out": entity_id % 31 == 0, "department": "Synthetic department",
                "distinguished_name": f"CN=fixture-{entity_id},OU=Fixtures,DC=example,DC=invalid",
                "user_principal_name": f"fixture-{entity_id}@example.invalid",
                "password_last_set_utc": None if entity_id % 17 == 0 else "2026-06-01T00:00:00Z",
                "last_logon_utc": None if entity_id % 19 == 0 else OBSERVED,
                "password_never_expires": False,
            }
            self.accounts.append({"entity_id": entity_id, "domain_id": 1,
                                  "display_name": f"Synthetic account {entity_id}",
                                  "natural_key": f"fixture-{entity_id}", "observed_at_utc": OBSERVED,
                                  "attributes": {"attributes": attrs}})
            self.versions.append({"entity_id": entity_id, "domain_id": 1,
                                  "source_section": "directory_accounts", "attributes_json": {"attributes": attrs},
                                  "last_observed_at_utc": OBSERVED, "source_run_id": "synthetic-directory"})
            self.relations.append({"domain_id": 1, "source_entity_id": entity_id,
                                   "target_entity_id": GROUP_ID, "source_kind": "ad_user", "target_kind": "ad_group",
                                   "last_observed_at_utc": OBSERVED,
                                   "attributes_json": {"membership_type": "primary" if entity_id % 2 else "direct"}})
            if entity_id % 23 == 0:
                self.privileges.append({"source_entity_id": entity_id, "target_entity_id": GROUP_ID,
                                        "target_name": "Synthetic group", "relation_attributes": {"membership_type": "direct"}})
        self.relations.append({"domain_id": 1, "source_entity_id": GROUP_ID,
                               "target_entity_id": GROUP_ID + 1, "source_kind": "ad_group", "target_kind": "ad_group",
                               "last_observed_at_utc": OBSERVED, "attributes_json": {"membership_type": "direct"}})

    def read(self, sql, params=(), **_kwargs):
        if "from platform_settings where key = ?" in sql:
            name = "setting:" + params[0]
            values = {"reports.domain_fqdn": "example.invalid", "ad.password_max_age_days": "90", "ad.inactivity_days": "60",
                      "ad.service_account_exceptions": "[]"}
            rows = [{"value": values[params[0]], "updated_by": None, "updated_at": None}]
        elif sql == "select is_archived from domains where lower(fqdn) = ?":
            assert params == ("example.invalid",)
            name, rows = "domain_lifecycle", [{"is_archived": False}]
        elif "users_report_coverage" in sql:
            name = "coverage"
            rows = [{"domain_id": 1, "domain_name": "example.invalid", "section_name": section,
                     "run_status": "completed", "section_status": "complete",
                     "record_count": len(self.accounts), "observed_at_utc": OBSERVED}
                    for section in ("directory_accounts", "privileged_membership")]
        elif "users_report_privileges" in sql:
            ids = set(params[0])
            name, rows = "privileges", [row for row in self.privileges if row["source_entity_id"] in ids]
        elif "users_report_acceptances" in sql:
            name, rows = "acceptances", []
        elif "users_v2_complete_get_aduser_population" in sql:
            if "not like '%$'" in sql:
                name = "legacy_population"
                rows = [row for row in self.accounts if not row["attributes"]["attributes"]["sam_account_name"].endswith("$")][:params[-1]]
            else:
                name, rows = "complete_population", self.accounts[:params[-1]]
        elif "users_v2_current_source_versions" in sql:
            ids = set(params[1])
            name, rows = "source_versions", [row for row in self.versions if row["entity_id"] in ids]
        elif "users_v2_stable_aliases" in sql:
            name = "aliases"
            rows = [{"entity_id": entity_id, "alias_type": "object_guid", "alias_value": f"synthetic-guid-{entity_id}"}
                    for entity_id in params[0]]
        elif "users_v2_latest_source_sections" in sql:
            name = "source_sections"
            rows = [{"domain_id": 1, "section_name": section, "status": "complete",
                     "record_count": len(self.accounts), "observed_at_utc": OBSERVED,
                     "source_pack_version": "0.8.0", "run_id": "synthetic-directory"}
                    for section in projection.SOURCE_SECTIONS]
        elif "users_v2_group_graph_relations" in sql:
            name, rows = "graph_relations", self.relations
        elif "users_v2_group_graph_entities" in sql:
            name = "graph_groups"
            rows = [{"entity_id": GROUP_ID + offset, "domain_id": 1, "display_name": "Synthetic group",
                     "last_observed_at_utc": OBSERVED, "attributes_json": {"name": "Synthetic group"}}
                    for offset in (0, 1)]
        elif "from entities_v2_active entity" in sql and "not like '%$'" in sql:
            name = "legacy_population"
            rows = [row for row in self.accounts if not row["attributes"]["attributes"]["sam_account_name"].endswith("$")][:params[-1]]
        else:
            raise AssertionError("Unexpected database query in synthetic Users profile")
        self.calls[name] += 1
        if self.query_delay:
            time.sleep(self.query_delay)
        return deepcopy(rows)

    @contextmanager
    def installed(self, adapter=engine, reader=legacy):
        platform_settings.clear_cache()
        try:
            with ExitStack() as stack:
                for module, name in ((adapter, "query_rows_bounded"), (reader, "query_rows_bounded"),
                                     (projection, "query_rows_bounded"), (platform_settings.database, "query_rows"),
                                     (platform_settings.database, "query_rows_bounded")):
                    stack.enter_context(patch.object(module, name, self.read))
                stack.enter_context(patch.object(adapter, "get_users_report", reader.get_users_report))
                stack.enter_context(patch.object(report, "load_users_v2_snapshots", adapter.load_users_v2_snapshots))
                stack.enter_context(patch.object(report, "_cache", {}))
                yield self
        finally:
            platform_settings.clear_cache()


def _baseline_module(ref, path, name, archive=None):
    if archive:
        with ZipFile(archive) as saved:
            source = saved.read(path).decode("utf-8")
    else:
        source = subprocess.run(["git", "show", f"{ref}:{path}"], check=True, capture_output=True).stdout.decode("utf-8")
    module = ModuleType(name)
    exec(compile(source, path, "exec"), module.__dict__)
    return module


def measure(adapter, reader, accounts, delay, repeat):
    durations = []
    profile = cProfile.Profile()
    context = QueryContext(access={}, params={}, domain_ids=[1], tab="active", limit=100)
    # Time unprofiled requests; an additional request supplies the call profile.
    for attempt in range(repeat + 1):
        directory = SyntheticDirectory(accounts, delay)
        with directory.installed(adapter, reader):
            start = time.perf_counter()
            if attempt == repeat:
                profile.enable()
            response = report._query(context)
            encoded = json.dumps(response, ensure_ascii=False, sort_keys=True).encode("utf-8")
            if attempt == repeat:
                profile.disable()
            else:
                durations.append(time.perf_counter() - start)
    output = io.StringIO()
    pstats.Stats(profile, stream=output).strip_dirs().sort_stats("cumulative").print_stats(15)
    return encoded, {"accounts": accounts, "filtered_count": response["filtered_count"],
                     "median_seconds": statistics.median(durations), "seconds": durations,
                     "database_calls": dict(directory.calls), "total_database_calls": sum(directory.calls.values()),
                     "query_delay_ms": delay, "response_sha256": hashlib.sha256(encoded).hexdigest(),
                     "profile": output.getvalue()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--accounts", type=int, default=1500)
    parser.add_argument("--baseline", default="HEAD")
    parser.add_argument("--baseline-archive", help="Host-exported ZIP of the two baseline modules")
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--query-delay-ms", type=float, default=0)
    args = parser.parse_args()
    if args.accounts < 1500 or args.repeat < 1 or args.query_delay_ms < 0:
        parser.error("Use at least 1500 accounts, one repeat and nonnegative query delay")
    baseline = args.baseline
    if args.baseline_archive:
        with ZipFile(args.baseline_archive) as saved:
            # git archive records the source commit in the ZIP comment.
            baseline = saved.comment.decode("ascii") or baseline
    old_reader = _baseline_module(args.baseline, "server/sli/reports/users_reporting.py", "baseline_users_reporting", args.baseline_archive)
    old_adapter = _baseline_module(args.baseline, "server/sli/reports/users_v2_reporting.py", "baseline_users_v2_reporting", args.baseline_archive)
    before, before_stats = measure(old_adapter, old_reader, args.accounts, args.query_delay_ms, args.repeat)
    after, after_stats = measure(engine, legacy, args.accounts, args.query_delay_ms, args.repeat)
    print(json.dumps({"baseline": baseline, "before": before_stats, "after": after_stats,
                      "response_identical": before == after}, ensure_ascii=False, indent=2))
    if before != after:
        raise SystemExit("Synthetic response changed")


if __name__ == "__main__":
    main()
