"""Synthetic AD context for the isolated T002 native CI measurement.

Only the empty installation domain is reused; all AD context is synthetic.
No collector, network source, or runtime grants are used.
Call only inside the per-test disposable PostgreSQL clone, with dict_row.
"""
from __future__ import annotations

import copy
import hashlib
import json
from datetime import timedelta
from uuid import UUID, uuid4

from tests.postgres_integration_guard import assert_disposable_database
from tests.sources.test_computers_v6_source_contract import _production_snapshot


def _encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def synthetic_snapshot(observed_at, population):
    """Build canonical-contract input, not evidence captured from a real AD."""
    snapshot = _production_snapshot()
    template = snapshot["objects"][0]
    stamp = observed_at.isoformat()
    metadata = snapshot["metadata"]
    metadata.update(snapshot_id=str(uuid4()), label="T002 synthetic native CI",
                    started_at=stamp, completed_at=stamp, object_count=population)
    for source in metadata["sources"]:
        source["counts"] = {source["status"]: population}
    objects = []
    for index in range(population):
        item = copy.deepcopy(template)
        guid = str(UUID(int=index + 1))
        name = f"PC-{index}"
        dns = f"pc-{index}.example.test"
        address = f"10.10.{index // 250}.{index % 250 + 1}"
        item.update(id=guid, objectGuid=guid, name=name, dnsHostName=dns,
                    deviceType="workstation", osName="Windows 11 Pro",
                    osVersion="10.0 (26100)", osBuild="26100", osFamily="Windows 11",
                    ipv4s=[address], ou="Workstations",
                    distinguishedName=f"CN={name},OU=Workstations,DC=example,DC=test",
                    canonicalName=f"example.test/Workstations/{name}",
                    description="Synthetic native CI workstation", location="Synthetic",
                    sid=f"S-1-5-21-1-2-3-{20000 + index}", spns=[f"HOST/{dns}"],
                    roleHint="Workstation", roleEvidence="Synthetic Windows client OS",
                    collectedAt=stamp, lastLogonTimestamp=stamp, exactLastLogon=stamp)
        item["classification"] = {
            "status": "observed", "value": "workstation",
            "rule_id": "device-classification/os-workstation-v1",
            "evidence": ["OperatingSystem is Windows client"],
        }
        for source in item["sources"].values():
            if source["observed_at"] is not None:
                source["observed_at"] = stamp
        item["sources"]["dns"]["value"] = {"ipv4": [address], "ipv6": []}
        item["sources"]["os"]["value"] = {
            "name": item["osName"], "version": item["osVersion"], "service_pack": "",
        }
        for key in ("last_logon_timestamp", "exact_last_logon"):
            item["sources"][key]["value"] = stamp
        objects.append(item)
    snapshot["objects"] = objects
    return snapshot


def seed_native_context(connection, *, observed_at, population=5000):
    """Commit a complete, fresh directory snapshot and return synthetic identities."""
    from server.sli.entities.what_where_when_projection import _canonical_hash
    from server.sli.plugins.ad.snapshots.computers_persistence import (
        persist_computers_v6_source_snapshot,
    )

    assert 2 <= population <= 5000
    assert observed_at.tzinfo is not None
    assert_disposable_database(connection)
    # CI's migrated baseline already owns this synthetic installation domain.
    # Reuse its identity only when every context source is empty, before any DML.
    baseline_domain = connection.execute(
        "select id from domains where lower(fqdn)='example.test'"
    ).fetchone()
    assert baseline_domain is not None, "native fixture requires migrated example.test baseline"
    domain = baseline_domain["id"]
    for table in (
        "servers", "ad_context_runs", "entities_v2", "users_report_v2_snapshots",
        "computers_v6_source_snapshots",
    ):
        assert connection.execute(
            f"select 1 from {table} where domain_id=%s limit 1", (domain,)
        ).fetchone() is None, f"native fixture requires empty example.test {table}"
    servers = []
    for index in (1, 2):
        servers.append(connection.execute(
            """insert into servers(domain_id,hostname,fqdn,role)
               values (%s,%s,%s,'domain_controller') returning id""",
            (domain, f"DC-{index}", f"dc-{index}.example.test"),
        ).fetchone()["id"])
    payload = {"users": [{"samAccountName": f"synthetic-user-{i}"} for i in range(population)]}
    connection.execute(
        """insert into users_report_v2_snapshots
           (domain_id,contract_id,schema_version,scope_json,scope_sha256,bucket_start_utc,
            captured_at_utc,source_observed_at_utc,source_state,user_count,payload_json,payload_sha256)
           values (%s,'sli.users-report.v2',1,'{}'::jsonb,%s,%s,%s,%s,'complete',%s,%s::jsonb,%s)""",
        (domain, _canonical_hash({}), observed_at.replace(minute=0, second=0, microsecond=0),
         observed_at, observed_at, population, _encoded(payload), _canonical_hash(payload)),
    )
    run = uuid4()
    connection.execute(
        """insert into ad_context_runs
           (run_id,source_pack_id,source_pack_version,domain_id,mode,observed_at_utc,
            bundle_sha256,status,completed_at)
           values (%s,'t002-synthetic-native','1',%s,'full',%s,%s,'completed',%s)""",
        (run, domain, observed_at, hashlib.sha256(_encoded(payload).encode()).digest(), observed_at),
    )
    connection.execute(
        """insert into ad_context_sections(run_id,section_name,status,record_count)
           values (%s,'directory_accounts','complete',%s)""", (run, population),
    )
    connection.execute("insert into storage_v2_entity_type(value) values ('ad_computer') on conflict do nothing")
    entity_type = connection.execute(
        "select id from storage_v2_entity_type where value='ad_computer'"
    ).fetchone()["id"]
    snapshot = synthetic_snapshot(observed_at, population)
    guids = {}
    for item in snapshot["objects"]:
        guid = item["objectGuid"]
        guids[item["name"]] = guid
        attrs = {
            "identity": {"object_guid": guid, "object_sid": item["sid"]},
            "object_guid": guid, "enabled": True, "dns_host_name": item["dnsHostName"],
            "operating_system": item["osName"], "operating_system_version": item["osVersion"],
            "distinguished_name": item["distinguishedName"], "canonical_name": item["canonicalName"],
            "ip_addresses": item["ipv4s"], "last_logon_utc": observed_at.isoformat(),
        }
        digest = hashlib.sha256(_encoded(attrs).encode()).digest()
        entity = connection.execute(
            """insert into entities_v2(entity_type_id,natural_key,display_name,domain_id,
               first_seen_utc,last_seen_utc,source_core_sha256) values (%s,%s,%s,%s,%s,%s,%s) returning id""",
            (entity_type, f"ad_computer:{guid}", item["name"], domain,
             observed_at - timedelta(days=31), observed_at, digest),
        ).fetchone()["id"]
        connection.execute(
            """insert into ad_context_entity_versions
               (entity_id,source_section,valid_from_utc,last_observed_at_utc,
                content_sha256,attributes_json,source_run_id)
               values (%s,'directory_accounts',%s,%s,%s,%s::jsonb,%s)""",
            (entity, observed_at, observed_at, digest, _encoded(attrs), run),
        )
    saved = persist_computers_v6_source_snapshot(
        connection, snapshot=snapshot, captured_at=observed_at,
        capture_options={"server": "dc-1.example.test", "collect_ad_site": True,
                         "collect_exact_last_logon": True}, collector_exit_code=0,
    )
    assert saved["object_count"] == population and saved["domain_id"] == domain
    connection.commit()
    return {"domain_id": domain, "server_ids": servers, "computer_guids": guids}


def explain_native_context(connection, domain):
    """EXPLAIN two actual context SELECT shapes, outside timed report calls.

    The scoped statements mirror computers_v6_reporting.get_computers_v6_report
    (computers_v6_accounts) and what_where_when_projection._load_service_accounts.
    Only the DB adapter's '?' placeholders become psycopg '%s'. Plans cover SQL,
    not snapshot decoding, overlay construction, source validation or Python work.
    """
    from server.sli.plugins.ad.reports.computers_v6_reporting import COMPUTERS_INPUT_LIMIT

    assert_disposable_database(connection)
    queries = [
        ("computers_v6_accounts", """
            select entity.id as entity_id,entity.domain_id,report_domain.fqdn as domain_name,entity.display_name,entity.natural_key,
                   version.last_observed_at_utc as observed_at_utc,
                   version.attributes_json->'identity' as identity,
                   version.attributes_json as attributes
            from entities_v2_active entity
            join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
            join domains report_domain on report_domain.id=entity.domain_id
            join ad_context_entity_versions version on version.entity_id=entity.id
             and version.valid_to_utc is null and version.source_section='directory_accounts'
            where entity_type.value='ad_computer'
               and entity.domain_id=any(%s)
            order by entity.domain_id,entity.id limit %s""", ([domain], COMPUTERS_INPUT_LIMIT + 1)),
        ("latest_user_classification", """
            select snapshot_id,payload_json,payload_sha256
                 from users_report_v2_snapshots
                where domain_id=%s and source_state in ('complete','partial')
                order by captured_at_utc desc,snapshot_id desc limit 1""", (domain,)),
    ]

    def structural_nodes(node):
        result = [{
            "node": node["Node Type"], "rows": node["Actual Rows"],
            "loops": node["Actual Loops"], "shared_hit_blocks": node.get("Shared Hit Blocks", 0),
            "shared_read_blocks": node.get("Shared Read Blocks", 0),
            "temp_read_blocks": node.get("Temp Read Blocks", 0),
            "temp_written_blocks": node.get("Temp Written Blocks", 0),
        }]
        for child in node.get("Plans", []):
            result.extend(structural_nodes(child))
        return result

    diagnostics = []
    for name, sql, params in queries:
        plan = connection.execute(
            "explain (analyze, buffers, format json) " + sql, params
        ).fetchone()["QUERY PLAN"][0]
        diagnostics.append({
            "query": name, "planning_ms": plan["Planning Time"],
            "execution_ms": plan["Execution Time"], "nodes": structural_nodes(plan["Plan"]),
        })
    print("T002 synthetic PostgreSQL context EXPLAIN: " + _encoded(diagnostics))
    return diagnostics
