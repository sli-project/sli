"""Transactional agent ingress; Part A authenticates and locks the agent first."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from xml.etree.ElementTree import ParseError

from server.sli.sources.collection_packet_import import event_rows_from_packet
from server.sli.plugins.registry import plugin_hook
from server.sli.agents.runtime_switch import source_host
from sli_agent.envelope import digest, timestamp, verify_packet
from sli_agent.snapshot_stream import MODULE_FAMILIES


class PostgresLedger:
    def __init__(self, cur):
        self.cur = cur

    def recovery_boundary(self, identity, envelope, previous, now):
        from server.sli.agents.sequence_recovery import observe_boundary
        return observe_boundary(self.cur, identity, envelope, previous, now)

    def accept_recovery(self, observation_id, envelope, now):
        from server.sli.agents.sequence_recovery import record_acceptance
        record_acceptance(self.cur, observation_id, envelope, now)

    def get(self, agent, module, sequence):
        self.cur.execute("select envelope,envelope_sha256,receipt from sli_agent_receipts where agent_id=%s and module_id=%s and sequence=%s",
                         (agent, module, sequence))
        return self.cur.fetchone()

    def packet_exists(self, packet_id):
        self.cur.execute("select packet_id from sli_agent_receipts where packet_id=%s", (packet_id,))
        return self.cur.fetchone() is not None

    def latest(self, agent, module):
        self.cur.execute("select envelope from sli_agent_receipts where agent_id=%s and module_id=%s order by sequence desc limit 1",
                         (agent, module))
        row = self.cur.fetchone()
        if row:
            return row["envelope"]
        self.cur.execute("select runtime_resume->%s as envelope from sli_agents where id=%s", (module, agent))
        row = self.cur.fetchone()
        return row["envelope"] if row else None

    def binding(self, agent, module):
        if module in MODULE_FAMILIES:
            self.cur.execute("select config as policy from sli_agent_snapshot_bindings where agent_id=%s and module_id=%s and enabled",
                             (agent, module))
            return self.cur.fetchone()
        self.cur.execute("select source_instance_id,source_name,channel,module_version,policy_revision from sli_agent_module_bindings where agent_id=%s and module_id=%s",
                         (agent, module))
        return self.cur.fetchone()

    def policy_assignment(self, agent, module, revision):
        if (not isinstance(revision, str) or not revision.isascii() or not revision.isdecimal()
                or len(revision) > 16 or not 1 <= int(revision) <= 9007199254740991):
            return None
        # A common-control revision or another module's revision can retain
        # this module's earlier policy revision. Find the issued module inside
        # the agent's snapshots, including the migration's initial snapshot.
        self.cur.execute("""select assignment from sli_agent_policy_history h
            cross join lateral jsonb_array_elements(h.assigned_modules) assignment
            where h.agent_id=%s and assignment->>'module_id'=%s
              and assignment->'enabled'='true'::jsonb
              and coalesce(assignment->'config'->>'policy_revision','1')=%s
            order by h.revision limit 1""", (agent, module, revision))
        row = self.cur.fetchone()
        return row["assignment"] if row else None

    def quota_error(self, value, receipt, rows):
        if value["envelope"]["module_id"] == "sli.windows.ad-dc-history":
            self.cur.execute("""select packet_id from sli_agent_packet_inbox
                where envelope->>'agent_id'=%s and envelope->>'module_id'=%s
                  and imported_at is null limit 1""",
                (value["envelope"]["agent_id"], value["envelope"]["module_id"]))
            if self.cur.fetchone():
                return "agent_history_pending"
        if value["envelope"]["module_id"] in MODULE_FAMILIES:
            from server.sli.agents.snapshot_ingest import quota_error
            return quota_error(self.cur, value, receipt)
        from server.sli.agents.inbox_quota import quota_error
        return quota_error(self.cur, value, receipt, rows)

    def snapshot_cycle(self, cycle_id):
        # Validate UUID before binding it to PostgreSQL, including malformed payloads.
        from uuid import UUID
        try:
            if str(UUID(cycle_id)) != cycle_id:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise ValueError("agent_snapshot_chunk_invalid") from None
        self.cur.execute("select agent_id::text,module_id,slot_start_utc,policy,transport_state from sli_agent_snapshot_cycles where cycle_id=%s",
                         (cycle_id,))
        row = self.cur.fetchone()
        if row and isinstance(row["slot_start_utc"], datetime):
            # psycopg returns timestamptz as datetime; the signed contract is UTC text.
            row = {**row, "slot_start_utc": row["slot_start_utc"].astimezone(timezone.utc).isoformat()}
        return row

    def snapshot_conflict(self, envelope, payload, config):
        from server.sli.agents.snapshot_ingest import conflict
        return conflict(self.cur, envelope, payload, config)

    def snapshot_policy_revision(self, agent, module, revision):
        self.cur.execute("""select config,enabled,superseded_at from sli_agent_snapshot_policies
            where agent_id=%s and module_id=%s and policy_revision=%s""", (agent, module, revision))
        return self.cur.fetchone()

    def workstation_counts(self, agent, window_seconds):
        # Authentication holds the agent row lock through receipt commit.
        # Count retained admitted rows, including those already projected.
        self.cur.execute("""select event->>'event_id' as event_id,count(*) as count
            from sli_agent_receipts r join sli_agent_packet_inbox i using(packet_id)
            cross join lateral jsonb_array_elements(i.event_rows) event
            where r.agent_id=%s and r.module_id='sli.workstations'
              and r.received_at >= clock_timestamp() - (%s * interval '1 second')
            group by event->>'event_id'""", (agent, window_seconds))
        return {row["event_id"]: row["count"] for row in self.cur.fetchall()}

    def commit(self, value, receipt, envelope_hash, rows):
        envelope = value["envelope"]
        self.cur.execute("""insert into sli_agent_receipts
            (agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            values(%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb)""",
            (envelope["agent_id"], envelope["module_id"], envelope["sequence"], envelope["packet_id"],
             envelope_hash, json.dumps(envelope), json.dumps(receipt)))
        if envelope["module_id"] in MODULE_FAMILIES:
            from server.sli.agents.snapshot_ingest import store_chunk
            store_chunk(self.cur, value)
        elif rows is not None:
            from server.sli.sources.collection_packet_import import store_agent_packet
            store_agent_packet(self.cur, packet_id=envelope["packet_id"], envelope=envelope,
                               packet=value["payload"], event_rows=rows)


def _receipt(envelope, status, code=None, *, now=None):
    committed = status in ("committed", "duplicate")
    return {"contract_id": "sli.agent-receipt.v1", "packet_id": envelope["packet_id"],
        "payload_sha256": envelope["payload_sha256"], "status": status,
        "committed_cursor": envelope["cursor_after"] if committed else None,
        "evidence_ref": "agent-packet:" + envelope["packet_id"] if committed else None,
        "committed_at_utc": now.isoformat() if committed else None, "error_code": code}


def _event_rows(envelope, payload, binding):
    rows = event_rows_from_packet(payload)
    header = payload["header"]
    try:
        before = envelope["cursor_before"]
        after = envelope["cursor_after"]
        before_id = int(before["token"]) if before["token"] else None
        after_id = int(after["token"]) if after["token"] else None
        ids = [row["record_id"] for row in rows]
        if (header["source"] != binding["source_name"] or header["channel"] != envelope["channel"] or
                header["generation"] != envelope["generation"] or
                header["cursor"] != {"after_record_id": before_id, "last_record_id": after_id} or
                before["strategy"] != "record_id" or after["strategy"] != "record_id" or
                any(type(n) is not int for n in ids) or ids != sorted(set(ids)) or
                any(before_id is not None and n <= before_id for n in ids) or
                after_id != (ids[-1] if ids else before_id) or
                envelope["continuity_state"] not in ("not_proven", "gap") or
                payload["continuity"]["status"] != "not_proven" or
                envelope["filtered_count"] != 0 or envelope["lost_count"] is not None):
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise ValueError("agent_collection_cursor_invalid") from None
    return rows


def _dc_event_rows(envelope, payload, binding, policy=None):
    """Compatibility entry point for AD-owned signed-event attestation."""
    validator = plugin_hook("sli.ad", "ad_agent_rows")
    if validator is None:
        raise ValueError("agent_collection_cursor_invalid")
    return validator(envelope, payload, binding, policy)


def _module_assignment(assignments, module):
    matches = [item for item in assignments if isinstance(item, dict) and item.get("module_id") == module]
    return matches[0] if len(matches) == 1 and matches[0].get("enabled") is True else None


def _capture_assignment(ledger, identity, envelope):
    module = envelope["module_id"]
    current = _module_assignment(identity.get("assigned_modules", []), module)
    if current is None:
        return None
    if current.get("config", {}).get("policy_revision", "1") == envelope["policy_revision"]:
        return current
    history = getattr(ledger, "policy_assignment", None)
    retained = history(str(identity["id"]), module, envelope["policy_revision"]) if history else None
    if retained and retained.get("config", {}).get("policy_revision", "1") == envelope["policy_revision"]:
        return retained
    return None


def receive_packet(ledger, *, identity, public_key, value, now=None, replay_seconds=7 * 86400):
    """Return a receipt; the HTTP caller must commit before exposing success.

    Authentication/revocation and the Part-A agent row lock happen on every
    request, including duplicates. The lock serializes sequence publication.
    """
    envelope = verify_packet(value, public_key)
    now = now or datetime.now(timezone.utc)
    def reject(code, status="rejected"):
        return _receipt(envelope, status, code)
    if envelope["agent_id"] != str(identity["id"]):
        return reject("agent_identity_mismatch")
    envelope_hash = digest(envelope)
    existing = ledger.get(envelope["agent_id"], envelope["module_id"], envelope["sequence"])
    if existing:
        if existing["envelope_sha256"] != envelope_hash:
            return reject("agent_sequence_conflict")
        # An exact accepted replay can recover its ACK even after the freshness
        # window or policy changes. No evidence is imported a second time.
        return {**existing["receipt"], "status": "duplicate"}
    if ledger.packet_exists(envelope["packet_id"]):
        return reject("agent_packet_id_conflict")
    age = (now - timestamp(envelope["observed_at_utc"])).total_seconds()
    if age < -300 or age > replay_seconds:
        return reject("agent_replay_window")
    module = envelope["module_id"]
    if module != "sli.heartbeat" and identity.get("source_host_id"):
        identity = {**identity, "host_id": source_host(identity)}
    payload = value["payload"]
    rows = None
    if module == "sli.heartbeat":
        if (envelope["source_instance_id"] != str(identity["host_id"]) or envelope["channel"] != "heartbeat" or
                envelope["generation"] != str(identity["host_id"]) or envelope["module_version"] != "1.0.0" or
                envelope["policy_revision"] != "1" or payload != {"contract": "sli.heartbeat.v1", "status": "alive"} or
                envelope["continuity_state"] != "not_proven" or envelope["filtered_count"] != 0 or
                envelope["lost_count"] is not None):
            return reject("agent_heartbeat_invalid")
    elif module == "sli.workstations":
        from server.sli.agents.workstation_ingest import workstation_rows

        try:
            assignment = _capture_assignment(ledger, identity, envelope)
            if assignment is None:
                return reject("agent_workstations_packet_invalid")
            rows = workstation_rows({**identity, "assigned_modules": [assignment]}, envelope, payload)
        except (ValueError, KeyError, TypeError):
            return reject("agent_workstations_packet_invalid")
    elif module == "sli.file-audit":
        try:
            validator = plugin_hook("sli.file-audit", "file_audit_agent_rows")
            if validator is None:
                return reject("agent_file_audit_packet_invalid")
            rows = validator(ledger, identity, envelope, payload)
        except (ValueError, KeyError, TypeError, AttributeError, ParseError):
            return reject("agent_file_audit_packet_invalid")
    elif module in ("sli.vpn-nps", "sli.radius-accounting"):
        try:
            validator = plugin_hook("sli.remote-access", "nps_agent_rows")
            if validator is None:
                return reject("agent_nps_packet_invalid")
            rows = validator(ledger, identity, envelope, payload)
        except (ValueError, KeyError, TypeError, AttributeError, ParseError):
            return reject("agent_nps_packet_invalid")
    elif module in MODULE_FAMILIES:
        from server.sli.agents.snapshot_ingest import snapshot_policy
        try:
            snapshot_policy(ledger, identity, envelope, payload)
        except ValueError as exc:
            return reject(str(exc))
        except (KeyError, TypeError):
            return reject("agent_snapshot_chunk_invalid")
    else:
        assignments = identity.get("assigned_modules", [])
        assigned = any(item == module or isinstance(item, dict) and item.get("module_id") == module
                       and item.get("enabled") is True for item in assignments)
        if not assigned:
            return reject("agent_module_not_assigned")
        policy = None
        if module in ("sli.windows.ad-dc", "sli.windows.ad-dc-history") and _module_assignment(assignments, module) is not None:
            assignment = _capture_assignment(ledger, identity, envelope)
            if assignment is None:
                return reject("agent_source_not_bound")
            try:
                build_policy = plugin_hook("sli.ad", "ad_agent_policy")
                if build_policy is None:
                    return reject("agent_source_not_bound")
                policy = build_policy(str(identity["host_id"]), assignment.get("config", {}))
            except ValueError:
                return reject("agent_source_not_bound")
            binding = {"source_instance_id": str(identity["host_id"]), "source_name": policy["source_name"],
                       "channel": "ad-dc", "module_version": "1.0.0", "policy_revision": policy["policy_revision"]}
        else:
            binding = ledger.binding(envelope["agent_id"], module)
        if not binding or any(envelope[name] != binding[name] for name in
                ("source_instance_id", "channel", "module_version", "policy_revision")):
            return reject("agent_source_not_bound")
        if module not in ("sli.windows-eventlog", "sli.windows.ad-dc", "sli.windows.ad-dc-history") or envelope["payload_contract"] != "sli.collection-packet.v1":
            return reject("agent_module_unsupported")
        try:
            rows = (_dc_event_rows(envelope, payload, binding, policy) if module in ("sli.windows.ad-dc", "sli.windows.ad-dc-history")
                    else _event_rows(envelope, payload, binding))
        except ValueError:
            return reject("agent_collection_packet_invalid")
    previous = ledger.latest(envelope["agent_id"], module)
    expected = previous["sequence"] + 1 if previous else 1
    recovery = None
    if previous and (previous["source_instance_id"] != envelope["source_instance_id"] or
                     previous["channel"] != envelope["channel"]):
        return reject("agent_stream_identity_changed")
    if envelope["sequence"] < expected:
        return reject("agent_sequence_replayed")
    if envelope["sequence"] > expected:
        boundary = getattr(ledger, "recovery_boundary", None)
        if boundary and module == "sli.heartbeat" and envelope["cursor_after"] != {
                "strategy": "record_id", "token": str(envelope["sequence"])}:
            return reject("agent_heartbeat_invalid")
        recovery = boundary(identity, envelope, previous, now) if boundary else None
        if recovery is None:
            return reject("agent_sequence_gap", "retry_later")
    # A recovery is a one-packet explicit owner authorization of both sequence
    # and cursor discontinuity. Every subsequent packet uses ordinary checks.
    if recovery is None:
        if previous and previous["generation"] == envelope["generation"]:
            if previous["cursor_after"] != envelope["cursor_before"]:
                return reject("agent_cursor_mismatch")
        elif envelope["cursor_before"]["token"] != "" or (previous and envelope["continuity_state"] != "gap"):
            return reject("agent_reset_invalid")
    if module == "sli.heartbeat" and envelope["cursor_after"] != {
            "strategy": "record_id", "token": str(envelope["sequence"])}:
        return reject("agent_heartbeat_invalid")
    if module == "sli.workstations":
        from collections import Counter
        from server.sli.agents.assignments import workstation_assignment
        from sli_agent.workstations import WorkstationsModule

        policy = WorkstationsModule(str(identity["host_id"]),
            workstation_assignment(identity["assigned_modules"]).get("config", {})).policy
        limits = policy["rate_limits"]
        counts = Counter(str(row["event_id"]) for row in rows)
        if any(counts[event] > limit for event, limit in limits.items()):
            return reject("agent_workstations_rate_limit", "retry_later")
        if any(counts[event] for event in limits):
            admitted = ledger.workstation_counts(envelope["agent_id"], policy["rate_window_seconds"])
            if any(counts[event] and counts[event] + admitted.get(event, 0) > limit
                   for event, limit in limits.items()):
                return reject("agent_workstations_rate_limit", "retry_later")
    receipt = _receipt(envelope, "committed", now=now)
    quota = ledger.quota_error(value, receipt, rows)
    if quota:
        return reject(quota, "retry_later")
    ledger.commit(value, receipt, envelope_hash, rows)
    if recovery is not None:
        ledger.accept_recovery(recovery, envelope, now)
    return receipt
