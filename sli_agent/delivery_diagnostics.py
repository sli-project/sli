"""Bounded delivery observations, never packet payloads or exception diagnostics."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import re
from uuid import UUID

from sli_agent.envelope import canonical, timestamp
from sli_agent.protection import atomic_write

MAX_ITEMS = 16
FIELDS = frozenset({"module_id", "packet_id", "sequence", "error_code", "receipt_status", "http_status",
                    "observed_at_utc", "resolved_at_utc"})
RECEIPT_STATUSES = frozenset({"rejected", "retry_later", "invalid", "unavailable"})
ERROR_CODES = frozenset({
    "agent_delivery_rejected", "agent_receipt_invalid", "agent_transport_failed", "agent_packet_invalid",
    "agent_sequence_gap", "agent_sequence_replayed", "agent_sequence_conflict", "agent_packet_id_conflict", "agent_cursor_mismatch",
    "agent_identity_mismatch", "agent_stream_identity_changed", "agent_reset_invalid", "agent_replay_window",
    "agent_history_pending", "agent_source_not_bound", "agent_module_not_assigned", "agent_module_unsupported", "agent_heartbeat_invalid",
    "agent_collection_packet_invalid", "agent_workstations_packet_invalid", "agent_workstations_rate_limit",
    "agent_file_audit_packet_invalid", "agent_nps_packet_invalid", "agent_snapshot_chunk_invalid",
    "agent_snapshot_cycle_conflict", "agent_snapshot_chunk_conflict",
    *("agent_" + kind + name + "_limit" for kind in ("inbox_", "snapshot_")
      for name in ("agent_count", "agent_bytes", "module_count", "module_bytes", "global_count", "global_bytes", "storage_bytes")),
})


def safe_code(value):
    return value if isinstance(value, str) and value in ERROR_CODES else "agent_delivery_rejected"


def validate_observations(values):
    try:
        if not isinstance(values, list) or len(values) > MAX_ITEMS:
            raise ValueError()
        modules = set()
        for item in values:
            if not isinstance(item, dict) or set(item) != FIELDS:
                raise ValueError()
            module = item["module_id"]
            if (not isinstance(module, str) or re.fullmatch(r"[a-z][a-z0-9_.-]{0,127}", module) is None
                    or module in modules or not isinstance(item["packet_id"], str)
                    or str(UUID(item["packet_id"])) != item["packet_id"]
                    or not isinstance(item["sequence"], str)
                    or re.fullmatch(r"0|[1-9][0-9]{0,18}", item["sequence"]) is None
                    or int(item["sequence"]) > 2**63 - 1
                    or not isinstance(item["error_code"], str) or item["error_code"] not in ERROR_CODES
                    or not isinstance(item["receipt_status"], str) or item["receipt_status"] not in RECEIPT_STATUSES
                    or item["http_status"] is not None and (type(item["http_status"]) is not int
                        or not 100 <= item["http_status"] <= 599)):
                raise ValueError()
            modules.add(module)
            observed = item["observed_at_utc"]
            resolved = item["resolved_at_utc"]
            if (not isinstance(observed, str) or len(observed) > 40
                    or resolved is not None and (not isinstance(resolved, str) or len(resolved) > 40
                                                or timestamp(resolved) < timestamp(observed))):
                raise ValueError()
            timestamp(observed)
        return deepcopy(values)
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ValueError("agent_delivery_diagnostics_invalid") from None


class DeliveryHealth:
    def __init__(self, storage_dir):
        self.path = storage_dir / "delivery-health.json"
        self.items = {}
        try:
            if self.path.stat().st_size <= 16384:
                self.items = {item["module_id"]: item for item in
                              validate_observations(json.loads(self.path.read_text("utf-8")))}
        except (OSError, ValueError):
            pass

    def observations(self):
        return validate_observations(list(self.items.values()))

    def observe(self, value, receipt, *, accepted, error=None, now=None):
        envelope = value["envelope"]
        module = envelope["module_id"]
        now = now or datetime.now(timezone.utc)
        old = self.items.get(module)
        if accepted:
            # Another stream's successful heartbeat is not recovery evidence.
            if old is None or old["packet_id"] != envelope["packet_id"] or old["resolved_at_utc"] is not None:
                return
            item = {**old, "resolved_at_utc": max(timestamp(old["observed_at_utc"]), now).isoformat()}
        else:
            status, code = "invalid", "agent_receipt_invalid"
            http_status = 200 if error is None else getattr(error, "http_status", None)
            if type(http_status) is not int or not 100 <= http_status <= 599:
                http_status = None
            if error is not None:
                status, code = "unavailable", "agent_transport_failed"
            elif (isinstance(receipt, dict) and receipt.get("contract_id") == "sli.agent-receipt.v1"
                  and receipt.get("packet_id") == envelope["packet_id"]
                  and receipt.get("payload_sha256") == envelope["payload_sha256"]
                  and receipt.get("status") in ("rejected", "retry_later")):
                status, code = receipt["status"], safe_code(receipt.get("error_code"))
            item = {"module_id": module, "packet_id": envelope["packet_id"], "sequence": str(envelope["sequence"]),
                    "error_code": code, "receipt_status": status, "http_status": http_status,
                    "observed_at_utc": now.isoformat(), "resolved_at_utc": None}
        validate_observations([item])
        self.items.pop(module, None)
        self.items[module] = item
        while len(self.items) > MAX_ITEMS:
            del self.items[next(iter(self.items))]
        atomic_write(self.path, canonical(self.observations()))

    def status_fields(self):
        items = self.observations()
        active = [item for item in items if item["resolved_at_utc"] is None]
        last = (active or items or [None])[-1]
        return {"delivery_diagnostics": items,
                **{"last_delivery_" + key: last[source] if last else None for key, source in (
                    ("error_code", "error_code"), ("receipt_status", "receipt_status"), ("http_status", "http_status"),
                    ("module_id", "module_id"), ("packet_id", "packet_id"), ("sequence", "sequence"),
                    ("at_utc", "observed_at_utc"), ("resolved_at_utc", "resolved_at_utc"))}}
