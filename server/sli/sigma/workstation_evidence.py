"""Exact WS evidence for dry-run mapping; no core-event IDs or publication.

The caller supplies an authorized agent key and trusted installation/source/
generation scope. This is a worker reader, not a public authorization endpoint.
Connections and the history adapter are injected; no implicit runtime IO.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from server.sli.plugins.workstations.importer import digest
from server.sli.sigma.windows_mapping import EventScope, MappedWindowsEvent, map_windows_event


class SigmaEvidenceError(ValueError):
    """Fixed codes only; never disclose source evidence in diagnostics."""


@dataclass(frozen=True, repr=False)
class WorkstationEvidenceRef:
    observation_id: str
    observation_sha256: str
    source_xml_sha256: str

    def __post_init__(self):
        if any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in (
            self.observation_id, self.observation_sha256, self.source_xml_sha256,
        )):
            raise SigmaEvidenceError("sigma_ws_reference_invalid")


@dataclass(frozen=True)
class WorkstationEvidence:
    ref: WorkstationEvidenceRef = field(repr=False)
    event: MappedWindowsEvent = field(repr=False)
    storage_kind: str = field(default="workstation_observation", init=False)


def _stamp(value):
    stamp = value if isinstance(value, datetime) else datetime.fromisoformat(
        re.sub(r"(\.\d{6})\d+(?=Z$)", r"\1", value).replace("Z", "+00:00"))
    if stamp.utcoffset() is None:
        raise ValueError
    return stamp


def _hot_row(row, scope, family="processes"):
    """Validate the full immutable observation before discarding projections."""
    body = row["observation"]
    if (digest(body) != row["observation_sha256"] or row["family"] != family
            or body["generation"] != scope.source_generation
            or any(body[key] != row[key] for key in ("agent_key", "entity_id", "ad_computer_id", "family", "event_id"))
            or _stamp(body["observed_at"]) != _stamp(row["observed_at"])):
        raise SigmaEvidenceError("sigma_ws_evidence_mismatch")
    return {**row, "source_sha256": body["source_sha256"]}


def _verify(row, *, ref, scope, agent_key, start, end):
    if (row["id"] != ref.observation_id or row["agent_key"] != agent_key
            or row["observation_sha256"] != ref.observation_sha256
            or row["source_sha256"] != ref.source_xml_sha256
            or not start <= _stamp(row["observed_at"]) < end):
        raise SigmaEvidenceError("sigma_ws_evidence_mismatch")
    event = map_windows_event(row["source_xml"], scope=scope)
    native = event.identity
    if (native.source_xml_sha256 != ref.source_xml_sha256 or native.event_id != row["event_id"]
            or _stamp(native.occurred_at) != _stamp(row["observed_at"])
            or digest([agent_key, native.channel, scope.source_generation, native.record_id]) != ref.observation_id):
        raise SigmaEvidenceError("sigma_ws_evidence_mismatch")
    if "observation" in row:
        body = row["observation"]
        if any(body[key] != value for key, value in (
            ("record_id", native.record_id), ("channel", native.channel), ("provider_name", native.provider_name),
        )):
            raise SigmaEvidenceError("sigma_ws_evidence_mismatch")
    return WorkstationEvidence(ref, event)


def read_workstation_evidence(conn, *, ref: WorkstationEvidenceRef, scope: EventScope,
                             agent_key: str, start: datetime, end: datetime, history=None,
                             family: str = "processes") -> WorkstationEvidence:
    """Read one immutable WS observation from PostgreSQL, then cold history.

    HistoryAdapter.read verifies the entire cold payload and routing columns;
    its exact-ID mode returns retained XML and hashes, never just facts.
    No row is substituted after a hot-copy conflict or integrity failure.
    The window and agent key are passed to both stores and checked again here.
    """
    if (family not in ("processes", "protection")
            or not isinstance(ref, WorkstationEvidenceRef) or not isinstance(scope, EventScope)
            or not isinstance(agent_key, str) or not agent_key.strip()
            or agent_key != agent_key.strip() or len(agent_key) > 256):
        raise SigmaEvidenceError("sigma_ws_scope_invalid")
    try:
        start, end = _stamp(start), _stamp(end)
        if start >= end or end - start > timedelta(days=3650):
            raise ValueError
    except (TypeError, ValueError, AttributeError):
        raise SigmaEvidenceError("sigma_ws_window_invalid") from None

    try:
        with conn.cursor() as cur:
            cur.execute(f"""
                select id,agent_key,entity_id,ad_computer_id,family,event_id,observed_at,
                       observation,observation_sha256,source_xml
                from sli_plugin_workstations.observations
                where agent_key=%s and id=%s and family='{family}'
                  and observed_at>=%s and observed_at<%s
                limit 2
            """, (agent_key, ref.observation_id, start, end))
            rows = list(cur.fetchall())
    except Exception:
        raise SigmaEvidenceError("sigma_ws_store_unavailable") from None
    try:
        if len(rows) > 1:
            raise SigmaEvidenceError("sigma_ws_evidence_mismatch")
        if rows:
            row = _hot_row(rows[0], scope, family)
        else:
            if history is None:
                raise SigmaEvidenceError("sigma_ws_history_unavailable")
            try:
                rows = list(history.read(keys=(agent_key,), family=family, start=start, end=end,
                                         cursor="", limit=2, observation_id=ref.observation_id))
            except ValueError:
                raise SigmaEvidenceError("sigma_ws_evidence_mismatch") from None
            except Exception:
                raise SigmaEvidenceError("sigma_ws_history_unavailable") from None
            if not rows:
                raise SigmaEvidenceError("sigma_ws_evidence_not_found")
            if len(rows) != 1:
                raise SigmaEvidenceError("sigma_ws_evidence_mismatch")
            row = rows[0]
        if family == "protection" and (row["family"] != family or row["event_id"] not in (1102, 7036, 7040, 4104)):
            raise SigmaEvidenceError("sigma_ws_evidence_mismatch")
        return _verify(row, ref=ref, scope=scope, agent_key=agent_key, start=start, end=end)
    except SigmaEvidenceError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError):
        raise SigmaEvidenceError("sigma_ws_evidence_mismatch") from None
