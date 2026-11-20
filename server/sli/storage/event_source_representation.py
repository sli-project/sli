"""Additive preferred source; immutable allocation/core hashes stay untouched."""
from __future__ import annotations

import hashlib
import importlib
import json

from server.sli.storage.event_source_identity import (
    IDENTITY_VERSION,
    RepresentationConflict,
    digest,
    event_identity_hash,
    legacy_event_hash,
    preferred_representation,
)
from server.sli.storage.storage_v2_archive import (
    ArchiveIntegrityError,
    ArchiveObjectUnavailableError,
    ArchiveReader,
)


def packet_source_row(summary, packet):
    rows = packet["event_rows"]
    if (not isinstance(rows, list) or not rows or len(rows) > 5000
            or any(not isinstance(row, dict) for row in rows)):
        raise ArchiveIntegrityError("agent event packet row bound invalid")
    raw = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows).encode("utf-8")
    if "attested_packet" in packet:
        from server.sli.sources.collection_packet_import import event_rows_from_packet

        def receipt_digest(value):
            return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()

        try:
            envelope = packet["attested_envelope"]
            valid = (receipt_digest(envelope) == packet["envelope_sha256"]
                and envelope["packet_id"] == packet["packet_id"]
                and receipt_digest(packet["attested_packet"]) == envelope["payload_sha256"]
                and event_rows_from_packet(packet["attested_packet"]) == rows)
        except (KeyError, ValueError, TypeError):
            valid = False
        if not valid:
            raise ArchiveIntegrityError("agent event packet receipt mismatch")
    elif hashlib.sha256(raw).hexdigest() != packet["raw_sha256"]:
        raise ArchiveIntegrityError("agent event packet checksum mismatch")
    expected = summary["normalized_hash"]
    expected = expected if isinstance(expected, str) else bytes(expected).hex()
    matches = [row for row in rows if legacy_event_hash(row) == expected or event_identity_hash(row) == expected]
    if len(matches) != 1:
        raise ArchiveIntegrityError("agent event packet exact identity mismatch")
    return matches[0]


def source_payload(summary, row):
    importer = importlib.import_module("scripts.import.import_event_jsonl_to_postgres")
    result = importer.build_direct_event_source_row(
        event_db_id=int(summary["id"]), raw_log_file_id=int(summary["raw_log_file_id"]),
        server_id=int(summary["server_id"]), domain_id=int(summary["domain_id"]),
        site_id=summary.get("site_id"), log_source_id=int(summary["log_source_id"]),
        normalized_at=str(summary["time_created_utc"]), row=row,
        event_data=importer.parse_event_data(row.get("xml")),
    )
    expected = summary["normalized_hash"]
    result["normalized_hash"] = expected if isinstance(expected, str) else bytes(expected).hex()
    return result


def verified_preferred_row(summary, stored):
    if (int(stored["identity_version"]) != IDENTITY_VERSION
            or bytes(stored["normalized_hash"]) != bytes(summary["normalized_hash"])
            or digest(stored["representation"]) != bytes(stored["representation_sha256"]).hex()
            or event_identity_hash(stored["representation"]) != bytes(stored["canonical_hash"]).hex()):
        raise ArchiveIntegrityError("preferred event representation integrity mismatch")
    return stored["representation"]


def verified_preferred_payload(summary, stored):
    return source_payload(summary, verified_preferred_row(summary, stored))


def _retained_source(cur, connection_factory, event_id):
    from server.sli.storage.storage_v2_repository import PostgresArchiveManifestStore
    from server.sli.storage.storage_v2_runtime import (
        PostgresStorageV2ReadStore,
        StorageV2RuntimeReader,
    )

    summary = PostgresStorageV2ReadStore(connection_factory).get_event_summary(event_id)
    if summary is None:
        raise RepresentationConflict("event_retained_source_unavailable")
    cur.execute("select public.event_source_packet_v284(%s) as packet", (event_id,))
    packet = cur.fetchone()["packet"]
    try:
        if packet:
            row = packet_source_row(summary, packet)
            StorageV2RuntimeReader._verify_core_identity(summary, source_payload(summary, row))
            return row
        payload = ArchiveReader(PostgresArchiveManifestStore(connection_factory)).read_event(
            archive_kind="event", event_id=event_id)
        StorageV2RuntimeReader._verify_core_identity(summary, payload)
        expected, actual = summary["normalized_hash"], payload.get("normalized_hash")
        expected = expected if isinstance(expected, str) else bytes(expected).hex()
        actual = actual if isinstance(actual, str) else bytes(actual or b"").hex()
        if actual != expected:
            raise RepresentationConflict("event_retained_hash_differs")
    except (FileNotFoundError, ArchiveObjectUnavailableError, ArchiveIntegrityError):
        raise RepresentationConflict("event_retained_source_unavailable") from None
    from sli_collect.eventlog import parse_event_xml

    # The published archive already verifies the old normalized hash. Rebuild
    # intrinsic native fields from its retained XML, never from incoming XML.
    return parse_event_xml(payload["record_xml"], source_name=payload["computer"],
                           connect_address="", channel=payload["channel"])


def reconcile_representation(cur, connection_factory, result, incoming, *, persist=True):
    event_id = int(result["id"])
    retained_hash = bytes(result["normalized_hash"])
    if (result.get("allocated_hash") is not None and bytes(result["allocated_hash"]) != retained_hash
            or result.get("published") and bytes(result.get("core_hash") or b"") != retained_hash):
        raise RepresentationConflict("event_retained_hash_differs")
    canonical_hash = bytes.fromhex(event_identity_hash(incoming))
    cur.execute("select * from event_source_representations_v2 where event_id=%s" +
                (" for update" if persist else ""), (event_id,))
    stored = cur.fetchone()
    if stored:
        if (int(stored["identity_version"]) != IDENTITY_VERSION
                or bytes(stored["normalized_hash"]) != retained_hash
                or digest(stored["representation"]) != bytes(stored["representation_sha256"]).hex()
                or event_identity_hash(stored["representation"]) != bytes(stored["canonical_hash"]).hex()):
            raise RepresentationConflict("event_retained_hash_differs")
        preferred = preferred_representation(stored["representation"], incoming)
    else:
        if result.get("published"):
            old = _retained_source(cur, connection_factory, event_id)
        elif retained_hash == canonical_hash or retained_hash.hex() == legacy_event_hash(incoming):
            old = incoming
        else:
            raise RepresentationConflict("event_retained_source_unavailable")
        preferred = preferred_representation(old, incoming)
    if persist:
        # Serialize first publication too: concurrent contenders read the winner
        # under a row lock before comparing. Never ON CONFLICT overwrite bodies.
        cur.execute("""insert into event_source_representations_v2
            (event_id,normalized_hash,identity_version,canonical_hash,representation,representation_sha256)
            values(%s,%s,%s,%s,%s::jsonb,%s) on conflict(event_id) do nothing""",
            (event_id, retained_hash, IDENTITY_VERSION, canonical_hash, json.dumps(preferred, ensure_ascii=False),
             bytes.fromhex(digest(preferred))))
        cur.execute("select * from event_source_representations_v2 where event_id=%s for update", (event_id,))
        winner = cur.fetchone()
        if bytes(winner["normalized_hash"]) != retained_hash or bytes(winner["canonical_hash"]) != canonical_hash:
            raise RepresentationConflict("event_retained_hash_differs")
        preferred = preferred_representation(winner["representation"], preferred)
        if preferred != winner["representation"]:
            cur.execute("""update event_source_representations_v2
                set representation=%s::jsonb,representation_sha256=%s where event_id=%s""",
                (json.dumps(preferred, ensure_ascii=False), bytes.fromhex(digest(preferred)), event_id))
    return preferred
