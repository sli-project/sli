"""Immutable workstation evidence, acknowledged only after exact CH readback.

Schema provisioning is explicit. Readers never create tables or start retention.
There is no history TTL: the complete observation and source XML remain available.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timedelta
from pathlib import Path

from server.sli.plugins.workstations.importer import digest
from server.sli.storage import permanent_fact_history as ch

TABLE = "sli_history.workstation_observations"
SCHEMA = Path(__file__).resolve().parents[3] / "config/clickhouse/005_workstation_history.sql"
FAMILIES = frozenset({"processes", "usb"})
MAX_DAYS = 3650
_FIELDS = frozenset({"id", "agent_key", "entity_id", "ad_computer_id", "family", "event_id",
                     "observed_at", "observation", "observation_sha256", "source_xml"})


def _stamp(value):
    stamp = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if stamp.utcoffset() is None:
        raise ValueError("workstation_history_receipt_mismatch")
    return stamp


def _validate(row):
    if (set(row) != _FIELDS or row["family"] not in FAMILIES
            or len(row["id"]) != 64 or any(ch not in "0123456789abcdef" for ch in row["id"])
            or not isinstance(row["agent_key"], str) or not row["agent_key"].strip()
            or row["agent_key"] != row["agent_key"].strip() or len(row["agent_key"]) > 256
            or type(row["entity_id"]) is not int or row["entity_id"] <= 0
            or (row["ad_computer_id"] is not None and
                (type(row["ad_computer_id"]) is not int or row["ad_computer_id"] <= 0))
            or type(row["event_id"]) is not int or row["event_id"] <= 0
            or not isinstance(row["source_xml"], str) or not 1 <= len(row["source_xml"].encode()) <= 1048576
            or digest(row["observation"]) != row["observation_sha256"]
            or hashlib.sha256(row["source_xml"].encode()).hexdigest() != row["observation"]["source_sha256"]):
        raise ValueError("workstation_history_receipt_mismatch")
    _stamp(row["observed_at"])


def _record(row):
    return {key: row[key] for key in ("id", "agent_key", "entity_id", "ad_computer_id", "family", "event_id")} | {
        "observed_at": ch._ch_time(_stamp(row["observed_at"])), "payload_sha256": digest(row),
        "payload_json": json.dumps(row, sort_keys=True, ensure_ascii=True, separators=(",", ":"))}


def _decode(record):
    try:
        row = json.loads(record["payload_json"])
        _validate(row)
        expected = _record(row)
        actual = {**record, "observed_at": ch._json_ch_time(record["observed_at"])}
        # JSONEachRow normally quotes UInt64 values to preserve integer precision.
        for key in ("entity_id", "ad_computer_id", "event_id"):
            if isinstance(actual[key], str) and actual[key].isascii() and actual[key].isdecimal():
                actual[key] = int(actual[key])
        # Compare all routing columns, not only a hash returned by the server.
        if actual != expected:
            raise ValueError("workstation_history_receipt_mismatch")
        return row
    except (KeyError, TypeError, AttributeError, ValueError) as error:
        raise ValueError("workstation_history_receipt_mismatch") from error


def report_row(row, *, evidence=False):
    body = row["observation"]
    item = {key: row[key] for key in ("id", "agent_key", "entity_id", "ad_computer_id", "event_id",
                                    "observed_at", "observation_sha256")}
    item.update(semantic_type=body.get("semantic_type"), facts=body.get("facts"), quality=body.get("quality"))
    if evidence:
        item.update(source_xml=row["source_xml"], source_sha256=body["source_sha256"])
    return item


def ensure_schema(port):
    for statement in SCHEMA.read_text(encoding="utf-8").split(";"):
        if statement.strip():
            ch._http_query(port, statement.strip())


class ClickHouseHistoryAdapter:
    def __init__(self, port):
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("workstation_history_port_invalid")
        self.port = port

    def _rows(self, sql, params):
        try:
            return ch._rows(self.port, sql, query_params=params)
        except Exception:
            # Do not expose transport credentials, URLs, SQL or evidence in receipts.
            raise RuntimeError("workstation_history_unavailable") from None

    def preserve(self, observation):
        _validate(observation)
        schema = self._rows("SELECT engine,sorting_key,partition_key,create_table_query FROM system.tables "
                            "WHERE database='sli_history' AND name='workstation_observations'", {})
        if (len(schema) != 1 or schema[0]["engine"] != "ReplacingMergeTree"
                or schema[0]["sorting_key"] != "id" or schema[0]["partition_key"] not in {"", "tuple()"}
                or "TTL" in schema[0]["create_table_query"]
                or any(not re.search(rf"\b{setting}\s*=\s*1\b", schema[0]["create_table_query"])
                       for setting in ("fsync_after_insert", "fsync_part_directory"))):
            raise ValueError("workstation_history_durability_unverified")
        expected = _record(observation)
        sql = f"SELECT * FROM {TABLE} FINAL WHERE id={{id:String}} LIMIT 2"
        parameters = {"id": observation["id"]}
        actual = self._rows(sql, parameters)
        if not actual:
            try:
                # Override user/server async defaults: an enqueue is insufficient.
                # The verified table fsyncs both files and the part directory.
                payload = json.dumps(expected, ensure_ascii=True, separators=(",", ":"))
                ch._http_query(self.port, f"INSERT INTO {TABLE} FORMAT JSONEachRow\n{payload}",
                               params={"async_insert": "0", "wait_for_async_insert": "1"}, timeout=65)
            except Exception:
                raise RuntimeError("workstation_history_unavailable") from None
            actual = self._rows(sql, parameters)
        if len(actual) != 1 or _decode(actual[0]) != observation:
            raise ValueError("workstation_history_receipt_mismatch")
        return expected["payload_sha256"]

    def read(self, *, keys, family, start, end, cursor, limit, observation_id=None):
        if (family not in FAMILIES or not 1 <= len(keys) <= 500 or type(limit) is not int
                or not 1 <= limit <= 501 or start >= end or end - start > timedelta(days=MAX_DAYS)):
            raise ValueError("workstation_history_query_invalid")
        keys_json = json.dumps(list(keys), ensure_ascii=False).encode("utf-8")
        params = {"keys": base64.b64encode(keys_json).decode("ascii"), "family": family, "start": ch._ch_time(_stamp(start)),
                  "end": ch._ch_time(_stamp(end)), "cursor": cursor, "limit": str(limit)}
        exact = ""
        if observation_id is not None:
            params["id"] = observation_id
            exact = " AND id={id:String}"
        # HTTP Array(String) parameters use ClickHouse's quoted array syntax,
        # not JSON. Base64 also protects JSON escapes from String parameter decoding.
        sql = (f"SELECT * FROM {TABLE} FINAL WHERE agent_key IN JSONExtract(base64Decode({{keys:String}}),'Array(String)')"
               " AND family={family:String}"
               " AND observed_at>={start:DateTime64(6)} AND observed_at<{end:DateTime64(6)} AND id>{cursor:String}"
               " AND ({family:String}<>'usb' OR JSONExtractBool(payload_json,'observation','facts','storage_evidence'))"
               f"{exact} ORDER BY id LIMIT {{limit:UInt16}}")
        rows = [_decode(record) for record in self._rows(sql, params)]
        # Independently validate the returned identities before exposing evidence.
        for row in rows:
            if (row["agent_key"] not in keys or row["family"] != family
                    or not start <= _stamp(row["observed_at"]) < end or row["id"] <= cursor
                    or (observation_id is not None and row["id"] != observation_id)
                    or (family == "usb" and row["observation"].get("facts", {}).get("storage_evidence") is not True)):
                raise ValueError("workstation_history_receipt_mismatch")
        if len(rows) > limit or [row["id"] for row in rows] != sorted({row["id"] for row in rows}):
            raise ValueError("workstation_history_receipt_mismatch")
        return [report_row(row, evidence=observation_id is not None) for row in rows]


def configured_history():
    port = ch.configured_read_port()
    return ClickHouseHistoryAdapter(port) if port is not None else None
