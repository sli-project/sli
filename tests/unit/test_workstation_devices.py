"""WR10: synthetic C06 publication and rolling windows, without a real DB."""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from itertools import permutations
import json
import re

import pytest

from server.sli.plugins.workstations import devices as c06, normalizers, projection
from server.sli.plugins.workstations.contracts import Workstation
from server.sli.plugins.workstations.importer import digest

NOW = datetime(2026, 10, 19, 12, tzinfo=timezone.utc)
STATION = "fixture-station"
DEVICE = r"USBSTOR\DISK&VEN_FIXTURE\FIXTURE-A&0"


def native(*, at=NOW - timedelta(days=1), record=1, device=DEVICE,
           channel="Security", provider=normalizers.SECURITY_PROVIDER, number=6416):
    observation = normalizers.normalize({"channel": channel, "provider_name": provider, "event_id": number},
        {"DeviceId": device, "DeviceDescription": "fixture-storage"}, Workstation("fixture-agent", 100))
    assert observation is not None
    observation.update({"channel": channel, "provider_name": provider, "source_sha256": digest([record, "source"])})
    return {"id": digest([record, device]), "agent_key": "fixture-agent", "family": "usb", "event_id": number,
            "observed_at": at, "observation": observation}


class PG:
    def __init__(self):
        self.seen, self.findings, self.occurrences = {}, {}, set()
        self.now, self.calls, self.fail = NOW, [], False

    @contextmanager
    def cursor(self):
        yield self

    @contextmanager
    def transaction(self):
        saved = deepcopy((self.seen, self.findings, self.occurrences))
        try:
            yield self
        except Exception:
            self.seen, self.findings, self.occurrences = saved
            raise

    def execute(self, sql, params=()):
        sql = " ".join(sql.split())
        self.calls.append((sql, params))
        self.one = None
        if sql.startswith("set local statement_timeout"):
            return
        if sql == "select transaction_timestamp() as detected_at":
            self.one = {"detected_at": self.now}
        elif sql.startswith("select * from sli_plugin_workstations.device_seen"):
            self.one = deepcopy(self.seen.get(tuple(params)))
        elif sql.startswith("select min(first_seen_at)"):
            station, now = params
            self.one = {"history_start_at": min((row["first_seen_at"] for row in self.seen.values()
                if row["station_id"] == station and row["first_seen_at"] < now), default=None)}
        elif sql.startswith("select count(distinct device_key)"):
            station, start, now = params
            self.one = {"value": len({device for item_station, device, at in self.occurrences
                                     if item_station == station and start <= at < now})}
        elif sql.startswith("insert into sli_plugin_workstations.device_seen_occurrences"):
            self.occurrences.add(tuple(params))
        elif sql.startswith("insert into sli_plugin_workstations."):
            table, columns = re.match(r"insert into sli_plugin_workstations\.(\w+) \(([^)]+)\)", sql).groups()
            row = dict(zip(columns.split(","), params))
            for key in ("first_ref", "last_ref", "subject_ref", "reason_params", "quality", "evidence_refs"):
                if key in row:
                    row[key] = json.loads(row[key])
            if table == "device_seen":
                self.seen[row["station_id"], row["device_key"]] = row
            elif table == "check_findings":
                if self.fail:
                    raise RuntimeError("fixture-publication-failed")
                old = self.findings.get(row["id"])
                if old is None:
                    self.findings[row["id"]] = {**row, "revision": 1}
                else:
                    changed = row["condition_sha256"] != old["condition_sha256"]
                    self.findings[row["id"]] = {**row, "first_detected_at": old["first_detected_at"],
                        "revision": old["revision"] + int(changed),
                        "materially_changed_at": row["materially_changed_at"] if changed else old["materially_changed_at"]}
            else:
                raise AssertionError(table)
        else:
            raise AssertionError(sql)

    def fetchone(self):
        return self.one


def apply(pg, row, station=STATION):
    with pg.transaction():
        c06.apply(pg, station, {"kind": "observations", "source_id": row["id"], "payload": row})


def test_native_provider_events_for_one_device_produce_one_row_and_finding():
    pg = PG()
    rows = [native(at=NOW - timedelta(hours=3)),
            native(record=2, at=NOW - timedelta(hours=2), device=DEVICE.lower(), number=400,
                   channel=normalizers.PNP_CHANNEL, provider=normalizers.PNP_PROVIDER),
            native(record=3, at=NOW - timedelta(hours=1), number=2003,
                   channel=normalizers.DRIVER_CHANNEL, provider=normalizers.DRIVER_PROVIDER)]
    for row in reversed(rows):
        apply(pg, row)
    assert len(pg.seen) == len(pg.findings) == 1
    seen, finding = next(iter(pg.seen.values())), next(iter(pg.findings.values()))
    assert seen["first_seen_at"] == rows[0]["observed_at"]
    assert seen["last_seen_at"] == rows[-1]["observed_at"]
    assert finding["fact_at"] == rows[0]["observed_at"]
    assert finding["evidence_refs"] == [c06.event(rows[0])["ref"], c06.event(rows[-1])["ref"]]
    assert finding["subject_ref"]["serial"] is None
    assert finding["reason_params"]["actor_status"] == "unknown"
    assert finding["reason_params"]["cross_station_status"] == "unavailable"
    assert finding["quality"]["status"] == "partial"
    assert len(pg.occurrences) == 3
    assert c06.summary(pg, STATION, now=NOW)["devices_7d"] == {"value": 1, "relation": "at_least"}
    assert not any("from sli_plugin_workstations.observations" in sql or "projection_work" in sql for sql, _ in pg.calls)


def test_full_ids_and_stations_do_not_merge_on_description_or_suffix():
    pg = PG()
    for row in (native(), native(record=2, device=DEVICE.replace("VEN_FIXTURE", "VEN_OTHER"))):
        apply(pg, row)
    apply(pg, native(), "fixture-other-station")
    assert len(pg.seen) == len(pg.findings) == 3
    assert c06.summary(pg, STATION, now=NOW)["devices_7d"]["value"] == 2
    assert c06.summary(pg, "fixture-other-station", now=NOW)["devices_7d"]["value"] == 1
    for sql, params in pg.calls:
        if sql.startswith("select min(") or sql.startswith("select count("):
            assert "where station_id=%s" in sql and params[0] in (STATION, "fixture-other-station")


def test_late_earlier_event_preserves_detection_and_replay_does_not_revise():
    pg = PG()
    recent, old = native(), native(at=NOW - timedelta(days=60), record=2)
    apply(pg, recent)
    original_id = next(iter(pg.findings))
    pg.now += timedelta(hours=1)
    apply(pg, old)
    finding = deepcopy(pg.findings[original_id])
    assert finding["first_detected_at"] == NOW
    assert finding["fact_at"] == old["observed_at"]
    assert finding["last_observed_at"] == recent["observed_at"]
    for row in (recent, old, recent):
        apply(pg, row)
    assert pg.findings[original_id] == finding
    assert len(pg.occurrences) == 2
    assert c06.summary(pg, STATION, now=NOW)["history_start_at"] == old["observed_at"].isoformat()


def test_repeat_sighting_updates_last_seen_without_marking_device_new_again():
    pg = PG()
    apply(pg, native())
    pg.now += timedelta(hours=1)
    apply(pg, native(record=2, at=NOW - timedelta(hours=1)))
    finding = next(iter(pg.findings.values()))
    assert finding["revision"] == 1
    assert finding["materially_changed_at"] == finding["first_detected_at"] == NOW
    assert finding["last_observed_at"] == NOW - timedelta(hours=1)
    assert len(finding["evidence_refs"]) == 2


def test_simultaneous_refs_are_deterministic_in_every_delivery_order():
    rows = [native(record=record) for record in (1, 2, 3)]
    results = []
    for order in permutations(rows):
        pg = PG()
        for row in order:
            apply(pg, row)
        seen = next(iter(pg.seen.values()))
        finding = next(iter(pg.findings.values()))
        results.append((seen, finding["condition_sha256"], finding["evidence_refs"]))
        assert len(pg.occurrences) == 1
    assert all(result == results[0] for result in results)


def test_seven_days_is_exact_half_open_window_including_earlier_sighting_of_future_device():
    pg = PG()
    for record, delta in enumerate((timedelta(days=7), timedelta(days=7, microseconds=1),
                                    timedelta(), timedelta(microseconds=-1)), 1):
        apply(pg, native(at=NOW - delta, record=record, device=DEVICE + str(record)))
    # This device has a future last_seen but also a valid in-window occurrence.
    apply(pg, native(record=10))
    apply(pg, native(record=11, at=NOW + timedelta(days=2)))
    result = c06.summary(pg, STATION, now=NOW)
    assert result["devices_7d"] == {"value": 2, "relation": "at_least"}
    assert result["window_start_at"] == (NOW - timedelta(days=7)).isoformat()
    assert result["window_end_at"] == NOW.isoformat()


def test_history_boundary_empty_unknown_and_expired_window_lower_bound():
    pg = PG()
    result = c06.summary(pg, STATION, now=NOW)
    assert result["devices_7d"] == {"value": None, "relation": "unknown"}
    assert result["quality"]["status"] == "not_collected" and result["history_start_at"] is None
    apply(pg, native(at=NOW - timedelta(hours=1)))
    result = c06.summary(pg, STATION, now=NOW)
    assert result["history_start_at"] > result["window_start_at"]
    assert result["devices_7d"]["relation"] == "at_least"
    result = c06.summary(pg, STATION, now=NOW + timedelta(days=8))
    assert result["devices_7d"] == {"value": 0, "relation": "at_least"}
    assert result["quality"]["status"] == "partial" and result["baseline_status"] == "unknown"


@pytest.mark.parametrize("defect", ["family", "provider", "channel", "number", "missing", "blank", "long", "truncated", "not_storage", "string_storage"])
def test_non_storage_or_unproven_identity_does_not_create_rows_or_counts(defect):
    row, pg = native(), PG()
    if defect == "family":
        row["family"] = "processes"
    elif defect in ("provider", "channel"):
        row["observation"]["provider_name" if defect == "provider" else defect] = "fixture-wrong"
    elif defect == "number":
        row["event_id"] = 400
    else:
        row["observation"]["facts"].update({
            "missing": {"device_id": None}, "blank": {"device_id": " - "}, "long": {"device_id": "x" * 513},
            "truncated": {"device_id": "x" * 512},
            "not_storage": {"storage_evidence": False}, "string_storage": {"storage_evidence": "true"}}[defect])
    apply(pg, row)
    assert pg.calls == [] and not pg.seen and not pg.findings
    assert c06.summary(pg, STATION, now=NOW)["devices_7d"]["value"] is None


def test_rollback_covers_seen_occurrences_and_finding_then_replay_recovers():
    pg, row = PG(), native()
    pg.fail = True
    with pytest.raises(RuntimeError, match="publication-failed"):
        apply(pg, row)
    assert pg.seen == pg.findings == {} and pg.occurrences == set()
    pg.fail = False
    apply(pg, row)
    apply(pg, row)
    assert len(pg.seen) == len(pg.findings) == len(pg.occurrences) == 1


def test_timestamps_require_timezone_and_are_normalized_to_utc():
    row = native(at="2026-10-19T18:00:00+07:00")
    assert c06.event(row)["at"] == NOW - timedelta(hours=1)
    row["observed_at"] = "2026-10-19T12:00:00"
    with pytest.raises(ValueError, match="timestamp_invalid"):
        c06.event(row)
    row = native()
    row["id"] = "fixture-invalid"
    with pytest.raises(ValueError, match="observation_id_invalid"):
        c06.event(row)


def test_c06_is_registered_as_independent_versioned_consumer_and_skips_other_inputs():
    rule = next(item for item in projection.projectors() if item.key == c06.PROJECTOR)
    assert rule.version == 1 and rule.apply is c06.apply
    pg = PG()
    rule.apply(pg, STATION, {"kind": "station_inventory"})
    assert pg.calls == []


class BatchPG(PG):
    def execute(self, sql, params=()):
        if sql.lstrip().startswith('with selected as'):
            self.calls.append((sql, params))
            stations, now, start, end = params
            assert now == end
            self.rows = []
            for station in stations:
                boundary = min((row['first_seen_at'] for row in self.seen.values()
                    if row['station_id'] == station and row['first_seen_at'] < now), default=None)
                count = len({device for item, device, at in self.occurrences if item == station and start <= at < end})
                self.rows.append({'station_id': station, 'history_start_at': boundary, 'value': count})
        else:
            super().execute(sql, params)
    def fetchall(self):
        return self.rows


def test_registered_c06_to_batched_count_preserves_distinct_window_and_unknown():
    pg = BatchPG()
    rule = next(item for item in projection.projectors() if item.key == c06.PROJECTOR)
    rows = [native(record=1, at=NOW-timedelta(days=7)), native(record=2),
            native(record=3, device=DEVICE+'old', at=NOW-timedelta(days=7, microseconds=1)),
            native(record=4, device=DEVICE+'future', at=NOW), native(record=5, at=NOW+timedelta(days=1))]
    for row in [*rows, rows[0]]:
        with pg.transaction():
            rule.apply(pg, STATION, {'kind': 'observations', 'source_id': row['id'], 'payload': row})
    # Same native ID on another station is never an additional local device.
    rule.apply(pg, 'hidden-station', {'kind': 'observations', 'source_id': rows[1]['id'], 'payload': rows[1]})
    before = len(pg.calls)
    result = c06.summaries(pg, [STATION, 'unobserved-station'], now=NOW)
    assert len(pg.calls) == before + 1
    assert result[STATION]['devices_7d'] == {'value': 1, 'relation': 'at_least'}
    assert result[STATION]['baseline_status'] == 'unknown'
    assert result['unobserved-station']['devices_7d'] == {'value': None, 'relation': 'unknown'}
    assert 'hidden-station' not in result
    assert result[STATION] == c06.summary(pg, STATION, now=NOW)
    assert c06.summaries(pg, [STATION], now=NOW+timedelta(days=9))[STATION]['devices_7d'] == {'value': 0, 'relation': 'at_least'}


@pytest.mark.parametrize('stations', [['a']*2, ['a']*52, [''], [None], 'station'])
def test_device_batch_rejects_invalid_scope_or_size_before_sql(stations):
    pg = BatchPG()
    with pytest.raises(ValueError, match='device_summary_batch_invalid'):
        c06.summaries(pg, stations, now=NOW)
    assert pg.calls == []


def test_device_batch_empty_has_no_query_and_51_is_supported():
    pg = BatchPG()
    assert c06.summaries(pg, [], now=NOW) == {} and pg.calls == []
    assert len(c06.summaries(pg, [f's-{n}' for n in range(51)], now=NOW)) == 51
    assert len(pg.calls) == 1
