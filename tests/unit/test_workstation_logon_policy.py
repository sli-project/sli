"""WR11/C07: synthetic policies and native sign-ins, no DB or source I/O."""
from copy import deepcopy
from contextlib import contextmanager
import json

import pytest

from server.sli.core import platform_settings
from server.sli.plugins.workstations import logon_policy as c07, normalizers, projection
from server.sli.plugins.workstations.contracts import Workstation
from server.sli.plugins.workstations.importer import digest
from tests.unit.test_workstation_projection import PG as QueuePG, prepare

OU = "ou=fixture,dc=example,dc=invalid"
STATION = {"station_id": "fixture-station", "agent_key": "fixture-agent", "domain_id": 11,
           "ou_entity_id": None, "metadata": {"ou_path": OU}}


def config(*, version=1, **changes):
    rule = {"scope": {"kind": "station", "station_id": STATION["station_id"]},
            "timezone": "Asia/Bangkok", "weekdays": [0, 1, 2, 3, 4],
            "start": "09:00", "end": "18:00", "include_cached_interactive": False, **changes}
    return {"version": version, "policies": [rule]}


def native(logon_type="2", *, at="2026-10-19T12:30:00Z", event_id=4624, record=1):
    observation = normalizers.normalize(
        {"event_id": event_id, "channel": "Security", "provider_name": normalizers.SECURITY_PROVIDER},
        {"LogonType": logon_type, "TargetUserSid": "S-1-5-21-1-2-3-1001", "TargetUserName": "fixture-account",
         "TargetLogonId": "0x123"}, Workstation(STATION["agent_key"], 100))
    observation.update({"channel": "Security", "provider_name": normalizers.SECURITY_PROVIDER,
                        "source_sha256": "a" * 64})
    return {"id": digest([record, at]), "agent_key": STATION["agent_key"], "event_id": event_id,
            "family": "logons", "observed_at": at, "observation": observation}


def evaluate(row=None, policy=None, station=None):
    return c07.evaluate(row or native(), config=policy if policy is not None else config(), station=station or STATION)


def test_outside_window_keeps_local_offset_rule_version_and_explanation():
    result = evaluate()
    check = result["check"].to_dict()
    assert result["outside"] is True
    assert result["params"]["local_time"] == "2026-10-19T19:30:00+07:00"
    assert result["params"]["policy_version"] == 1
    assert result["params"]["policy_sha256"] == digest(config())
    assert result["params"]["scope_basis"] == "current_inventory"
    assert check["counts"]["stations"] == {"value": 1, "relation": "exact"}
    assert check["reasons"][0]["message_key"] == "workstations.reasons.logon_outside_policy"


@pytest.mark.parametrize("at,outside", [
    ("2026-10-19T01:59:59Z", True), ("2026-10-19T02:00:00Z", False),
    ("2026-10-19T10:59:59Z", False), ("2026-10-19T11:00:00Z", True),
    ("2026-10-18T03:00:00Z", True),
])
def test_local_days_and_start_inclusive_end_exclusive(at, outside):
    result = evaluate(native(at=at))
    assert result["outside"] is outside
    assert bool(result["check"].reasons) is outside


@pytest.mark.parametrize("kind", ["3", "4", "5", "7", "8", "9", "12", "13", "0", "1"])
def test_non_interactive_and_unlock_types_do_not_create_findings(kind):
    result = evaluate(native(kind))
    if kind in {"0", "1"}:
        assert result["outside"] is None  # Invalid/unavailable type cannot establish human activity.
    else:
        assert result is None


@pytest.mark.parametrize("kind", ["2", "10"])
def test_only_successful_interactive_signins_are_checked(kind):
    assert evaluate(native(kind))["outside"] is True
    for number in (4625, 4634, 4647):
        assert evaluate(native(kind, event_id=number)) is None


def test_cached_interactive_requires_explicit_opt_in():
    assert evaluate(native("11"))["outside"] is False
    assert evaluate(native("11"), config(include_cached_interactive=True))["outside"] is True
    assert c07.evaluate(native("11"), config=None, station=STATION)["outside"] is None


@pytest.mark.parametrize("policy", [None, {"version": 1, "policies": []},
                                        config(scope={"kind": "station", "station_id": "fixture-other"})])
def test_missing_norm_is_unknown_instead_of_zero_or_finding(policy):
    result = c07.evaluate(native(), config=policy, station=STATION)
    assert result["outside"] is None
    check = result["check"].to_dict()
    assert check["counts"]["stations"] == {"value": None, "relation": "unknown"}
    assert check["quality"]["reasons"][0]["code"] == "logon_policy_not_configured"
    assert check["reasons"] == []


@pytest.mark.parametrize("kind", [None, "", "unknown", "2.0", True])
def test_missing_or_malformed_type_cannot_become_interactive(kind):
    row = native()
    row["observation"]["facts"]["logon_type"] = kind
    result = evaluate(row)
    assert result["outside"] is None
    assert result["check"].quality.reasons[0].code == "logon_type_unknown"


@pytest.mark.parametrize("field,value", [("family", "processes"), ("channel", "System"),
                                         ("provider_name", "fixture-provider")])
def test_event_family_channel_and_provider_are_required(field, value):
    row = native()
    (row if field == "family" else row["observation"])[field] = value
    assert evaluate(row) is None


def test_station_precedence_and_exact_domain_ou_binding():
    ou = config(scope={"kind": "ou", "domain_id": 11, "ou_path": OU}, start="18:00", end="22:00")
    assert evaluate(policy=ou)["outside"] is False
    assert evaluate(policy=ou, station=STATION | {"domain_id": 99})["outside"] is None
    assert evaluate(policy=ou, station=STATION | {"metadata": {}})["outside"] is None
    ou["policies"].append(config()["policies"][0])
    assert evaluate(policy=ou)["outside"] is True
    # The event itself cannot override inventory's authorized OU.
    row = native()
    row["observation"]["facts"].update({"domain_id": 11, "ou_path": OU})
    ou["policies"].pop()
    assert evaluate(row, ou, STATION | {"metadata": {}})["outside"] is None
    assert evaluate(policy=ou, station=STATION | {"metadata": {"ou_path": OU.upper()}})["outside"] is False
    assert evaluate(policy=ou, station=STATION | {"metadata": {"ou_path": "ou=child," + OU}})["outside"] is None


@pytest.mark.parametrize("at,outside", [
    ("2026-10-19T23:00:00Z", False), ("2026-10-20T05:59:59Z", False),
    ("2026-10-20T06:00:00Z", True), ("2026-10-19T05:00:00Z", True),
])
def test_overnight_shift_uses_starting_weekday(at, outside):
    policy = config(timezone="UTC", weekdays=[0], start="22:00", end="06:00")
    assert evaluate(native(at=at), policy)["outside"] is outside


@pytest.mark.parametrize("at,local", [
    ("2026-10-25T00:30:00Z", "2026-10-25T02:30:00+02:00"),
    ("2026-10-25T01:30:00Z", "2026-10-25T02:30:00+01:00"),
    ("2026-03-29T01:30:00Z", "2026-03-29T03:30:00+02:00"),
])
def test_dst_conversion_uses_event_instant_and_keeps_fold_offset(at, local):
    result = evaluate(native(at=at), config(timezone="Europe/Berlin", weekdays=[6], start="01:00", end="04:00"))
    assert result["outside"] is False
    assert result["params"]["local_time"] == local


def test_timezone_conversion_can_change_the_weekday():
    result = evaluate(native(at="2026-10-19T00:00:00Z"),
                      config(timezone="America/New_York", weekdays=[6], start="19:00", end="21:00"))
    assert result["outside"] is False
    assert result["params"]["local_time"] == "2026-10-18T20:00:00-04:00"


@pytest.mark.parametrize("change", [
    {"timezone": "fixture-invalid-zone"}, {"timezone": None}, {"weekdays": []}, {"weekdays": [True]},
    {"weekdays": [7]}, {"weekdays": [0, 0]}, {"start": "9:00"}, {"end": "24:00"},
    {"end": "09:00"}, {"include_cached_interactive": 1}, {"unexpected": True},
    {"scope": {"kind": "all"}}, {"scope": {"kind": "station", "station_id": " "}},
    {"scope": {"kind": "ou", "domain_id": True, "ou_path": OU}},
    {"scope": {"kind": "ou", "domain_id": 11, "ou_path": "fixture-caption"}},
])
def test_config_rejects_ambiguous_or_invalid_calendar_and_scope(change):
    with pytest.raises(ValueError, match=c07.ERROR):
        c07.setting_value(json.dumps(config(**change)))


@pytest.mark.parametrize("raw", ["{}", "null", "[]", "not-json", " " * 1025,
                                 '{"version":true,"policies":[]}', '{"version":0,"policies":[]}',
                                 '{"version":2147483647,"policies":[]}'])
def test_config_contract_is_bounded_and_versioned(raw):
    with pytest.raises(ValueError, match=c07.ERROR):
        c07.setting_value(raw)


def test_duplicate_scopes_rejected_and_update_requires_a_new_version():
    value = config()
    value["policies"].append(deepcopy(value["policies"][0]))
    with pytest.raises(ValueError, match=c07.ERROR):
        c07.setting_value(json.dumps(value))
    previous = c07.setting_value(json.dumps(config()))
    c07.validate_update(previous, previous)
    c07.validate_update(previous, json.dumps(config(), indent=2))
    with pytest.raises(ValueError, match=c07.ERROR):
        c07.validate_update(c07.setting_value(json.dumps(config(start="10:00"))), previous)
    c07.validate_update(c07.setting_value(json.dumps(config(version=2, start="10:00"))), previous)


def test_ou_contract_canonicalizes_case_and_rejects_duplicate_paths():
    rule = config(scope={"kind": "ou", "domain_id": 11, "ou_path": OU.upper()})
    value = json.loads(c07.setting_value(json.dumps(rule)))
    assert value["policies"][0]["scope"]["ou_path"] == OU
    value["policies"].append(rule["policies"][0])
    with pytest.raises(ValueError, match=c07.ERROR):
        c07.setting_value(json.dumps(value))


def test_ou_policy_uses_existing_inventory_directory_path_without_an_ou_entity_id():
    from tests.unit.test_workstation_inventory import agent, association, computer, device
    from server.sli.plugins.workstations.inventory import build_inventory

    station = build_inventory([computer(1, organizational_unit=OU)], [agent(1)], [device(1)], [association(1001, 1)])[0]
    assert station["ou_entity_id"] is None
    policy = config(scope={"kind": "ou", "domain_id": 11, "ou_path": OU})
    result = c07.evaluate(native(), station=station, config=policy)
    assert result["outside"] is True and result["params"]["scope_id"] == OU


class PG(QueuePG):
    """Execute the C07 SQL protocol and existing WR05 queue with synthetic rows."""
    def __init__(self, policy=None):
        super().__init__()
        self.policy = policy
        self.station = dict(STATION)
        self.findings = {}
        self.summary = {"C01": {"fixture": True}}
        self.summary_revision = 1

    @contextmanager
    def transaction(self):
        summary, revision = deepcopy(self.summary), self.summary_revision
        try:
            with super().transaction():
                yield
        except Exception:
            self.summary, self.summary_revision = summary, revision
            raise

    def execute(self, sql, params=()):
        sql = " ".join(sql.split())
        assert sql.count("%s") == len(params)
        self.one, self.rows = None, []
        if sql.startswith("select value from public.platform_settings"):
            self.one = {"value": json.dumps(self.policy)} if self.policy else None
        elif sql.startswith("select station_id,agent_key,domain_id,metadata"):
            self.one = dict(self.station)
        elif sql.startswith("set local statement_timeout"):
            pass
        elif sql.startswith("insert into sli_plugin_workstations.station_summary"):
            state = json.loads(params[1])
            if self.summary.get("C07") != state:
                self.summary_revision += 1
            self.summary["C07"] = state
        elif sql.startswith("insert into sli_plugin_workstations.check_findings"):
            identifier, station, rule, episode, condition, at, latest, reason, quality, refs = params
            old = self.findings.get(identifier)
            if old is None or old["condition_sha256"] != condition:
                self.findings[identifier] = {"id": identifier, "station_id": station, "rule_version": rule,
                    "episode_id": episode, "condition_sha256": condition, "fact_at": at, "last_observed_at": latest,
                    "status": "active", "reason_params": json.loads(reason), "quality": json.loads(quality),
                    "evidence_refs": json.loads(refs), "revision": old["revision"] + 1 if old else 1}
        elif sql.startswith("update sli_plugin_workstations.check_findings"):
            resolved, _, quality, condition, replace_params, reason, identifier, _ = params
            old = self.findings.get(identifier)
            if old and old["condition_sha256"] != condition:
                old.update({"status": "resolved" if resolved else old["status"], "quality": json.loads(quality),
                            "condition_sha256": condition, "revision": old["revision"] + 1})
                if replace_params:
                    old["reason_params"] = json.loads(reason)
        else:
            return super().execute(sql, params)
        self.calls.append((sql, params))


def apply(pg, row):
    c07.apply(pg, STATION["station_id"], {"kind": "observations", "payload": row})


def test_persisted_finding_is_exact_idempotent_and_keeps_native_date():
    pg, row = PG(config()), native(at="2026-08-03T12:30:00Z")
    apply(pg, row)
    assert len(pg.findings) == 1
    finding = next(iter(pg.findings.values()))
    assert finding["fact_at"].isoformat() == "2026-08-03T12:30:00+00:00"
    assert finding["reason_params"]["local_time"] == "2026-08-03T19:30:00+07:00"
    assert finding["evidence_refs"] == [{"kind": "workstation_observation", "observation_id": row["id"],
        "agent_key": STATION["agent_key"], "source_sha256": "a" * 64}]
    saved = deepcopy((pg.findings, pg.summary, pg.summary_revision))
    apply(pg, row)
    assert (pg.findings, pg.summary, pg.summary_revision) == saved
    assert pg.summary["C01"] == {"fixture": True}
    assert pg.summary["C07"]["stations"] == {"value": None, "relation": "unknown"}
    assert all("source_xml" not in sql for sql, _ in pg.calls)


def test_no_policy_and_service_types_cannot_create_a_finding():
    pg = PG()
    apply(pg, native())
    assert pg.findings == {}
    assert pg.summary["C07"]["quality"]["reasons"][0]["code"] == "logon_policy_not_configured"
    pg.policy = config()
    for kind in ("3", "5"):
        apply(pg, native(kind))
    assert pg.findings == {}


def test_policy_reevaluation_resolves_only_when_known_and_updates_same_finding():
    pg, row = PG(config()), native()
    apply(pg, row)
    original = next(iter(pg.findings.values()))["reason_params"]
    pg.policy = None
    apply(pg, row)
    finding = next(iter(pg.findings.values()))
    assert finding["status"] == "active" and finding["quality"]["status"] == "not_collected"
    assert finding["reason_params"] == original
    pg.policy = config(version=2, start="18:00", end="22:00")
    apply(pg, row)
    assert finding["status"] == "resolved" and finding["revision"] == 3
    assert finding["reason_params"]["policy_version"] == 2
    pg.policy = config(version=3)
    apply(pg, row)
    assert len(pg.findings) == 1
    assert next(iter(pg.findings.values()))["status"] == "active"


def test_cached_opt_out_resolves_previously_included_logon():
    pg, row = PG(config(include_cached_interactive=True)), native("11")
    apply(pg, row)
    pg.policy = config(version=2)
    apply(pg, row)
    assert next(iter(pg.findings.values()))["status"] == "resolved"


def test_agent_mismatch_rolls_back_instead_of_using_another_station_policy():
    pg = PG(config())
    before = deepcopy(pg.summary)
    row = native()
    row["agent_key"] = "fixture-other-agent"
    with pytest.raises(ValueError, match="input_conflict"):
        with pg.transaction():
            apply(pg, row)
    assert pg.findings == {}
    assert pg.summary == before


def test_versioned_consumer_backfills_old_inputs_and_pins_configuration():
    pg, row = PG(), native()
    pg.add_fact(row["id"], payload=row)
    rules = c07.configured(pg, (projection.Projector(c07.PROJECTOR, 1, c07.apply),))
    prepare(pg, rules)
    projection.run_batch(pg, evaluators=rules)
    assert pg.findings == {} and pg.receipts[1, c07.PROJECTOR, 1]["applied"]
    pg.policy = config()
    rules = c07.configured(pg, (projection.Projector(c07.PROJECTOR, 1, c07.apply),))
    assert rules[0].version == 2
    prepare(pg, rules)
    # Mutating storage after pinning cannot change the policy acknowledged by this receipt.
    pg.policy = config(version=2, start="18:00", end="22:00")
    projection.run_batch(pg, evaluators=rules)
    assert len(pg.findings) == 1 and pg.receipts[1, c07.PROJECTOR, 2]["applied"]
    rules = c07.configured(pg, (projection.Projector(c07.PROJECTOR, 1, c07.apply),))
    prepare(pg, rules)
    projection.run_batch(pg, evaluators=rules)
    assert next(iter(pg.findings.values()))["status"] == "resolved"
    assert pg.receipts[1, c07.PROJECTOR, 3]["applied"]


def test_registered_setting_has_no_default_or_environment_and_validates_json():
    spec = platform_settings.SETTINGS[c07.SETTING_KEY]
    assert spec.default is None and spec.environment == ""
    assert json.loads(spec.validate(json.dumps(config()))) == config()
    assert any(item.key == c07.PROJECTOR for item in projection.projectors())


class LoginPG(QueuePG):
    """Actual WR05 queue with only the existing summary SQL boundary replaced."""
    def __init__(self):
        super().__init__()
        self.summary = {}
        self.station_agent = STATION["agent_key"]

    @contextmanager
    def transaction(self):
        saved = deepcopy(self.summary)
        try:
            with super().transaction():
                yield
        except Exception:
            self.summary = saved
            raise

    def execute(self, sql, params=()):
        compact = " ".join(sql.split())
        if compact.startswith("set local statement_timeout"):
            return
        if compact.startswith("select agent_key from sli_plugin_workstations.station_inventory"):
            self.one = {"agent_key": self.station_agent}
        elif compact.startswith("select last_interactive_login from sli_plugin_workstations.station_summary"):
            self.one = {"last_interactive_login": self.summary[params[0]]} if params[0] in self.summary else None
        elif compact.startswith("insert into sli_plugin_workstations.station_summary(station_id,last_interactive_login"):
            self.summary[params[0]] = json.loads(params[1])
        else:
            return super().execute(sql, params)
        self.calls.append((compact, params))


def login_rules():
    rules = tuple(item for item in projection.projectors() if item.key == "workstations.last-interactive-login")
    assert len(rules) == 1, "The last login must be connected to the registered WR05 path"
    return rules


def login_native(kind="2", *, at="2026-10-19T12:30:00Z", record=1, event_id=4624):
    row = native(kind, at=at, record=record, event_id=event_id)
    observation = normalizers.normalize(
        {"event_id": event_id, "channel": "Security", "provider_name": normalizers.SECURITY_PROVIDER},
        {"LogonType": kind, "TargetUserSid": "S-1-5-21-1-2-3-1001", "TargetUserName": "fixture-target",
         "TargetDomainName": "EXAMPLE", "SubjectUserName": "fixture-actor", "TargetLogonId": "0x123"},
        Workstation(STATION["agent_key"], 100))
    observation.update({"channel": "Security", "provider_name": normalizers.SECURITY_PROVIDER, "source_sha256": "a" * 64})
    row["observation"] = observation
    return row


@pytest.mark.parametrize("kind", ["2", "10", "11"])
def test_registered_last_login_projects_target_not_actor_and_never_active(kind):
    pg, rules, row = LoginPG(), login_rules(), login_native(kind)
    prepare(pg, rules)
    pg.add_fact(row["id"], payload=row)
    with pg.transaction():
        projection.run_batch(pg, evaluators=rules)
    summary = pg.summary[STATION["station_id"]]
    assert summary["account"] == {"name": "fixture-target", "domain": "EXAMPLE", "sid": "S-1-5-21-1-2-3-1001"}
    assert summary["logon_type"] == int(kind)
    assert summary["observed_at"] == "2026-10-19T12:30:00+00:00"
    assert summary["current_state"] == "unknown"
    assert summary["evidence_ref"]["observation_id"] == row["id"]
    assert "fixture-actor" not in repr(summary)
    assert pg.receipts[1, rules[0].key, 1]["applied"]
    with pg.transaction():
        assert projection.run_batch(pg, evaluators=rules)["processed"] == 0


@pytest.mark.parametrize("kind,event_id", [("3",4624),("4",4624),("5",4624),("7",4624),("unknown",4624),
                                           (None,4624),("2",4625),("2",4634),("2",4647)])
def test_last_login_ignores_network_service_unlock_unknown_failure_and_end(kind, event_id):
    pg, rules = LoginPG(), login_rules()
    prepare(pg, rules)
    row = login_native(kind, event_id=event_id)
    pg.add_fact(row["id"], payload=row)
    with pg.transaction():
        projection.run_batch(pg, evaluators=rules)
    assert pg.summary == {}


def test_last_login_late_replay_and_equal_timestamps_are_delivery_order_independent():
    recent = login_native("10", at="2026-10-19T13:00:00Z", record=10)
    older = login_native("2", record=11)
    tied = login_native("11", at="2026-10-19T13:00:00Z", record=12)
    outcomes = []
    for order in ([recent, older, tied], [tied, recent, older]):
        pg, rules = LoginPG(), login_rules()
        prepare(pg, rules)
        for row in order:
            pg.add_fact(row["id"], payload=row)
            with pg.transaction():
                projection.run_batch(pg, evaluators=rules)
        outcomes.append(pg.summary)
    assert outcomes[0] == outcomes[1]
    assert outcomes[0][STATION["station_id"]]["observation_id"] == max(recent["id"], tied["id"])


def test_last_login_identity_mismatch_rolls_back_queue_receipt_and_summary():
    pg, rules, row = LoginPG(), login_rules(), login_native()
    prepare(pg, rules)
    pg.add_fact(row["id"], payload=row)
    pg.station_agent = "fixture-other-agent"
    with pytest.raises(ValueError, match="input_conflict"), pg.transaction():
        projection.run_batch(pg, evaluators=rules)
    assert pg.summary == {} and not pg.receipts[1, rules[0].key, 1]["applied"]


def test_last_login_old_observation_without_target_labels_stays_unknown_and_backfills():
    pg, row = LoginPG(), login_native()
    row["observation"]["facts"] = {"logon_type": "2"}
    pg.add_fact(row["id"], payload=row)  # Arrived before this consumer was registered.
    rules = login_rules()
    prepare(pg, rules)
    with pg.transaction():
        projection.run_batch(pg, evaluators=rules)
    assert pg.summary[STATION["station_id"]]["account"] == dict.fromkeys(("name", "domain", "sid"))
    assert pg.receipts[1, rules[0].key, 1]["applied"]


def test_last_login_unknown_type_is_preserved_in_canonical_observation():
    row = login_native("15")
    assert row["observation"]["facts"]["logon_type"] == "15"
    pg, rules = LoginPG(), login_rules()
    prepare(pg, rules)
    pg.add_fact(row["id"], payload=row)
    with pg.transaction():
        projection.run_batch(pg, evaluators=rules)
    assert pg.summary == {}


@pytest.mark.parametrize("mutate", [
    lambda row: row["observation"].update(agent_key="other-agent"),
    lambda row: row["observation"].update(source_sha256="invalid"),
])
def test_last_login_rejects_mismatched_native_identity_or_source(mutate):
    pg, rules, row = LoginPG(), login_rules(), login_native()
    mutate(row)
    prepare(pg, rules)
    pg.add_fact(row["id"], payload=row)
    with pytest.raises(ValueError, match="input_conflict"), pg.transaction():
        projection.run_batch(pg, evaluators=rules)
    assert pg.summary == {} and not pg.receipts[1, rules[0].key, 1]["applied"]
