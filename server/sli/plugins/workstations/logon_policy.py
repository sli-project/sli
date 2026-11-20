"""C07 explicit station/OU working hours; no learned or implicit calendar.

Policies use current inventory scope, never an OU/name claimed by an event.
Version changes get independent WR05 receipts and bounded history backfill.
The caller owns the transaction and publication fence.
"""
from __future__ import annotations

import json
import re
from functools import partial
from zoneinfo import ZoneInfoNotFoundError

from server.sli.core import working_time

from .check_catalog import BY_ID
from .importer import digest
from .inventory import _split_dn
from .normalizers import SECURITY_PROVIDER
from .overview_contracts import CheckCounts, CheckResult, Count, Quality, Reason
from .protection import timestamp

SETTING_KEY = "workstations.logon_policy"
PROJECTOR = "workstations.C07"
RULE_VERSION = BY_ID["C07"].rule_version
ERROR = "workstation_logon_policy_invalid"
MAX_VALUE = 1024  # Existing platform_settings storage contract.
_UNSET = object()


def _ou_path(value):
    # Exact OU DN from current directory metadata; no caption, event-provided
    # OU, suffix/substring inheritance or cross-domain name matching.
    if not isinstance(value, str) or not 1 <= len(value) <= 512 or value.endswith("\\"):
        return None
    parts = _split_dn(value)
    if (not parts or not parts[0].casefold().startswith("ou=") or not parts[-1].casefold().startswith("dc=")
            or any("=" not in part or not part.split("=", 1)[1] for part in parts)):
        return None
    return ",".join(part.casefold() for part in parts)


def setting_value(raw):
    """Versioned JSON: exact station scope overrides exact domain/OU scope.

    Weekdays use Monday=0; start is inclusive and end exclusive. For an
    overnight shift weekdays refer to the date on which the shift starts.
    Empty policies explicitly leave the norm unknown. Cached interactive (11)
    is evaluated only when include_cached_interactive is explicitly true.
    """
    try:
        if not isinstance(raw, str) or len(raw) > MAX_VALUE:
            raise ValueError
        value = json.loads(raw)
        if (not isinstance(value, dict) or set(value) != {"version", "policies"}
                or type(value["version"]) is not int or not 1 <= value["version"] < 2147483647
                or not isinstance(value["policies"], list)):
            raise ValueError
        scopes = set()
        for rule in value["policies"]:
            if not isinstance(rule, dict) or set(rule) != {
                    "scope", "timezone", "weekdays", "start", "end", "include_cached_interactive"}:
                raise ValueError
            scope = rule["scope"]
            if not isinstance(scope, dict):
                raise ValueError
            if scope.get("kind") == "station":
                if (set(scope) != {"kind", "station_id"} or not isinstance(scope["station_id"], str)
                        or not 1 <= len(scope["station_id"]) <= 256 or scope["station_id"].strip() != scope["station_id"]):
                    raise ValueError
            elif scope.get("kind") == "ou":
                if (set(scope) != {"kind", "domain_id", "ou_path"}
                        or type(scope["domain_id"]) is not int or scope["domain_id"] < 1
                        or _ou_path(scope["ou_path"]) is None):
                    raise ValueError
                scope["ou_path"] = _ou_path(scope["ou_path"])
            else:
                raise ValueError
            identity = json.dumps(scope, sort_keys=True)
            if identity in scopes or type(rule["include_cached_interactive"]) is not bool:
                raise ValueError
            scopes.add(identity)
            working_time.validate({key: rule[key] for key in ("timezone", "weekdays", "start", "end")}
                                  | {"excluded_dates": [], "exceptions": []})
        normalized = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if len(normalized) > MAX_VALUE:
            raise ValueError
        return normalized
    except (ValueError, TypeError, KeyError, ZoneInfoNotFoundError):
        raise ValueError(ERROR) from None


def validate_update(normalized, previous):
    """Never reuse a receipt version for different policy content."""
    if previous is not None and normalized != setting_value(previous):
        old = json.loads(setting_value(previous))
        if json.loads(normalized)["version"] <= old["version"]:
            raise ValueError(ERROR)


def load(conn):
    # Read through the caller's connection: no cached setting or extra DB I/O
    # can escape the core job transaction. Invalid stored data fails closed.
    with conn.cursor() as cur:
        cur.execute("select value from public.platform_settings where key=%s", (SETTING_KEY,))
        row = cur.fetchone()
    return json.loads(setting_value(row["value"])) if row else None


def configured(conn, evaluators):
    """Pin policy content to one versioned evaluator for this invocation."""
    if not any(item.key == PROJECTOR for item in evaluators):
        return evaluators
    from .projection import Projector

    config = load(conn)
    # Version 1 is the unconfigured consumer; configured versions start at 2.
    version = config["version"] + 1 if config else 1
    return tuple(Projector(item.key, version, partial(apply, config=config)) if item.key == PROJECTOR else item
                 for item in evaluators)


def select_policy(config, station):
    if config is None:
        return None
    for rule in config["policies"]:
        scope = rule["scope"]
        if scope["kind"] == "station" and scope["station_id"] == station["station_id"]:
            return rule
    return next((rule for rule in config["policies"] if rule["scope"]["kind"] == "ou"
                 and rule["scope"]["domain_id"] == station.get("domain_id")
                 and _ou_path(rule["scope"]["ou_path"]) == _ou_path(station.get("metadata", {}).get("ou_path"))), None)


def evaluate(row, *, station, config):
    """Evaluate one native sign-in, not collection coverage for a station.

    None means an irrelevant event/type. Missing policy/type is an explicit
    unknown result, never a clean result or an outside-hours finding.
    """
    observation = row.get("observation", {})
    if (row.get("family") != "logons" or row.get("event_id") != 4624
            or observation.get("channel", "").casefold() != "security"
            or observation.get("provider_name", "").casefold() != SECURITY_PROVIDER.casefold()):
        return None
    logon_type = observation.get("facts", {}).get("logon_type")
    known_type = type(logon_type) in (str, int) and str(logon_type) in {str(number) for number in range(2, 14)}
    if known_type and str(logon_type) not in {"2", "10", "11"}:
        return None
    policy = select_policy(config, station)
    reason = "logon_type_unknown" if not known_type else "logon_policy_not_configured" if policy is None else None
    params = {}
    if reason:
        check = CheckResult("C07", Quality("not_collected", (Reason(reason),)),
                            CheckCounts(Count(None, "unknown"), Count(None, "unknown")))
        return {"check": check, "outside": None, "params": params}
    instant = timestamp(row["observed_at"])
    calendar = {key: policy[key] for key in ("timezone", "weekdays", "start", "end")}
    outside, local = working_time.outside(instant.isoformat(), None, calendar | {"exceptions": [], "excluded_dates": []})
    if str(logon_type) == "11" and not policy["include_cached_interactive"]:
        outside = False
    scope = policy["scope"]
    params = {"local_time": local, "timezone": policy["timezone"], "logon_type": int(logon_type),
              "policy_version": config["version"], "policy_sha256": digest(config),
              "window_start": policy["start"], "window_end": policy["end"],
              "weekdays": ",".join(str(day) for day in policy["weekdays"]),
              "include_cached_interactive": policy["include_cached_interactive"],
              "scope_kind": scope["kind"], "scope_id": scope.get("station_id", scope.get("ou_path")),
              "domain_id": scope.get("domain_id"), "scope_basis": "current_inventory"}
    check = CheckResult("C07", Quality("complete"), CheckCounts(Count(int(outside), "exact"), Count(None, "unknown")),
                        (Reason("logon_outside_policy", params),) if outside else ())
    return {"check": check, "outside": outside, "params": params}


def _save(cur, station_id, row, result):
    """One stable finding per native observation; config replay updates it."""
    identifier = row["id"]
    if not isinstance(identifier, str) or not re.fullmatch(r"[a-f0-9]{64}", identifier):
        raise ValueError("workstation_c07_observation_id_invalid")
    finding_id = digest([PROJECTOR, RULE_VERSION, station_id, identifier])
    quality = result["check"].quality.to_dict()
    params = result["params"]
    condition = digest([result["outside"], quality, params])
    if result["outside"] is not True:
        # Unknown invalidates certainty of an old finding without inventing a
        # resolution. Only an observed sign-in inside a configured window does.
        cur.execute("""update sli_plugin_workstations.check_findings set
            status=case when %s then 'resolved' else status end,
            resolved_at=case when %s then coalesce(resolved_at,transaction_timestamp()) else resolved_at end,
            quality=%s::jsonb,condition_sha256=%s,
            reason_params=case when %s then %s::jsonb else reason_params end,
            revision=revision+1,materially_changed_at=transaction_timestamp()
            where id=%s and condition_sha256<>%s""",
            (result["outside"] is False, result["outside"] is False, json.dumps(quality), condition,
             result["outside"] is False, json.dumps(params), finding_id, condition))
        return
    ref = {"kind": "workstation_observation", "observation_id": identifier,
           "agent_key": row["agent_key"], "source_sha256": row["observation"].get("source_sha256")}
    cur.execute("""insert into sli_plugin_workstations.check_findings
        (id,station_id,check_id,rule_version,episode_id,condition_sha256,status,severity,
         fact_at,first_detected_at,last_observed_at,materially_changed_at,reason_code,reason_params,quality,evidence_refs)
        values(%s,%s,'C07',%s,%s,%s,'active','medium',%s,transaction_timestamp(),%s,transaction_timestamp(),
               'logon_outside_policy',%s::jsonb,%s::jsonb,%s::jsonb)
        on conflict(id) do update set condition_sha256=excluded.condition_sha256,status='active',resolved_at=null,
            reason_params=excluded.reason_params,quality=excluded.quality,evidence_refs=excluded.evidence_refs,
            materially_changed_at=excluded.materially_changed_at,revision=check_findings.revision+1
        where check_findings.condition_sha256<>excluded.condition_sha256""",
        (finding_id, station_id, RULE_VERSION, finding_id, condition, timestamp(row["observed_at"]),
         timestamp(row["observed_at"]), json.dumps(params), json.dumps(quality), json.dumps([ref])))


def apply(conn, station_id, fact, *, config=_UNSET):
    if fact["kind"] not in {"observations", "station_inventory"}:
        return
    if config is _UNSET:
        config = load(conn)
    with conn.cursor() as cur:
        cur.execute("set local statement_timeout='5000ms'")
        cur.execute("""select station_id,agent_key,domain_id,metadata
            from sli_plugin_workstations.station_inventory where station_id=%s""", (station_id,))
        station = cur.fetchone()
        if station is None:
            raise ValueError("workstation_projection_station_missing")
        policy = select_policy(config, station)
        quality = Quality("partial", (Reason("coverage_incomplete"),)) if policy else Quality(
            "not_collected", (Reason("logon_policy_not_configured"),))
        # No single event establishes station-wide coverage or a zero count.
        state = {"policy_version": config["version"] if config else None,
                 "policy_sha256": digest(config) if config else None,
                 "quality": quality.to_dict(), "stations": Count(None, "unknown").to_dict()}
        cur.execute("""insert into sli_plugin_workstations.station_summary(station_id,counters,as_of_utc)
            values(%s,jsonb_build_object('C07',%s::jsonb),transaction_timestamp())
            on conflict(station_id) do update set counters=station_summary.counters||excluded.counters,
                as_of_utc=excluded.as_of_utc,revision=station_summary.revision+1,updated_at=now()
            where station_summary.counters->'C07' is distinct from excluded.counters->'C07'""",
            (station_id, json.dumps(state)))
        if fact["kind"] == "observations":
            row = fact["payload"]
            if row.get("agent_key") != station["agent_key"]:
                raise ValueError("workstation_projection_input_conflict")
            result = evaluate(row, station=station, config=config)
            if result is not None:
                _save(cur, station_id, row, result)


def apply_last_login(conn, station_id, fact):
    """Latest observed native interactive sign-in, never a current session claim.

    WR05 serializes this write and owns its transaction/receipt. Timestamp plus
    immutable observation ID makes delayed delivery and ties deterministic.
    Existing observations without native target labels remain unidentified.
    """
    if fact["kind"] != "observations":
        return
    row = fact["payload"]
    observation = row.get("observation", {})
    facts = observation.get("facts", {})
    kind = facts.get("logon_type")
    if (row.get("family") != "logons" or row.get("event_id") != 4624
            or observation.get("channel", "").casefold() != "security"
            or observation.get("provider_name", "").casefold() != SECURITY_PROVIDER.casefold()
            or type(kind) not in (str, int) or str(kind) not in {"2", "10", "11"}):
        return
    identifier, source = row.get("id"), observation.get("source_sha256")
    if (not isinstance(identifier, str) or not re.fullmatch(r"[a-f0-9]{64}", identifier)
            or not isinstance(source, str) or not re.fullmatch(r"[a-f0-9]{64}", source)
            or observation.get("agent_key") != row.get("agent_key")):
        raise ValueError("workstation_projection_input_conflict")
    instant = timestamp(row["observed_at"])
    account = {}
    for key in ("name", "domain", "sid"):
        value = facts.get("logon_user_" + key)
        account[key] = value if isinstance(value, str) and 0 < len(value) <= 256 else None
    state = {"observation_id": identifier, "observed_at": instant.isoformat(),
             "logon_type": int(kind), "account": account, "current_state": "unknown",
             "evidence_ref": {"kind": "workstation_observation", "observation_id": identifier,
                              "agent_key": row["agent_key"], "source_sha256": source}}
    with conn.cursor() as cur:
        cur.execute("set local statement_timeout='5000ms'")
        cur.execute("select agent_key from sli_plugin_workstations.station_inventory where station_id=%s", (station_id,))
        station = cur.fetchone()
        if station is None or station["agent_key"] != row["agent_key"]:
            raise ValueError("workstation_projection_input_conflict")
        cur.execute("""select last_interactive_login from sli_plugin_workstations.station_summary
            where station_id=%s for update""", (station_id,))
        previous = cur.fetchone()
        previous = previous["last_interactive_login"] if previous else {}
        if previous and (timestamp(previous["observed_at"]), previous["observation_id"]) >= (instant, identifier):
            return
        cur.execute("""insert into sli_plugin_workstations.station_summary(station_id,last_interactive_login,as_of_utc)
            values(%s,%s::jsonb,transaction_timestamp())
            on conflict(station_id) do update set last_interactive_login=excluded.last_interactive_login,
                as_of_utc=greatest(station_summary.as_of_utc,excluded.as_of_utc),
                revision=station_summary.revision+1,updated_at=now()""", (station_id, json.dumps(state)))
