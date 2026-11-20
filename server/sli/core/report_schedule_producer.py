"""Separate bounded report producer; fixed RPCs, no API/delivery credentials."""

from datetime import datetime
import json
import os
from pathlib import Path
import signal
import threading
import time
from uuid import UUID

from server.sli.access.access_composition import compose_schedule_access
from server.sli.core import report_schedule_calendar as calendar
from server.sli.core.report_schedule_candidates import validate
from server.sli.core.report_schedule_projection import project
from server.sli.semantic.runtime_state import scheduled_quality

PRODUCER_ROLE = "adlog_report_producer"
PRODUCER_SECRET_REF = "postgres/report-producer"
MAX_READ_MS = 2000
MAX_LOCK_MS = 500
MAX_CYCLE_SECONDS = 20
MAX_BATCH = 2
STATUS = Path("/tmp/report-producer.json")


class RpcReadDeadline(RuntimeError):
    pass


class RpcCapacity(RuntimeError):
    pass


def _instant(value):
    value = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("invalid_report_claim")
    return value


def run_cycle(backend, stop, *, leader_token=None, clock=time.monotonic,
              definition_loader=None, authority_factory=None):
    """One bounded producer cycle. This never invokes a delivery transport."""
    deadline = clock() + MAX_CYCLE_SECONDS
    result = {"status": "ok", "leader": leader_token, "published": 0}
    def check():
        if stop.is_set():
            raise InterruptedError("report_producer_stopped")
        if clock() >= deadline:
            raise TimeoutError("report_producer_deadline")
    try:
        check()
        result["leader"] = backend.lead(leader_token, deadline)
        if result["leader"] is None:
            return {**result, "status": "standby"}
        check()
        claims = backend.claim(result["leader"], MAX_BATCH, deadline)
        if len(claims) > MAX_BATCH:
            raise ValueError("invalid_report_claim")
        for claim in claims:
            check()
            try:
                schedule = dict(claim["schedule"])
                schedule["created_at"] = _instant(schedule["created_at"])
                slot, start, evaluated = (_instant(claim[key]) for key in ("slot", "period_from", "evaluated_at"))
                # The DB's independently derived slot must match the original
                # Python oracle. A TZ-data mismatch cannot produce a release.
                if calendar.latest_slot(schedule, evaluated) != slot or calendar.period_start(schedule, slot) != start:
                    raise ValueError("report_calendar_mismatch")
                if definition_loader is None:
                    from server.sli.reporting.v2.registry import get_report
                    definition = get_report(schedule["report_key"])
                else:
                    definition = definition_loader(schedule["report_key"])
                check()
                snapshot = backend.facts(claim, deadline)
                check()
                try:
                    candidate = backend.candidates(claim, deadline)
                except RuntimeError:
                    check()
                    backend.failure(claim, "error", deadline)
                    candidate = backend.candidates(claim, deadline)
                projected = project(definition, snapshot, candidate, authority_factory=authority_factory, check=check)
                check()
                try:
                    outcome = backend.publish(claim, projected["selection"], deadline)
                except RpcReadDeadline:
                    # A conditional quality read timed out. Publish only a
                    # fresh-fenced, countless error run, never the staged count.
                    check()
                    backend.failure(claim, "error", deadline)
                    candidate = backend.candidates(claim, deadline)
                    projected = project(definition, snapshot, candidate, authority_factory=authority_factory, check=check)
                    check()
                    outcome = backend.publish(claim, projected["selection"], deadline)
                result["published"] += int(bool(outcome["published"]))
            except RpcCapacity:
                return {**result, "status": "backpressure"}
            except (InterruptedError, TimeoutError):
                raise
            except Exception:
                # No raw exception, actor, filters or source value in health.
                result["status"] = "failed"
        return result
    except InterruptedError:
        return {**result, "status": "stopped"}
    except Exception:
        return {**result, "status": "failed"}


def normalize_candidate(raw, report_key):
    """Project fixed DB quality facts without returning them to a recipient."""
    if not isinstance(raw, dict) or raw.get("report_key") != report_key:
        raise ValueError("invalid_report_candidate")
    if report_key == "security.problems" and "quality_inputs" in raw:
        if set(raw) != {"report_key", "counts", "quality_inputs", "generated_at"}:
            raise ValueError("invalid_report_candidate")
        inputs = raw["quality_inputs"]
        if (not isinstance(inputs, dict) or set(inputs) != {"heartbeat", "refresh_limited", "coverage_incomplete"}
                or type(inputs["refresh_limited"]) is not bool or type(inputs["coverage_incomplete"]) is not bool
                or not isinstance(inputs["heartbeat"], dict)):
            raise ValueError("invalid_report_candidate")
        heartbeat = inputs["heartbeat"]
        if heartbeat:
            if (set(heartbeat) != {"status", "heartbeat_at", "expected_interval_seconds", "details_json"}
                    or heartbeat["status"] not in {"running", "idle", "other"}
                    or not isinstance(heartbeat["details_json"], dict)
                    or set(heartbeat["details_json"]) != {"runtime_mode", "manual_runtime"}
                    or heartbeat["details_json"]["runtime_mode"] not in {"facts-v1", "investigation-v1", "findings-v1", None}
                    or type(heartbeat["details_json"]["manual_runtime"]) is not bool):
                raise ValueError("invalid_report_candidate")
        candidate = validate({"report_key": report_key, "counts": raw["counts"], "roots": [], "quality": "partial"})
        candidate["quality"] = scheduled_quality(inputs["heartbeat"], generated=_instant(raw["generated_at"]),
            total=candidate["counts"]["individual"]["total"], refresh_limited=inputs["refresh_limited"],
            coverage_incomplete=inputs["coverage_incomplete"])
        return candidate
    expected = {"report_key", "quality", "counts", "roots"}
    if report_key == "file-audit.mass-operations":
        expected.add("root_limit")
    if set(raw) != expected:
        raise ValueError("invalid_report_candidate")
    return validate(raw)


class SqlBackend:
    """Fixed RPC adapter using only the distinct producer connection."""
    QUERIES = {
        "lead": "select public.report_producer_lead(%s::uuid) as value",
        "claim": "select * from public.report_schedule_claim(%s::uuid,%s)",
        "candidates": "select public.report_schedule_candidates(%s::uuid,%s::uuid) as value",
        "failure": "select public.report_schedule_failure(%s::uuid,%s::uuid,%s) as value",
        "publish": "select public.report_schedule_publish(%s::uuid,%s::uuid,%s::jsonb) as value",
    }
    def __init__(self, conn, *, clock=time.monotonic):
        self.conn, self.clock = conn, clock
    def _rpc(self, operation, params, deadline):
        remaining = int((deadline-self.clock())*1000)
        if remaining <= 0:
            raise TimeoutError("report_producer_deadline")
        budget = min(remaining, 10000 if operation == "claim" else MAX_READ_MS)
        try:
            with self.conn.transaction(), self.conn.cursor() as cur:
                cur.execute("select pg_catalog.set_config('statement_timeout',%s,true), "
                    "pg_catalog.set_config('lock_timeout',%s,true)", (f"{budget}ms", f"{min(budget, MAX_LOCK_MS)}ms"))
                cur.execute(self.QUERIES[operation], params)
                value = cur.fetchall() if operation == "claim" else cur.fetchone()["value"]
        except Exception as exc:
            if getattr(exc, "sqlstate", None) == "57014":
                raise RpcReadDeadline("report_producer_read_deadline") from None
            if getattr(exc, "sqlstate", None) == "P7001":
                raise RpcCapacity("report_producer_capacity") from None
            raise RuntimeError("report_producer_read_failed") from None
        if self.clock() >= deadline:
            raise TimeoutError("report_producer_deadline")
        return value
    def lead(self, token, deadline):
        return self._rpc("lead", (token,), deadline)
    def claim(self, token, limit, deadline):
        return self._rpc("claim", (token, limit), deadline)
    def facts(self, claim, deadline):
        return read_claimed_access(self.conn, claim["job_id"], claim["lease"], deadline=deadline, clock=self.clock)
    def candidates(self, claim, deadline):
        raw = self._rpc("candidates", (claim["job_id"], claim["lease"]), deadline)
        return normalize_candidate(raw, claim["schedule"]["report_key"])
    def failure(self, claim, quality, deadline):
        return self._rpc("failure", (claim["job_id"], claim["lease"], quality), deadline)
    def publish(self, claim, selection, deadline):
        return self._rpc("publish", (claim["job_id"], claim["lease"], json.dumps(selection, allow_nan=False)), deadline)


def healthy():
    try:
        row = json.loads(STATUS.read_text())
        return (set(row) == {"pid", "at", "state"} and type(row["pid"]) is int and row["pid"] > 0
                and row["state"] in {"ok", "standby", "backpressure"} and 0 <= time.time()-row["at"] <= 90)
    except (OSError, TypeError, ValueError, KeyError):
        return False


def connection_options(environ):
    """Use only the distinct producer DSN and explicitly mounted password.

    Passing password explicitly also prevents implicit libpq PGPASSWORD or
    password-file fallback. No API/delivery configuration loader is imported.
    """
    try:
        dsn = environ.get('SLI_REPORT_PRODUCER_PG_DSN', '')
        source = environ.get('SLI_REPORT_PRODUCER_PG_PASSWORD_FILE', '')
        if not isinstance(dsn, str) or not dsn.strip() or not isinstance(source, str) or not source:
            raise ValueError
        path = Path(source)
        if not path.is_absolute():
            raise ValueError
        with path.open('rb') as stream:
            data = stream.read(4097)
        if not data or len(data) > 4096:
            raise ValueError
        password = data.rstrip(b'\r\n').decode('utf-8')
        if not password or any(char in password for char in '\x00\r\n'):
            raise ValueError
        return {'conninfo': dsn.strip(), 'password': password}
    except (OSError, UnicodeError, ValueError, TypeError):
        raise ValueError('invalid_report_producer_connection') from None


def main():
    """Separate process entry point; no API or delivery credential fallback."""
    import argparse
    parser = argparse.ArgumentParser(description="Separate bounded report producer")
    parser.add_argument("--health", action="store_true")
    if parser.parse_args().health:
        return 0 if healthy() else 1
    try:
        options = connection_options(os.environ)
    except ValueError:
        return 1
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    try:
        import psycopg
        from psycopg.rows import dict_row
        with psycopg.connect(**options, connect_timeout=3, application_name="sli-report-producer", row_factory=dict_row) as conn:
            backend = SqlBackend(conn)
            token = None
            while not stop.is_set():
                result = run_cycle(backend, stop, leader_token=token)
                token = result["leader"]
                if result["status"] == "failed":
                    # Release the session and let the process supervisor apply
                    # its restart policy; a dead connection cannot recover here.
                    return 1
                if result["status"] in {"ok", "standby", "backpressure"}:
                    STATUS.write_text(json.dumps({"pid": os.getpid(), "at": time.time(), "state": result["status"]}))
                stop.wait(3)
        return 0
    except Exception:
        return 1


def read_claimed_access(conn, job_id, lease, *, deadline, clock=time.monotonic):
    """Read only schedule-derived actors and run the shared Python ACL engine.

    The injected connection must use the distinct proposed producer identity.
    No API/delivery DSN or HTTP ContextVar is used. This is not a producer loop
    and does not publish, resolve credentials or dispatch a transport.
    """
    try:
        identifiers = (str(UUID(str(job_id))), str(UUID(str(lease))))
    except (TypeError, ValueError, AttributeError):
        raise ValueError("invalid_schedule_access_facts") from None
    remaining = int((deadline - clock()) * 1000)
    if remaining <= 0:
        raise TimeoutError("report_producer_deadline")
    read_ms = min(remaining, MAX_READ_MS)
    try:
        with conn.transaction(), conn.cursor() as cur:
            cur.execute("select pg_catalog.set_config('statement_timeout',%s,true), "
                        "pg_catalog.set_config('lock_timeout',%s,true)",
                        (f"{read_ms}ms", f"{min(read_ms, MAX_LOCK_MS)}ms"))
            cur.execute("select public.report_schedule_acl_facts(%s::uuid,%s::uuid) as facts", identifiers)
            row = cur.fetchone()
    except Exception:
        # Database errors can carry values. Never return or print their text.
        raise RuntimeError("report_producer_read_failed") from None
    if clock() >= deadline:
        raise TimeoutError("report_producer_deadline")
    try:
        data = row["facts"]
        if not isinstance(data, dict) or set(data) != {
                "evaluated_at", "report_key", "schedule_revision", "owner_user_id", "actors", "bindings", "dependencies"}:
            raise ValueError
        stamp = data["evaluated_at"]
        stamp = datetime.fromisoformat(stamp.replace("Z", "+00:00")) if isinstance(stamp, str) else stamp
        if not isinstance(stamp, datetime) or stamp.tzinfo is None:
            raise ValueError
        if (type(data["schedule_revision"]) is not int or data["schedule_revision"] <= 0
                or type(data["owner_user_id"]) is not int or data["owner_user_id"] <= 0
                or not isinstance(data["actors"], list) or not 1 <= len(data["actors"]) <= 101
                or not isinstance(data["bindings"], list) or len(data["bindings"]) > 100):
            raise ValueError
        actors = {}
        for actor in data["actors"]:
            if not isinstance(actor, dict) or set(actor) != {"subject", "facts"}:
                raise ValueError
            access = compose_schedule_access(actor["subject"], actor["facts"], report_key=data["report_key"], now=stamp)
            identifier = access["subject"]["id"]
            if identifier in actors:
                raise ValueError
            actors[identifier] = access
        if data["owner_user_id"] not in actors:
            raise ValueError
        dependencies = data["dependencies"]
        expected_dependencies = {"security.queue"} if data["report_key"] == "file-audit.mass-operations" else set()
        if not isinstance(dependencies, dict) or set(dependencies) != expected_dependencies:
            raise ValueError
        dependency_access = {}
        for name, policy in dependencies.items():
            if set(policy) != {"subject", "facts"} or policy["subject"]["id"] != data["owner_user_id"]:
                raise ValueError
            dependency_access[name] = compose_schedule_access(policy["subject"], policy["facts"],
                report_key="security.problems", now=stamp)
        seen = set()
        for binding in data["bindings"]:
            if not isinstance(binding, dict) or set(binding) != {"id", "revision", "recipient_user_id", "channel", "channel_revision"}:
                raise ValueError
            identifier = str(UUID(binding["id"]))
            if (identifier in seen or binding["recipient_user_id"] not in actors
                    or type(binding["revision"]) is not int or binding["revision"] <= 0
                    or type(binding["channel_revision"]) is not int or binding["channel_revision"] <= 0
                    or binding["channel"] not in {"smtp", "telegram"}):
                raise ValueError
            seen.add(identifier)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ValueError("invalid_schedule_access_facts") from None
    if clock() >= deadline:
        raise TimeoutError("report_producer_deadline")
    return {**data, "dependencies": dependency_access, "evaluated_at": stamp, "actors": actors}


if __name__ == "__main__":
    raise SystemExit(main())
