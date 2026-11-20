# SPDX-License-Identifier: Apache-2.0
"""One service loop, bounded capture and ordered receipt-driven delivery."""
from __future__ import annotations

import os
import random
import threading
import time
from collections import deque
from datetime import datetime, timezone
from xml.etree.ElementTree import ParseError

from sli_agent.ad_dc import HISTORY_ID
from sli_agent.enrollment import IdentityStore
from sli_agent.envelope import canonical
from sli_agent.modules import configured_modules
from sli_agent.policies import acknowledge_policy, apply_policy, spool_limit
from sli_agent.probe import probe, save_report, service_identity_verified
from sli_agent.protection import atomic_write, directory_lock
from sli_agent.snapshot_stream import MODULE_FAMILIES, SnapshotStream
from sli_agent.spool import Spool, SpoolFull
from sli_agent.transport import Transport
from sli_agent.windows_audit import AuditManager


def deliver_once(spool, upload, *, now=None, batch_size=16, limit=None, diagnostics=None):
    blocked = set()
    counts = {}
    success = True
    attempts = 0
    pending = sorted(spool.pending(now=now), key=lambda value: value["envelope"]["module_id"] == HISTORY_ID)
    for value in pending:
        module_id = value["envelope"]["module_id"]
        if module_id == HISTORY_ID and (not success or limit is not None and attempts >= limit - 1):
            continue
        counts[module_id] = counts.get(module_id, 0) + 1
        if module_id in blocked or module_id in MODULE_FAMILIES and counts[module_id] > batch_size:
            continue
        if limit is not None and attempts >= limit:
            break
        attempts += 1
        result, error = None, None
        try:
            result = upload(value)
            accepted = spool.acknowledge(value, result)
        except (OSError, ValueError) as exc:
            accepted, error = False, exc
        if diagnostics is not None:
            try:
                diagnostics.observe(value, result, accepted=accepted, error=error, now=now)
            except (OSError, ValueError):
                # Diagnostics must not alter committed ACK/FIFO/backoff behavior.
                pass
        if not accepted:
            blocked.add(module_id)
            # A historical retry must not increase the live loop's backoff.
            if module_id != HISTORY_ID:
                success = False
    return success


def capture_module(module, spool, identity, *, now, batch_size=16, observe=None, clock=None):
    """Drain live event backlog, persisting each bounded packet first."""
    clock = clock or time.monotonic
    file_audit = module.module_id == "sli.file-audit"
    ad_dc = module.module_id == "sli.windows.ad-dc"
    budget = min(16, batch_size) if file_audit or ad_dc or module.module_id == "sli.workstations" else 1
    # Check the burst wall budget between bounded native reads, keeping other
    # collectors and receipt delivery reachable during backlog recovery.
    deadline = (clock() + (module.policy["wall_seconds"] if file_audit else 5)
                if file_audit or ad_dc or module.module_id == "sli.workstations" else None)
    if file_audit or ad_dc:
        # Delivery backpressure must not create a new burst every heartbeat.
        budget -= sum(value["envelope"]["module_id"] == module.module_id
                      for value in spool.pending(now=now))
    channel = None
    for _ in range(max(0, budget)):
        if deadline is not None and clock() >= deadline:
            break
        captured = spool.captured(module.module_id)
        sample = module.collect(captured, now=now, **({"channel": channel} if channel else {}))
        if observe is not None:
            observe(module)
        if sample is None:
            break
        # Only a successful durable capture permits the next read to advance.
        spool.capture(identity.key, agent_id=identity.agent_id, sample=sample, now=now)
        if file_audit:
            # A finite record loss is already accounted for; a native read
            # failure or journal break must still end this capture cycle.
            record_loss = sample.lost_count is not None and sample.lost_count > 0
            if (sample.cursor_after == sample.cursor_before
                or captured is not None and sample.generation != captured["generation"]
                or sample.payload["context"]["read_error"] is not None
                or sample.continuity_state == "gap" and not record_loss
                or not sample.payload["records"] and not sample.filtered_count and not record_loss):
                break
        else:
            channel = getattr(module, "catch_up_channel", None)
            if not channel:
                break


class SnapshotCapture:
    """One background source reader; timeout never creates abandoned readers."""
    def __init__(self, root):
        self.root = root
        self.job = None
        self.retry_at = {}
        self.busy = False
        self.streams = {}

    def tick(self, modules, spool, identity, *, now, batch_size=16):
        code = None
        self.busy = False
        if self.job:
            job = self.job
            if time.monotonic() >= job["deadline"] or job["module"] not in {m.module_id for m in modules}:
                job["stop"].set()
                code = "agent_snapshot_capture_timeout" if time.monotonic() >= job["deadline"] else None
            if job["done"].is_set():
                code = job["error"] or code
                self.retry_at[job["module"]] = time.monotonic() + 60
                self.job = None
        for module in modules:
            if module.module_id not in self.streams:
                self.streams[module.module_id] = SnapshotStream(self.root, module.module_id)
            stream = self.streams[module.module_id]
            state = stream.read()
            if state and state["ready"]:
                self.busy = True
                # A bounded burst, with cursor movement exclusively in spool.
                for _ in range(batch_size):
                    sample = stream.next_sample(spool.captured(module.module_id))
                    if sample is None:
                        break
                    spool.capture(identity.key, agent_id=identity.agent_id, sample=sample, now=now)
                continue
            if self.job or time.monotonic() < self.retry_at.get(module.module_id, 0):
                continue
            state = stream.begin(module.policy, now=now)
            if state is None:
                continue
            # Use the frozen policy even if assignment changed after restart.
            job = {"module": module.module_id, "stop": threading.Event(), "done": threading.Event(),
                   "deadline": time.monotonic() + state["policy"]["capture_seconds"], "error": None}
            def capture(module=module, stream=stream, state=state, job=job):
                try:
                    families = module.capture(state["policy"], deadline=job["deadline"], stop=job["stop"])
                    if not job["stop"].is_set() and time.monotonic() < job["deadline"]:
                        stream.freeze(state, families)
                except Exception:  # noqa: BLE001 - no source diagnostics
                    job["error"] = "agent_snapshot_capture_failed"
                finally:
                    job["done"].set()
            self.job = job
            threading.Thread(target=capture, name="snapshot-capture", daemon=True).start()
        self.busy = self.busy or self.job is not None
        return code

    def close(self):
        if self.job:
            self.job["stop"].set()


def run(config, stop, *, release_directory=None):
    if (os.name == "nt" or config.service_identity_sid is not None) and not service_identity_verified(config):
        # Check before the service/spool locks can secure state for the wrong
        # account. No private identity is loaded and no collector is constructed.
        save_report(config, probe(config, assigned_modules=(), planned=False))
        raise RuntimeError("agent_service_identity_unverified")
    # Distinct from the short spool lock; prevents two service/CLI owners from
    # collecting the same channel even while neither is writing a spool entry.
    with directory_lock(config.storage_dir / "running"):
        store = IdentityStore(config)
        public = store.prepare()
        modules = configured_modules(config, public["host_id"])
        spool = Spool(config.storage_dir / "spool", max_bytes=config.spool_max_bytes,
                      max_age_seconds=config.spool_max_age_seconds)
        transport = Transport(config)
        updates = None
        if config.update_root is not None and release_directory is not None:
            from sli_agent.updates import Updates
            updates = Updates(config)
        if updates is not None and updates.read()["pending"]:
            from cryptography import x509
            identity = store.load()
            if identity is None:
                raise ValueError("agent_not_enrolled")
            cert = x509.load_pem_x509_certificate(identity.certificate_pem.encode("ascii"))
            now = datetime.now(timezone.utc)
            if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
                raise ValueError("agent_certificate_expired")
            assignment = transport.get("/api/v1/agent/identity", identity=identity)
            if assignment.get("agent_id") != identity.agent_id:
                raise ValueError("agent_module_identity_mismatch")
            modules = configured_modules(config, public["host_id"], assignment["assigned_modules"])
            if any(module.module_id in {"sli.windows-eventlog", "sli.workstations", "sli.windows.ad-dc"} for module in modules):
                # Load the native reader/dependencies without collecting rows or
                # advancing a cursor during candidate admission.
                import importlib
                for name in ("win32evtlog", "sli_collect.eventlog", "sli_collect.packets"):
                    importlib.import_module(name)
            updates.healthy(release_directory)
        failures = 0
        snapshots = SnapshotCapture(config.storage_dir / "capture")
        audit_manager = AuditManager(config.storage_dir / "windows-audit")
        from sli_agent.file_audit import FileAuditManager
        file_audit_manager = FileAuditManager(config.storage_dir / "file-audit", audit_manager)
        windows_audit = None
        from sli_agent.eventlog_health import EventLogHealth
        eventlog_health = EventLogHealth(config.storage_dir)
        from sli_agent.delivery_diagnostics import DeliveryHealth
        delivery_health = DeliveryHealth(config.storage_dir)
        sends = deque()
        collection_state = "unknown"
        interval = config.interval_seconds
        next_collection = 0.0
        last_revision = None
        while not stop.is_set():
            now = datetime.now(timezone.utc)
            error_code = None
            history_error_code = None
            active_modules = modules
            rights = None
            control = None
            delivery_reporting = False
            try:
                identity = store.load()
                if identity is None:
                    raise ValueError("agent_not_enrolled")
                # Renewal failure does not prevent delivery using a still-valid
                # certificate. Once expired, mTLS fails closed and spool remains.
                try:
                    store.renew_if_due(transport, now=now)
                    identity = store.load()
                except (OSError, ValueError):
                    pass
                assigned_modules = ()
                delivered = False
                try:
                    assignment = transport.get("/api/v1/agent/identity", identity=identity)
                    delivery_reporting = assignment.get("delivery_diagnostics_supported") is True
                    if "agent_removal" in assignment:
                        from sli_agent.removal import launch
                        snapshots.close()
                        if launch(config, assignment, transport, identity):
                            return
                        raise ValueError("agent_removal_cleanup_failed")
                    applied = apply_policy(config, public["host_id"], assignment, transport, identity,
                                           defer_ack=True, audit_manager=audit_manager, file_audit_manager=file_audit_manager)
                    windows_audit = applied.windows_audit
                    control = applied.control
                    desired = control["state"] if control else "active"
                    collection_state = "draining" if desired == "drain" else desired
                    if control:
                        interval = control["interval_seconds"]
                    if assignment.get("policy_revision") != last_revision:
                        next_collection = 0.0
                        last_revision = assignment.get("policy_revision")
                    active_modules = applied if desired == "active" else modules
                    spool.max_bytes = spool_limit(config, active_modules, control)
                    assigned_modules = assignment["assigned_modules"]
                    if desired != "active":
                        snapshots.close()
                    # Apply pause before any data send, including an offline
                    # agent's first reconnect and retries after a lost ack.
                    if desired != "drain":
                        acknowledge_policy(applied, transport, identity, state=collection_state,
                                           diagnostics=eventlog_health.observations())
                    delivered = True
                    if desired != "paused":
                        tick = time.monotonic()
                        while sends and sends[0] <= tick - 60:
                            sends.popleft()
                        limit = max(0, control["rate_limit_per_minute"] - len(sends)) if control else None
                        def upload(value):
                            sends.append(time.monotonic())
                            return transport.post("/api/v1/agent/packets", value, identity=identity)
                        delivered = deliver_once(spool, upload, now=now, limit=limit,
                                                 batch_size=min(16, control["batch_size"]) if control else 16,
                                                 diagnostics=delivery_health)
                    if desired == "drain" and not spool.pending(now=now):
                        collection_state = "paused"
                        acknowledge_policy(applied, transport, identity, state="paused",
                                           diagnostics=eventlog_health.observations())
                    if updates is not None:
                        updates.report(transport, identity)
                        offer = assignment.get("agent_update")
                        if offer and updates.offer(offer, transport, identity):
                            snapshots.close()
                            return  # Launcher starts the candidate after this process exits.
                    elif assignment.get("agent_update"):
                        from sli_agent.msi import report_zip_offer
                        report_zip_offer(config, assignment["agent_update"], transport, identity)
                    # Keep acknowledgement/probe and update ordering unchanged.
                    # Legacy check-ins without collection control cannot accept
                    # the independent audit heartbeat; local status still can.
                    if control is not None and windows_audit is not None:
                        transport.post("/api/v1/agent/windows-audit-report",
                                       {"windows_audit": windows_audit}, identity=identity)
                    if applied.file_audit is not None:
                        transport.post("/api/v1/agent/file-audit-report", applied.file_audit, identity=identity)
                        file_audit_manager.acknowledge(applied.file_audit)
                except (OSError, ValueError, KeyError):
                    # Fail closed: no stale collectors or data sends when the
                    # current policy cannot be obtained/applied. Check-in retries
                    # remain independent of the durable event spool.
                    error_code = "agent_module_config_unavailable"
                    delivered = False
                    active_modules = modules
                    snapshots.close()
                if error_code is None and collection_state == "active" and (os.name == "nt" or config.service_identity_sid is not None):
                    candidates = active_modules
                    active_modules = [module for module in candidates if module.module_id == "sli.heartbeat"]
                    rights = probe(config, assigned_modules=assigned_modules, planned=False, now=now)
                    save_report(config, rights)
                    if not rights["identity_verified"] or (not rights["ready"] and not config.allow_missing_rights):
                        # Heartbeat and durable delivery remain possible while
                        # every source collector is paused. An override never
                        # permits collection as the wrong service identity.
                        error_code = "agent_required_rights_missing"
                    else:
                        active_modules = candidates
                # Check-in is the heartbeat while paused/draining; never append
                # heartbeat packets to the spool we have promised to preserve.
                capture_modules = active_modules if error_code in (None, "agent_required_rights_missing") and collection_state == "active" else ()
                if capture_modules and control is not None:
                    # Revisioned check-in already supplies an independent
                    # heartbeat. Do not let heartbeat packets fill or starve
                    # the rate-limited evidence spool.
                    capture_modules = [module for module in capture_modules if module.module_id != "sli.heartbeat"]
                for module in capture_modules:
                    if module.module_id in MODULE_FAMILIES:
                        continue
                    if module.module_id != "sli.heartbeat" and time.monotonic() < next_collection:
                        continue
                    if getattr(module, "low_priority", False):
                        pending = spool.pending(now=now)
                        # One outstanding history packet; reserve half the spool
                        # for current capture during network/import backpressure.
                        if (any(value["envelope"]["module_id"] == HISTORY_ID for value in pending)
                                or sum(len(canonical(value)) for value in pending) + 60 * 1024 > spool.max_bytes // 2):
                            continue
                    try:
                        capture_module(module, spool, identity, now=now,
                            batch_size=control["batch_size"] if control else 16,
                            observe=(lambda source: eventlog_health.observe(source, last_revision))
                            if control is not None else None)
                    except SpoolFull as exc:
                        if getattr(module, "low_priority", False):
                            history_error_code = str(exc)
                        else:
                            error_code = str(exc)
                            delivered = False
                    except (OSError, ValueError, RuntimeError, ParseError):
                        if not getattr(module, "low_priority", False):
                            raise
                        history_error_code = "agent_history_capture_failed"
                if capture_modules and time.monotonic() >= next_collection:
                    next_collection = time.monotonic() + interval
                snapshot_modules = [module for module in capture_modules if module.module_id in MODULE_FAMILIES]
                try:
                    error_code = snapshots.tick(snapshot_modules, spool, identity, now=now,
                                                batch_size=min(16, control["batch_size"]) if control else 16) or error_code
                except SpoolFull as exc:
                    error_code = str(exc)
                    delivered = False
                failures = 0 if delivered else min(failures + 1, 10)
            except (OSError, ValueError, RuntimeError):
                error_code = "agent_cycle_failed"
                failures = min(failures + 1, 10)
                snapshots.close()
            if delivery_reporting:
                try:
                    # Independent mTLS diagnostics must also work during drain;
                    # they do not acknowledge policy/state or consume the spool.
                    transport.post("/api/v1/agent/policy-report",
                                   {"delivery_diagnostics": delivery_health.observations()}, identity=identity)
                except (OSError, ValueError):
                    pass  # A failed report does not erase the durable local cause.
            # Safe machine-readable backpressure visibility, never source rows,
            # keys, host/account names or network exception diagnostics.
            atomic_write(config.storage_dir / "status.json", canonical({
                "observed_at_utc": now.isoformat(),
                **delivery_health.status_fields(),
                "windows_audit": windows_audit,
                "eventlog_diagnostics": eventlog_health.observations(),
                "collection_state": collection_state,
                "collection_enabled": error_code is None and collection_state == "active" and any(module.module_id != "sli.heartbeat" for module in active_modules),
                "enabled_modules": [module.module_id for module in active_modules],
                "rights_probe_ready": rights["ready"] if rights is not None else None,
                "history_error_code": history_error_code,
                "retry_count": failures, "error_code": error_code or ("agent_delivery_pending" if failures else None)}))
            delay = min(interval, 60) if failures == 0 else min(60, 2 ** failures + random.uniform(0, 1))
            if snapshots.busy:
                delay = min(delay, 1)
            stop.wait(delay)
        snapshots.close()


def child_main(config_path, directory):
    import threading
    from pathlib import Path

    from sli_agent.config import AgentConfig
    run(AgentConfig.load(Path(config_path)), threading.Event(), release_directory=directory)
