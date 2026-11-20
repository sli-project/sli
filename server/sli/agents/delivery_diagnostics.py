"""Bounded rejection logging after authenticated ingestion, without packet data."""
from collections import OrderedDict
import logging
import re
from threading import Lock
import time
from uuid import UUID

from sli_agent.delivery_diagnostics import safe_code

_LOG = logging.getLogger(__name__)


class RejectionLimiter:
    def __init__(self, capacity=1024, interval=60):
        self.capacity = capacity
        self.interval = interval
        self.entries = OrderedDict()
        self.lock = Lock()
        self.window_start = None
        self.window_count = 0

    def allow(self, key, now):
        with self.lock:
            if self.window_start is None or now - self.window_start >= self.interval:
                self.window_start, self.window_count = now, 0
            if self.window_count >= self.capacity:
                return False
            previous = self.entries.get(key)
            if previous is not None and now - previous < self.interval:
                return False
            self.window_count += 1
            self.entries[key] = now
            self.entries.move_to_end(key)
            while len(self.entries) > self.capacity:
                self.entries.popitem(last=False)
            return True


_LIMITER = RejectionLimiter()


def log_rejection(identity, value, result, *, limiter=_LIMITER, clock=time.monotonic):
    """Only callers holding a verified TLS identity may call this function."""
    try:
        agent_id = str(identity["id"])
        if str(UUID(agent_id)) != agent_id:
            return False
        envelope = value["envelope"]
        module = envelope["module_id"]
        sequence = envelope["sequence"]
        packet_id = envelope["packet_id"]
        status = result["status"]
        if (not isinstance(module, str) or re.fullmatch(r"[a-z][a-z0-9_.-]{0,127}", module) is None
                or type(sequence) is not int or not 0 <= sequence <= 2**63 - 1
                or not isinstance(packet_id, str) or str(UUID(packet_id)) != packet_id
                or status not in ("rejected", "retry_later")):
            return False
        code = safe_code(result.get("error_code"))
    except (KeyError, ValueError, TypeError, AttributeError):
        return False
    if not limiter.allow((agent_id, module, code), clock()):
        return False
    _LOG.warning("agent_packet_delivery_rejected agent_id=%s module_id=%s packet_id=%s sequence=%s receipt_status=%s error_code=%s",
                 agent_id, module, packet_id, sequence, status, code)
    return True
