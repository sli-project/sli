"""Durable bounded read observations, independent of event delivery/backpressure."""
import json

from sli_agent.envelope import canonical
from sli_agent.protection import atomic_write
from sli_collect.eventlog_diagnostics import validate_observations


class EventLogHealth:
    def __init__(self, storage_dir):
        self.path = storage_dir / "eventlog-health.json"
        self.items = {}
        try:
            if self.path.stat().st_size <= 8192:
                values = validate_observations(json.loads(self.path.read_text("utf-8")))
                self.items = {item["channel"]: item for item in values}
        except (OSError, ValueError):
            pass

    def observations(self):
        return validate_observations(list(self.items.values()))

    def observe(self, module, revision):
        item = getattr(module, "read_observation", None)
        if item is not None:
            item = validate_observations([{**item, "policy_revision": revision}])[0]
            self.items[item["channel"]] = item
            atomic_write(self.path, canonical(self.observations()))
