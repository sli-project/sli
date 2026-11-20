"""Admission of one pinned cross-plugin chain; historical reads stay independent."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import json

from server.sli.plugins import registry, update_runtime

# Reviewed providers, not names or executable paths supplied by a rule.
REQUIREMENTS = (
    ("sli.ad", "sli.ad.process-episode.v1", "1.0.0"),
    ("sli.sigma", "sli.sigma.detection-match.v1", "1.0.0"),
)
NATIVE_DEPENDENCY = {
    "contract_id": "sli.ad.process-episode.v1",
    "versions": {"minimum": "1.0.0", "maximum_exclusive": "2.0.0"},
    "required": True,
    "exchange": "immutable_typed_result",
}


@dataclass(frozen=True)
class ChainDependencyBlocker:
    plugin_id: str
    contract_id: str
    reason: str


def _capability_available(plugin_id, contract_id, version):
    try:
        # Use the active package's reviewed code, never a stale cached manifest.
        hook = registry.plugin_hook(plugin_id, "semantic_capabilities")
        capabilities = hook() if hook else {}
        if not isinstance(capabilities, dict) or capabilities.get(contract_id) != version:
            return False
        manifest = json.loads((registry.ROOT / f"config/plugin_packages/v3/{plugin_id}.json").read_text("utf-8"))
        # The AD package's applied manifest attestation stays immutable; its
        # reviewed hook advertises the additive native contract. Sigma declares
        # the required contract and its version range in its own new manifest.
        return (manifest["plugin_id"] == plugin_id and manifest["plugin_version"] == version
                and (plugin_id != "sli.sigma" or (
                    contract_id in manifest["capabilities"]
                    and manifest["dependencies"] == [NATIVE_DEPENDENCY])))
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, ImportError):
        return False


@contextmanager
def process_chain_admission(cur):
    """Fence package updates and lock lifecycle rows through the caller's commit.

    The narrow SQL reader takes SHARE row locks in provider order. Disable and
    detach must update those same rows, so they cannot commit across an admitted
    slice. The caller persists any output in this same worker transaction.
    Missing/disabled inputs are blocked, never reported as a clean non-match.
    """
    blockers = []
    with ExitStack() as stack:
        # Bypass discovery's contribution cache when checking physical removal.
        installed = dict(registry.discover_plugins())
        for plugin_id, contract_id, version in REQUIREMENTS:
            if plugin_id not in installed:
                reason = "plugin_not_installed"
            elif not stack.enter_context(update_runtime.optional_admission(plugin_id)):
                reason = "plugin_update_draining"
            elif not _capability_available(plugin_id, contract_id, version):
                reason = "plugin_capability_unavailable"
            else:
                continue
            blockers.append(ChainDependencyBlocker(plugin_id, contract_id, reason))
        if not blockers:
            cur.execute("select * from public.read_sigma_chain_plugin_states_v1()")
            states = {row["plugin_id"]: row for row in cur.fetchall()}
            for plugin_id, contract_id, version in REQUIREMENTS:
                state = states.get(plugin_id)
                if not state or state["installed"] is not True:
                    reason = "plugin_not_installed"
                elif state["package_version"] != version:
                    reason = "plugin_version_unavailable"
                elif state["configured"] is not True:
                    reason = "plugin_not_configured"
                elif state["enabled"] is not True or state["component_runtime"] != "running":
                    reason = "plugin_inactive"
                else:
                    continue
                blockers.append(ChainDependencyBlocker(plugin_id, contract_id, reason))
        yield tuple(blockers)
