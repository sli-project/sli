"""Built-in Source Pack contracts.

Source Packs are declarative project components, not a plugin execution API.
They describe product-specific semantics while the core remains responsible for
jobs, queues, storage, search, investigation, RBAC and operations.
"""

from server.source_packs.registry import get_source_pack, list_source_packs, resolve_source_pack

__all__ = ["get_source_pack", "list_source_packs", "resolve_source_pack"]
