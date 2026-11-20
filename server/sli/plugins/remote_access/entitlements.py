"""Typed v1 compatibility adapter over directory-owned VPN membership facts.

The directory producer and its published tables remain shared. This consumer
keeps the existing bounded query and report row representation unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

CONTRACT_ID = "directory.vpn_entitlements.v1"
MAX_ENTITLEMENT_ROWS = 5_000


@dataclass(frozen=True)
class VpnEntitlements:
    source_domain_id: int
    entity_ids: tuple[int, ...]
    contract_id: ClassVar[str] = CONTRACT_ID

    def as_rows(self) -> list[dict[str, int]]:
        """Preserve the legacy dataset bytes without exposing mutable state."""
        return [{"entity_id": entity_id} for entity_id in self.entity_ids]


def read_entitlements(cursor, *, source_domain_id: int) -> VpnEntitlements:
    """Called only after the report's trusted domain/access preflight."""
    cursor.execute(
        """select distinct source_entity.id as entity_id
               from ad_context_relation_versions relation
               join entities_v2 source_entity on source_entity.id=relation.source_entity_id
               join storage_v2_entity_type entity_type on entity_type.id=source_entity.entity_type_id
               where source_entity.domain_id=%s and relation.valid_to_utc is null
                 and relation.relation_kind='member_of'
                 and relation.source_section='vpn_membership'
                 and entity_type.value='ad_user'
                 and entity_v2_is_active(source_entity.id)
               order by source_entity.id limit %s""",
        (source_domain_id, MAX_ENTITLEMENT_ROWS + 1),
    )
    rows = cursor.fetchall()
    if len(rows) > MAX_ENTITLEMENT_ROWS:
        raise ValueError("vpn_connections_entitlement_bound_exceeded")
    return VpnEntitlements(source_domain_id, tuple(row["entity_id"] for row in rows))
