"""Native evidence bridge used inside the caller's publication transaction.

The database authorizes the session login against administrator-bound native
sources, then verifies type, generation, root and hash. No reader fallback,
implicit connections, commits, source writes or integer coercion of plugin IDs.
"""
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceRefError


def validate_finding_evidence(cur, refs: tuple[EvidenceRef, ...]) -> tuple[EvidenceRef, ...]:
    """Preflight the complete bounded set before creating a finding."""
    if (type(refs) is not tuple or len(refs) > 256
            or any(not isinstance(ref, EvidenceRef) for ref in refs)):
        raise EvidenceRefError("evidence_reference_invalid")
    unique = {}
    for ref in refs:
        key = (ref.scope, ref.storage_kind, ref.native_id)
        if key in unique and unique[key].sha256 != ref.sha256:
            raise EvidenceRefError("evidence_hash_conflict")
        unique[key] = ref
    for ref in unique.values():
        try:
            cur.execute("""
                select public.resolve_finding_evidence_ref(%s,%s,%s,%s,%s,%s,%s,%s) as verified
            """, ref.params)
            row = cur.fetchone()
        except Exception:
            raise EvidenceRefError("evidence_verification_failed") from None
        if not row or row.get("verified") is not True:
            raise EvidenceRefError("evidence_unavailable_or_denied")
    return tuple(unique.values())


def link_finding_evidence(cur, *, finding_id: int, refs: tuple[EvidenceRef, ...]) -> int:
    """Append exact links, rechecking authorization/integrity in each statement.

    Core links also use the legacy finding_evidence table. Plugin-native links
    use its typed companion, so last_evidence_event_id remains a real core ID.
    The caller must roll back its publication transaction on any error.
    """
    if type(finding_id) is not int or not 0 < finding_id < 2**63:
        raise EvidenceRefError("evidence_finding_invalid")
    refs = validate_finding_evidence(cur, refs)
    added = 0
    for ref in refs:
        try:
            cur.execute("""
                select public.link_finding_evidence_ref(%s,%s,%s,%s,%s,%s,%s,%s,%s) as added
            """, (finding_id, *ref.params))
            row = cur.fetchone()
        except Exception:
            raise EvidenceRefError("evidence_link_failed") from None
        if not row or type(row.get("added")) is not bool:
            raise EvidenceRefError("evidence_link_failed")
        added += row["added"]
    return added
