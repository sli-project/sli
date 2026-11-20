"""Security predecessor selection for builder publication under its per-key lock."""

from __future__ import annotations


def _security_predecessor(cur, report_key: str, published: dict) -> dict:
    """Keep retirement from erasing the last published security contract.

    The caller holds the report-key advisory transaction lock. This history is
    not proof of the original approval of every floating grant, and that lock
    does not serialize grant creation. Neither concern is repaired here.
    """
    if published:
        return published
    cur.execute(
        """select r.version,r.definition_json,d.dataset_key
           from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id
           where r.report_key=%s and r.status='retired'
             and r.published_at is not null
           order by r.published_at desc,r.version desc,r.id desc
           limit 1 for update of r""",
        (report_key,),
    )
    return dict(cur.fetchone() or {})
