from __future__ import annotations

from pathlib import Path

import pytest


def test_directory_details_repair_preserves_supplemental_values() -> None:
    from scripts.maintenance.ad_context_entity_details_repair import merge_directory_details

    directory = {
        "display_name": "Directory name",
        "exact_last_logon_status": "observed",
        "department": "IT",
    }
    current = {"display_name": "Membership name", "member_scope": "vpn"}

    assert merge_directory_details(directory, current) == {
        "display_name": "Membership name",
        "exact_last_logon_status": "observed",
        "department": "IT",
        "member_scope": "vpn",
    }


def test_directory_details_repair_requires_exact_apply_contract() -> None:
    from scripts.maintenance import ad_context_entity_details_repair as repair

    assert repair.APPLY_TOKEN == "APPLY-AD-CONTEXT-DIRECTORY-DETAILS-REPAIR"
    assert repair.ROLLBACK_TOKEN == "ROLLBACK-AD-CONTEXT-DIRECTORY-DETAILS-REPAIR"
    with pytest.raises(ValueError, match="confirmation token"):
        repair.require_confirmation("wrong", repair.APPLY_TOKEN)

    source = Path(repair.__file__).read_text(encoding="utf-8")
    assert "--expected-targets" in source
    assert "--receipt" in source
    assert "--use-admin-connection" in source
    assert "adlog_storage_owner" in source
    assert "has_table_privilege" in source
    assert "before_sha256" in source
    assert "after_sha256" in source
    assert "attributes_json=%s::jsonb" in source
