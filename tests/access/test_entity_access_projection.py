from server.sli.access.entity_access_projection import project_ad_context


def test_ad_context_projection_hides_ungranted_fields_relations_and_counts() -> None:
    source = {
        "entity_id": 7,
        "ad_context_entity_id": 70,
        "resolution": "shared_entity_id",
        "returned_count": 2,
        "bounded": True,
        "items": [
            {
                "context_evidence_id": 101,
                "source_run_id": "run-secret",
                "source_section": "directory_accounts",
                "integrity_sha256": "hash-secret",
                "context_kind": "entity",
                "subject_entity_id": 70,
                "subject_display_name": "Alice",
                "attributes": {
                    "identity": {"object_sid": "S-1-5-21-7"},
                    "attributes": {
                        "display_name": "Alice",
                        "enabled": True,
                        "admin_count": 1,
                        "employee_id": "secret-hr",
                        "unknown_secret": "never-project",
                    },
                },
            },
            {
                "context_evidence_id": 102,
                "context_kind": "relation",
                "subject_entity_id": 70,
                "related_entity_id": 71,
                "related_display_name": "Domain Admins",
                "attributes": {"membership_type": "direct"},
            },
        ],
    }

    result = project_ad_context(
        source,
        capabilities={"field.identity_basic", "field.security"},
        include_relations=False,
    )

    assert result["returned_count"] == 1
    assert "ad_context_entity_id" not in result
    item = result["items"][0]
    assert item["attributes"] == {"display_name": "Alice", "enabled": True}
    assert item["subject_display_name"] == "Alice"
    for hidden in (
        "context_evidence_id", "source_run_id", "integrity_sha256",
        "subject_entity_id", "related_entity_id",
        "source_section",
    ):
        assert hidden not in item


def test_ad_context_projection_preserves_typed_group_relation_when_authorized() -> None:
    result = project_ad_context(
        {
            "entity_id": 7,
            "resolution": "shared_entity_id",
            "returned_count": 1,
            "bounded": True,
            "items": [{
                "context_evidence_id": 102,
                "integrity_sha256": "not-needed-in-ui",
                "context_kind": "relation",
                "subject_entity_id": 70,
                "related_entity_id": 71,
                "related_display_name": "VPNl2tp",
                "attributes": {"membership_type": "direct"},
            }],
        },
        capabilities={"field.identity_basic", "field.privilege", "field.technical"},
        include_relations=True,
    )

    assert result["returned_count"] == 1
    assert result["items"][0]["related_display_name"] == "VPNl2tp"
    assert result["items"][0]["related_entity_id"] == 71
    assert result["items"][0]["attributes"] == {"membership_type": "direct"}
    assert "integrity_sha256" not in result["items"][0]
