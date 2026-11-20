from server.sli.entities.entity_model import extract_event_entities


DOMAIN_SID = "S-1-5-21-100000003-200000003-300000003-1104"


def _target(event_data: dict, *, server: str | None = "DC1") -> dict:
    event_row = {"event_id": 4624}
    if server:
        event_row["computer_name"] = server
    return next(
        link
        for link in extract_event_entities(event_row, event_data)
        if link["link_role"] == "target"
    )


def test_sid_identity_uses_stable_key_and_keeps_legacy_alias() -> None:
    link = _target(
        {
            "TargetUserName": "alice",
            "TargetDomainName": "EXAMPLE",
            "TargetUserSid": DOMAIN_SID,
        }
    )

    assert link["natural_key"] == f"sid:{DOMAIN_SID}"
    assert link["confidence"] == 1.0
    assert link["attributes"]["identity_state"] == "resolved"
    assert link["attributes"]["identity_step"] == 1
    assert "sam:example:alice" in link["attributes"]["identity_aliases"]
    assert "ad_user:example:alice" in link["attributes"]["identity_aliases"]


def test_missing_sid_uses_provisional_key_with_lower_confidence() -> None:
    provisional = _target(
        {
            "TargetUserName": "alice",
            "TargetDomainName": "EXAMPLE",
        }
    )
    resolved = _target(
        {
            "TargetUserName": "alice",
            "TargetDomainName": "EXAMPLE",
            "TargetUserSid": DOMAIN_SID,
        }
    )

    assert provisional["natural_key"] == "sam:example:alice"
    assert provisional["attributes"]["identity_state"] == "provisional"
    assert provisional["attributes"]["identity_step"] == 4
    assert provisional["confidence"] == 0.6
    assert provisional["confidence"] < resolved["confidence"]


def test_event_path_keeps_upn_and_mail_as_distinct_normalized_aliases() -> None:
    link = _target(
        {
            "TargetUserName": "alice",
            "TargetDomainName": "EXAMPLE",
            "TargetUserSid": DOMAIN_SID,
            "TargetUserPrincipalName": "Alice@Corp.Example",
            "TargetEmail": "ALICE@CORP.EXAMPLE",
        }
    )

    aliases = link["attributes"]["identity_aliases"]
    assert "upn:alice@corp.example" in aliases
    assert "mail:alice@corp.example" in aliases


def test_empty_ladder_key_falls_back_to_legacy_observation_key() -> None:
    link = _target(
        {
            "TargetUserName": "SYSTEM",
            "TargetDomainName": "NT AUTHORITY",
            "TargetUserSid": "S-1-5-18",
        },
        server=None,
    )

    assert link["natural_key"] == "ad_user:nt authority:system"
    assert link["attributes"]["identity_state"] == "unresolved"
    assert link["attributes"]["identity_step"] == 1
    assert link["confidence"] == 0.0
