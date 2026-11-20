from __future__ import annotations

import pytest

from server.source_packs.windows_ad_dc import (
    event_facts_for_event,
    semantic_projection_for_event,
)


@pytest.mark.parametrize("representation", ["compact", "semantic"])
@pytest.mark.parametrize(
    "substatus,expected",
    [
        ("0xC000006A", "0xC000006A"),
        (" 0xc000006a ", "0xc000006a"),
        ("0x0", "0xC000006D"),
        ("0x00000000", "0xC000006D"),
        ("0", "0xC000006D"),
        (None, "0xC000006D"),
        ("", "0xC000006D"),
        ("-", "0xC000006D"),
    ],
)
def test_failed_logon_uses_specific_substatus_or_falls_back_to_status(
    representation, substatus, expected,
):
    data = {"Status": "0xC000006D", "SubStatus": substatus}
    original = dict(data)
    if representation == "compact":
        facts = event_facts_for_event(
            row={"event_id": 4625, "channel": "Security"}, event_data=data,
        )
    else:
        projection = semantic_projection_for_event(
            event_id=4625,
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            event_data=data,
            correlation_id=None,
            source_host="dc-fixture",
        )
        assert projection["semantic_type"] == "authentication.session.failed"
        facts = projection["facts"]
        assert facts["failure_status"] == expected
        assert facts["result"] == "failure"

    assert facts["result_code"] == expected
    assert data == original


def test_compact_failed_logon_preserves_explicit_result_code_priority():
    compact = event_facts_for_event(
        row={"event_id": 4625, "channel": "Security"},
        event_data={
            "ResultCode": "0xC000015B",
            "Status": "0xC000006D",
            "SubStatus": "0xC000006A",
        },
    )

    assert compact["result_code"] == "0xC000015B"


def test_compact_other_events_preserve_status_priority():
    compact = event_facts_for_event(
        row={"event_id": 4776, "channel": "Security"},
        event_data={"Status": "0xC000006D", "SubStatus": "0xC000006A"},
    )

    assert compact["result_code"] == "0xC000006D"
