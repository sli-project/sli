from __future__ import annotations

import importlib

import pytest

from server.sli.storage.xml_safety import UnsafeXmlError, parse_bounded_xml


def test_bounded_xml_accepts_normal_event_document() -> None:
    root = parse_bounded_xml("<Event><EventData><Data Name='User'>alice</Data></EventData></Event>")
    assert root.tag == "Event"


def test_bounded_xml_rejects_doctype_and_entities() -> None:
    with pytest.raises(UnsafeXmlError, match="dtd_or_entity"):
        parse_bounded_xml("<!DOCTYPE Event [<!ENTITY x 'secret'>]><Event>&x;</Event>")
    with pytest.raises(UnsafeXmlError, match="dtd_or_entity"):
        parse_bounded_xml(" " * 5000 + "<!DOCTYPE Event><Event />")


def test_bounded_xml_rejects_size_and_depth_limits() -> None:
    with pytest.raises(UnsafeXmlError, match="size_limit"):
        parse_bounded_xml("<E>payload</E>", max_bytes=4)
    with pytest.raises(UnsafeXmlError, match="depth_limit"):
        parse_bounded_xml("<a><b><c /></b></a>", max_depth=2)
    with pytest.raises(UnsafeXmlError, match="node_limit"):
        parse_bounded_xml("<a><b /><c /></a>", max_nodes=2)


@pytest.mark.parametrize(
    "module_name",
    [
        "scripts.import.import_event_jsonl_to_postgres",
    ],
)
def test_event_importers_preserve_xml_parse_failure_as_data_quality(
    module_name: str,
) -> None:
    importer = importlib.import_module(module_name)

    parsed = importer.parse_event_data("<Event><broken></Event>")

    assert parsed == {
        "_sli_data_quality": {
            "event_data_parse_status": "failed",
            "error_type": "ParseError",
        }
    }
