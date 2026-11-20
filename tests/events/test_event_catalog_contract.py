"""Контракт каталога событий: правило границы и то, что проверка подключена.

Правило введено 28.07.2026 решением владельца: обязательная полнота
применяется к новым и изменённым записям, прежние освобождены.

Отдельный тест проверяет, что проверка вообще вызывается из release_check.
Прежний валидатор существовал давно и не вызывался ниоткуда - ни отсюда, ни из
одного модуля. Объявленный и неподключённый механизм неотличим от
отсутствующего, и заметить это можно было только поиском по дереву. Тест
превращает подключение в требование.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from server.sli.events import event_catalog
from server.sli.events.event_catalog_quality import (
    build_catalog_baseline,
    catalog_completeness,
    validate_catalog_changes,
    validate_catalog_data,
)
from server.sli.storage.storage_policy import (
    StoragePolicy,
    resolve_catalogue_retention,
    resolve_descriptor_retention,
)

ROOT = Path(__file__).resolve().parents[2]
КАТАЛОГ = ROOT / "config" / "event_catalog.json"
СНИМОК = ROOT / "config" / "event_catalog_baseline.json"

ПОЛНАЯ_ЗАПИСЬ = {
    "source": "sli.exchange",
    "stream": "message-tracking",
    "event_key": "RECEIVE",
    "event_id": None,
    "severity": "low",
    "title": "Проверочная запись",
    "why": "Существует только в тесте.",
    "fix": "Ничего не делать.",
    "base_risk": "low",
    "purpose_tier": "technical",
    "noise_class": "context",
    "category": "authentication",
    "lifecycle": {
        "raw_payload_days": 2,
        "record_days": 7,
        "warm_record_days": 365,
        "rollup": None,
    },
    "correlation": None,
    "correlation_absent_reason": "одиночное событие, парного нет",
    "required_fields": ["target_user_name", "target_user_sid"],
}


@pytest.fixture(scope="module")
def каталог() -> dict:
    return json.loads(КАТАЛОГ.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def снимок() -> dict:
    assert СНИМОК.is_file(), (
        "Снимок отпечатков обязателен: без него новая и прежняя запись "
        "неразличимы, и правило границы вырождается"
    )
    return json.loads(СНИМОК.read_text(encoding="utf-8"))


def test_нетронутый_каталог_проходит(каталог, снимок) -> None:
    """Каталог проходит с одной принятой provider-правкой Event 1102."""
    результат = validate_catalog_changes(каталог, снимок)
    assert результат["valid"], результат["violations"]
    assert результат["новых"] == 30
    assert результат["изменённых"] == 75


def test_новая_запись_без_заполнения_блокирует(каталог, снимок) -> None:
    подделка = copy.deepcopy(каталог)
    неполная = {k: v for k, v in ПОЛНАЯ_ЗАПИСЬ.items()
                if k in {"source", "stream", "event_key", "severity", "title", "why", "fix"}}
    подделка["entries"].append(неполная)

    результат = validate_catalog_changes(подделка, снимок)

    assert not результат["valid"]
    assert результат["новых"] == 31
    нарушение = результат["violations"][0]
    assert нарушение["вид"] == "новая"
    # Все три поля схемы версии 2 обязаны попасть в список недостающих:
    # именно они не дают заполнять каталог в форме, которую придётся переписывать.
    assert {"lifecycle", "correlation", "required_fields"} <= set(нарушение["не_заполнено"])


def test_новая_заполненная_запись_проходит(каталог, снимок) -> None:
    подделка = copy.deepcopy(каталог)
    подделка["entries"].append(copy.deepcopy(ПОЛНАЯ_ЗАПИСЬ))

    результат = validate_catalog_changes(подделка, снимок)

    assert результат["valid"], результат["violations"]
    assert результат["новых"] == 31


def test_новая_запись_без_срока_тёплого_слоя_блокируется(каталог, снимок) -> None:
    подделка = copy.deepcopy(каталог)
    запись = copy.deepcopy(ПОЛНАЯ_ЗАПИСЬ)
    del запись["lifecycle"]["warm_record_days"]
    подделка["entries"].append(запись)

    результат = validate_catalog_changes(подделка, снимок)

    assert not результат["valid"]
    assert "lifecycle.warm_record_days" in результат["violations"][0]["не_заполнено"]


def test_lifecycle_отклоняет_невалидный_predicate() -> None:
    запись = copy.deepcopy(ПОЛНАЯ_ЗАПИСЬ)
    запись["lifecycle"]["warm_record_days"] = {
        "default": 365,
        "rules": [
            {
                "field": "message",
                "op": "regex",
                "value": "[",
                "then": 30,
            }
        ],
    }

    результат = validate_catalog_data({"entries": [запись]})

    assert not результат["valid"]
    assert результат["errors"][0]["code"] == "predicate_regex_invalid"


def test_string_event_key_и_noise_predicate_проходят() -> None:
    запись = copy.deepcopy(ПОЛНАЯ_ЗАПИСЬ)
    запись["noise_class"] = {
        "default": "noise",
        "rules": [
            {
                "field": "message_sample",
                "op": "contains",
                "value": "external",
                "then": "signal",
            }
        ],
    }

    результат = validate_catalog_data({"entries": [запись]})

    assert результат["valid"], результат["errors"]


def test_duplicate_string_event_key_в_source_stream_блокируется() -> None:
    первая = copy.deepcopy(ПОЛНАЯ_ЗАПИСЬ)
    вторая = copy.deepcopy(ПОЛНАЯ_ЗАПИСЬ)
    вторая["event_id"] = 9999

    результат = validate_catalog_data({"entries": [первая, вторая]})

    assert not результат["valid"]
    assert any(error["code"] == "duplicate_identity" for error in результат["errors"])


def test_exchange_chain_correlation_проходит() -> None:
    запись = copy.deepcopy(ПОЛНАЯ_ЗАПИСЬ)
    запись["correlation"] = {
        "role": "open",
        "key": ["correlation_id"],
        "cardinality": "chain",
        "terminators": ["DELIVER", "SEND", "FAIL"],
        "close_timeout_seconds": 86400,
    }
    запись.pop("correlation_absent_reason")

    результат = validate_catalog_data({"entries": [запись]})

    assert результат["valid"], результат["errors"]


def test_pair_correlation_с_двумя_терминаторами_блокируется() -> None:
    запись = copy.deepcopy(ПОЛНАЯ_ЗАПИСЬ)
    запись["correlation"] = {
        "role": "open",
        "key": "logon_id",
        "cardinality": "pair",
        "terminators": ["4634", "4647"],
        "close_timeout_seconds": 86400,
    }
    запись.pop("correlation_absent_reason")

    результат = validate_catalog_data({"entries": [запись]})

    assert not результат["valid"]
    assert any(
        error["code"] == "correlation_pair_has_multiple_terminators"
        for error in результат["errors"]
    )


def test_required_fields_проверяются_против_storage_contract() -> None:
    запись = copy.deepcopy(ПОЛНАЯ_ЗАПИСЬ)
    запись["required_fields"] = ["TargetUserName"]

    результат = validate_catalog_data({"entries": [запись]})

    assert not результат["valid"]
    assert any(error["code"] == "required_fields_invalid" for error in результат["errors"])


def test_v2_lookup_читает_string_event_key(tmp_path: Path, monkeypatch) -> None:
    путь = tmp_path / "exchange_catalog.json"
    путь.write_text(
        json.dumps({"entries": [ПОЛНАЯ_ЗАПИСЬ]}, ensure_ascii=False),
        encoding="utf-8",
    )
    monkeypatch.setattr(event_catalog, "CATALOG_PATH", путь)
    event_catalog._descriptor_index_for_path.cache_clear()

    запись = event_catalog.lookup_event_descriptor(
        "sli.exchange",
        "message-tracking",
        "RECEIVE",
    )

    assert запись is not None
    assert запись["event_key"] == "RECEIVE"


def test_semantic_descriptor_identity_читает_exchange_string_event_key(
    tmp_path: Path,
    monkeypatch,
) -> None:
    путь = tmp_path / "exchange_catalog.json"
    запись = {
        **ПОЛНАЯ_ЗАПИСЬ,
        "provider_name": "MSExchange Message Tracking",
    }
    путь.write_text(
        json.dumps({"entries": [запись]}, ensure_ascii=False),
        encoding="utf-8",
    )
    monkeypatch.setattr(event_catalog, "CATALOG_PATH", путь)
    event_catalog._descriptor_index_for_path.cache_clear()

    найдено = event_catalog.lookup_semantic_event_descriptor(
        "sli.exchange",
        "message-tracking",
        "RECEIVE",
        "MSExchange Message Tracking",
    )
    неверный_provider = event_catalog.lookup_semantic_event_descriptor(
        "sli.exchange",
        "message-tracking",
        "RECEIVE",
        "Other Provider",
    )

    assert найдено is not None
    assert найдено["event_key"] == "RECEIVE"
    assert неверный_provider is None


def test_legacy_windows_entry_доступна_через_v2_lookup() -> None:
    запись = event_catalog.lookup_event_descriptor(
        "sli.windows.ad-dc",
        "Security",
        "4624",
    )

    assert запись is not None
    assert запись["event_id"] == 4624


def test_windows_authentication_catalog_uses_descriptor_roles_not_general_correlation(каталог) -> None:
    entries = {entry["event_id"]: entry for entry in каталог["entries"]}

    assert entries[4624]["correlation"] is None
    assert entries[4634]["correlation"] is None
    assert entries[4624]["lifecycle"]["rollup_role"] == "open"
    assert entries[4634]["lifecycle"]["rollup_role"] == "close"
    assert "не генерирует" in entries[4772]["why"]
    assert entries[4772]["noise_class"] == "context"


def test_authentication_descriptors_declare_descriptor_owned_lifecycle_v2(каталог) -> None:
    entries = {entry["event_id"]: entry for entry in каталог["entries"]}

    expected_roles = {4624: "open", 4634: "close", 4608: "boot_scope"}
    for event_id, role in expected_roles.items():
        lifecycle = entries[event_id]["lifecycle"]
        assert lifecycle["rollup"] == "authentication_session"
        assert lifecycle["rollup_role"] == role
        assert lifecycle["promotion"] == {
            "version": "descriptor-lifecycle-v2",
            "archive_requirement": "no_archive",
            "post_promotion_disposition": "delete_source",
            "read_representation": "derived_only",
            "high_volume": True,
            "semantic_role": "authentication_boundary",
            "hot_need": "raw_investigation_window",
            "warm_value": "closed_or_incomplete_authentication_history",
            "executable_lifecycle": "semantic_then_direct_retention_executor",
            "budget": {
                "events_per_day_upper": 5,
                "source_bytes_per_event_upper": 468,
                "derived_bytes_per_object_upper": 1341,
                "calibration": "representative",
            },
        }

    resolution = resolve_descriptor_retention(
        "sli.windows.ad-dc", "Security", "4624", policy=StoragePolicy()
    )
    assert resolution.rollup_role == "open"
    assert resolution.promotion["archive_requirement"] == "no_archive"
    assert resolution.policy_fingerprint == resolve_descriptor_retention(
        "sli.windows.ad-dc", "Security", "4624", policy=StoragePolicy()
    ).policy_fingerprint


def test_high_volume_promotion_is_complete_and_noise_does_not_choose_retention(
    tmp_path: Path,
    monkeypatch,
) -> None:
    incomplete = copy.deepcopy(ПОЛНАЯ_ЗАПИСЬ)
    incomplete["lifecycle"]["rollup"] = "authentication_session"
    incomplete["lifecycle"]["rollup_role"] = "open"
    incomplete["lifecycle"]["promotion"] = {
        "version": "descriptor-lifecycle-v2",
        "archive_requirement": "no_archive",
        "post_promotion_disposition": "delete_source",
        "read_representation": "derived_only",
        "high_volume": True,
    }
    result = validate_catalog_data({"entries": [incomplete]})
    assert "lifecycle_promotion_field_missing" in {item["code"] for item in result["errors"]}

    path = tmp_path / "source_neutral_catalog.json"
    noisy_legacy = copy.deepcopy(ПОЛНАЯ_ЗАПИСЬ)
    noisy_legacy["noise_class"] = "noise"
    path.write_text(json.dumps({"entries": [noisy_legacy]}), encoding="utf-8")
    monkeypatch.setattr(event_catalog, "CATALOG_PATH", path)
    event_catalog._descriptor_index_for_path.cache_clear()

    resolution = resolve_descriptor_retention(
        "sli.exchange", "message-tracking", "RECEIVE", policy=StoragePolicy()
    )
    assert resolution.promotion["archive_requirement"] == "archive_required"
    assert resolution.promotion["post_promotion_disposition"] == "preserve_source"


def test_direct_retention_executor_rejects_archive_required(каталог) -> None:
    entry = copy.deepcopy(next(
        item for item in каталог["entries"] if item["event_id"] == 4624
    ))
    promotion = entry["lifecycle"]["promotion"]
    promotion["archive_requirement"] = "archive_required"
    promotion["read_representation"] = "archived_atomic"

    result = validate_catalog_data({"entries": [entry]})

    assert "lifecycle_direct_retention_requires_no_archive" in {
        item["code"] for item in result["errors"]
    }


def test_runtime_resolver_rejects_archive_required_direct_retention(
    каталог,
) -> None:
    entry = copy.deepcopy(next(
        item for item in каталог["entries"] if item["event_id"] == 4624
    ))
    entry["lifecycle"]["promotion"].update(
        archive_requirement="archive_required",
        read_representation="archived_atomic",
    )
    with pytest.raises(ValueError, match="direct retention requires no_archive"):
        resolve_catalogue_retention(entry, policy=StoragePolicy())


def test_v2_retention_resolver_поддерживает_string_event_key(
    tmp_path: Path,
    monkeypatch,
) -> None:
    путь = tmp_path / "exchange_catalog.json"
    путь.write_text(
        json.dumps({"entries": [ПОЛНАЯ_ЗАПИСЬ]}, ensure_ascii=False),
        encoding="utf-8",
    )
    monkeypatch.setattr(event_catalog, "CATALOG_PATH", путь)
    event_catalog._descriptor_index_for_path.cache_clear()

    решение = resolve_descriptor_retention(
        "sli.exchange",
        "message-tracking",
        "RECEIVE",
        policy=StoragePolicy(),
    )

    assert решение.record.days == 7
    assert решение.warm_record.days == 365
    assert решение.record.source == "catalogue"


def test_правка_прежней_записи_снимает_освобождение(каталог, снимок) -> None:
    """Освобождение даётся записи, а не навсегда.

    Тронул прежнюю запись - изволь довести её до текущей формы. Иначе
    освобождение стало бы способом обходить правило: достаточно было бы
    дописывать в старую запись вместо создания новой.
    """
    подделка = copy.deepcopy(каталог)
    прежняя = next(item for item in подделка["entries"] if item.get("event_id") == 4624)
    del прежняя["noise_class"]
    прежняя["title"] += " (правка)"

    результат = validate_catalog_changes(подделка, снимок)

    assert not результат["valid"]
    assert результат["изменённых"] == 75
    assert результат["violations"][0]["вид"] == "изменённая"


def test_форма_каталога_без_ошибок(каталог) -> None:
    результат = validate_catalog_data(каталог)
    assert результат["valid"], результат["errors"][:5]


def test_снимок_описывает_текущие_записи(каталог, снимок) -> None:
    """Снимок не должен молча расходиться с каталогом по числу записей."""
    assert снимок["entry_count"] == 103
    assert len(каталог["entries"]) == снимок["entry_count"] + 2


def test_полнота_считается_и_не_притворяется(каталог) -> None:
    итог = catalog_completeness(каталог)
    assert итог["entry_count"] == len(каталог["entries"])
    assert итог["fully_classified"] == 105
    assert итог["classification_ratio"] == 1
    assert итог["schema_v2_ready"] == 105


def test_проверка_подключена_к_выпуску() -> None:
    """Валидатор обязан вызываться, а не просто существовать."""
    исходник = (ROOT / "scripts" / "maintenance" / "release_check.py").read_text(encoding="utf-8")

    assert "event_catalog_quality" in исходник, (
        "release_check не импортирует валидатор каталога - это ровно то "
        "состояние, в котором валидатор пролежал неиспользованным"
    )
    assert "event_catalog_check" in исходник
    assert "validate_catalog_changes" in исходник
