"""Separate settings declarations cannot change attested package manifests."""
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from server.sli import plugin_validation as contracts

PLUGIN_IDS = (
    "sli.ad", "sli.gpo", "sli.workstations", "sli.file-audit",
    "sli.remote-access", "sli.sigma",
)
ROOT = Path(__file__).resolve().parents[2]


def package_manifest(plugin_id="sli.ad"):
    return json.loads((ROOT / f"config/plugin_packages/v3/{plugin_id}.json").read_text("utf-8"))


def settings_metadata(plugin_id="sli.ad"):
    return json.loads((ROOT / f"config/plugin_settings_schema/{plugin_id}.settings.json").read_text("utf-8"))


@pytest.mark.parametrize("plugin_id", PLUGIN_IDS)
def test_bundled_metadata_is_separate_and_manifest_hash_is_unchanged(plugin_id):
    path = ROOT / f"config/plugin_packages/v3/{plugin_id}.json"
    original_bytes = path.read_bytes()
    value = package_manifest(plugin_id)
    metadata = settings_metadata(plugin_id)
    assert not {"name", "settings", "rules", "permissions"} & value.keys()
    assert "migration_directory" not in value["data"]
    assert {"name", "settings", "rules", "permissions"} <= metadata.keys()
    assert metadata["migration_directory"] == "config/postgres_migrations"
    before = deepcopy(value)
    before_metadata = deepcopy(metadata)
    original_hash = contracts.digest(value)
    assert contracts.validate_package_manifest(value, metadata=metadata) is value
    loaded = contracts.load_package_manifest(plugin_id)
    assert loaded == value == before
    assert contracts.digest(loaded) == original_hash
    assert path.read_bytes() == original_bytes
    assert contracts.load_package_settings_schema(plugin_id) == metadata == before_metadata


@pytest.mark.parametrize("field", ["name", "settings", "rules", "permissions"])
def test_package_metadata_cannot_be_omitted(field):
    value = settings_metadata()
    value.pop(field, None)
    with pytest.raises(ValueError, match="^manifest_package_metadata_required$"):
        contracts.validate_package_settings_schema(value)


@pytest.mark.parametrize("key,low,default,high", [
    ("ad.snapshot_history_days", 7, 365, 3650),
    ("ad.password_max_age_days", 1, 365, 3650),
    ("ad.inactivity_days", 1, 90, 3650),
    ("windows_auth.distributed_window_hours", 1, 24, 744),
    ("windows_auth.distributed_min_accounts", 1, 10, 744),
    ("windows_auth.distributed_min_sources", 1, 5, 744),
    ("windows_auth.distributed_max_failures_per_account", 1, 3, 744),
])
def test_ad_setting_schema_accepts_only_current_policy_bounds(key, low, default, high):
    value = settings_metadata()
    setting = value["settings"]["properties"][key]
    assert setting["default"] == default
    for accepted in (low, default, high):
        setting["default"] = accepted
        contracts.validate_package_settings_schema(value)
    for rejected in (low - 1, high + 1, True, str(default)):
        setting["default"] = rejected
        with pytest.raises(ValueError, match="^manifest_shape_invalid$"):
            contracts.validate_package_settings_schema(value)


@pytest.mark.parametrize("edit", [
    lambda m: m.update(name="plugins.unknown.name"),
    lambda m: m.update(name={"ru": "invalid inline text"}),
    lambda m: m["settings"]["properties"]["ad.inactivity_days"].update(**{"x-label": "plugins.unknown.label"}),
    lambda m: m["settings"]["properties"]["ad.inactivity_days"].update(**{"x-help": "plugins.unknown.help"}),
    lambda m: m["settings"]["properties"]["ad.inactivity_days"].update(**{"x-group": "other"}),
    lambda m: m["settings"]["properties"]["ad.inactivity_days"].update(**{"x-secret": "false"}),
    lambda m: m["settings"]["properties"]["ad.inactivity_days"].update(minimum=4000),
    lambda m: m["settings"]["properties"]["ad.inactivity_days"].update(executable="anything"),
    lambda m: m["settings"].update(required=["unknown.setting"]),
    lambda m: m["rules"].append(deepcopy(m["rules"][0])),
    lambda m: m["rules"][0].update(settings=["unknown.setting"]),
    lambda m: m["rules"][0].update(core_settings=["unknown.setting"]),
    lambda m: m["permissions"].append(m["permissions"][0]),
    lambda m: m.update(migration_directory="../outside"),
])
def test_invalid_package_declarations_are_rejected(edit):
    value = settings_metadata()
    edit(value)
    with pytest.raises(ValueError):
        contracts.validate_package_settings_schema(value)


@pytest.mark.parametrize("key", [
    "command", "argv", "entrypoint", "import_path", "javascript", "html",
    "sql", "dsn", "password", "secret", "COMMAND",
])
def test_executable_or_sensitive_fields_are_rejected_at_any_depth(key):
    value = settings_metadata()
    value["settings"]["properties"]["ad.service_account_exceptions"]["default"] = [{key: "synthetic"}]
    with pytest.raises(ValueError, match="^executable_or_sensitive_manifest_key:"):
        contracts.validate_package_settings_schema(value)


def test_settings_schema_rejects_unknown_values_and_preserves_shared_core_ownership():
    settings = settings_metadata()["settings"]
    with pytest.raises(ValueError, match="^manifest_shape_invalid$"):
        contracts.validate_shape({"unknown.setting": 1}, settings, settings)
    file_audit = settings_metadata("sli.file-audit")
    assert file_audit["settings"]["x-core-settings"] == ["security.working_time"]
    assert "security.working_time" not in file_audit["settings"]["properties"]
    contracts.validate_package_settings_schema(file_audit)


def test_workstation_retention_default_and_bounds():
    value = settings_metadata("sli.workstations")
    setting = value["settings"]["properties"]["workstations.evidence_retention_days"]
    assert setting["default"] == 90
    for accepted in (1, 3650):
        setting["default"] = accepted
        contracts.validate_package_settings_schema(value)
    setting["default"] = 3651
    with pytest.raises(ValueError, match="^manifest_shape_invalid$"):
        contracts.validate_package_settings_schema(value)


def test_json_schema_composition_keeps_sibling_constraints():
    node = {"type": "integer", "minimum": 5, "oneOf": [{"type": "integer"}, {"type": "string"}]}
    with pytest.raises(ValueError, match="^manifest_shape_invalid$"):
        contracts.validate_shape(3, node, node)


def test_core_setting_references_cannot_redeclare_plugin_owned_values():
    value = settings_metadata()
    value["settings"]["x-core-settings"] = ["ad.inactivity_days"]
    with pytest.raises(ValueError, match="^manifest_setting_owner_conflict$"):
        contracts.validate_package_settings_schema(value)


def test_both_legacy_and_attributed_service_exceptions_remain_representable():
    value = settings_metadata()
    value["settings"]["properties"]["ad.service_account_exceptions"]["default"] = [
        "S-1-5-21-1-2-3-1000",
        {"sid": "S-1-5-21-1-2-3-1001", "excluded_by": "test-admin", "excluded_at": "2026-01-01T00:00:00Z"},
    ]
    contracts.validate_package_settings_schema(value)


def test_logon_policy_schema_checks_nested_scope_and_weekday_bounds():
    value = settings_metadata("sli.workstations")
    policy = {"scope": {"kind": "station", "station_id": "test-station"},
              "timezone": "UTC", "weekdays": [0, 4], "start": "09:00", "end": "18:00",
              "include_cached_interactive": False}
    value["settings"]["properties"]["workstations.logon_policy"]["default"] = {"version": 1, "policies": [policy]}
    contracts.validate_package_settings_schema(value)
    policy["scope"] = {"kind": "ou", "domain_id": 1, "ou_path": "OU=Test,DC=example,DC=test"}
    contracts.validate_package_settings_schema(value)
    policy["weekdays"] = [7]
    with pytest.raises(ValueError, match="^manifest_shape_invalid$"):
        contracts.validate_package_settings_schema(value)


def test_package_metadata_loads_without_runtime_imports_from_neutral_cwd(tmp_path):
    code = '''
import importlib.abc, sys
sys.path.insert(0, sys.argv[1])
class BlockRuntime(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith('server.') and fullname not in {'server.sli', 'server.sli.plugin_validation'}:
            raise AssertionError('runtime import: ' + fullname)
sys.meta_path.insert(0, BlockRuntime())
from server.sli.plugin_validation import load_package_manifest, load_package_settings_schema
for plugin_id in sys.argv[2:]:
    assert load_package_manifest(plugin_id)['plugin_id'] == plugin_id
    assert load_package_settings_schema(plugin_id)['plugin_id'] == plugin_id
'''
    result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(ROOT), *PLUGIN_IDS],
                            cwd=tmp_path, capture_output=True, text=True, timeout=20, check=False)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("plugin_id", ["../sli.ad", "sli.ad/../../other", "", "SLI.AD"])
def test_loader_rejects_non_package_paths(plugin_id):
    with pytest.raises(ValueError, match="^manifest_plugin_id_invalid$"):
        contracts.load_package_manifest(plugin_id)
    with pytest.raises(ValueError, match="^manifest_plugin_id_invalid$"):
        contracts.load_package_settings_schema(plugin_id)


@pytest.fixture
def fake_package_root(tmp_path):
    """Only JSON files and an empty migration directory; no runtime or DB."""
    paths = ["config/plugin_architecture_v3.json", "config/plugin_settings_schema_v1.json",
             "config/plugin_packages/v3/sli.ad.json",
             "config/plugin_settings_schema/sli.ad.settings.json",
             "config/i18n/server.ru.json", "config/i18n/server.en.json"]
    for relative in paths:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / relative).read_bytes())
    (tmp_path / "config/postgres_migrations").mkdir()
    return tmp_path


@pytest.mark.parametrize("language", ["ru", "en"])
@pytest.mark.parametrize("text", [None, " ", "word " * 13, 123])
@pytest.mark.parametrize("key", [
    "plugins.sli.ad.name", "plugins.sli.ad.settings.ad.inactivity_days.label",
    "plugins.sli.ad.settings.ad.inactivity_days.help", "plugins.sli.ad.rules.inactivity.name",
])
def test_settings_require_complete_short_translations(fake_package_root, language, text, key):
    path = fake_package_root / f"config/i18n/server.{language}.json"
    messages = json.loads(path.read_text("utf-8"))
    if text is None:
        messages.pop(key)
    else:
        messages[key] = text
    path.write_text(json.dumps(messages), encoding="utf-8")
    with pytest.raises(ValueError, match="^manifest_localized_text_invalid$"):
        contracts.load_package_manifest("sli.ad", root=fake_package_root)


@pytest.mark.parametrize("kind", ["manifest", "settings"])
@pytest.mark.parametrize("contents,code", [
    ('{"plugin_id":"sli.gpo"}', "manifest_plugin_id_mismatch"),
    ('{"plugin_id":"sli.ad","plugin_id":"sli.gpo"}', "manifest_duplicate_json_key"),
])
def test_both_loaders_reject_identity_mismatch_and_duplicate_keys(fake_package_root, kind, contents, code):
    relative = ("config/plugin_packages/v3/sli.ad.json" if kind == "manifest" else
                "config/plugin_settings_schema/sli.ad.settings.json")
    (fake_package_root / relative).write_text(contents, encoding="utf-8")
    with pytest.raises(ValueError, match="^" + code + "$"):
        contracts.load_package_manifest("sli.ad", root=fake_package_root)


@pytest.mark.parametrize("field", ["name", "settings", "rules", "permissions"])
def test_inline_metadata_is_rejected_by_published_manifest_contract(field):
    value = package_manifest()
    value[field] = settings_metadata()[field]
    with pytest.raises(ValueError, match="^manifest_shape_invalid$"):
        contracts.validate_package_manifest(value)


def test_settings_changes_do_not_change_loaded_manifest_or_its_digest(fake_package_root):
    before = contracts.load_package_manifest("sli.ad", root=fake_package_root)
    metadata = settings_metadata()
    metadata["settings"]["properties"]["ad.inactivity_days"]["default"] = 100
    path = fake_package_root / "config/plugin_settings_schema/sli.ad.settings.json"
    path.write_text(json.dumps(metadata), encoding="utf-8")
    loaded = contracts.load_package_manifest("sli.ad", root=fake_package_root)
    assert loaded == before
    assert contracts.digest(loaded) == contracts.digest(before)
    assert contracts.load_package_settings_schema("sli.ad", root=fake_package_root) == metadata


def test_explicit_metadata_must_match_manifest_plugin():
    with pytest.raises(ValueError, match="^manifest_plugin_id_mismatch$"):
        contracts.validate_package_manifest(package_manifest(), metadata=settings_metadata("sli.gpo"))


def test_manifest_version_range_is_still_checked():
    value = package_manifest()
    value["core_api"]["maximum_exclusive"] = "2.0.0"
    with pytest.raises(ValueError, match="^manifest_version_range_invalid$"):
        contracts.validate_package_manifest(value)


@pytest.mark.parametrize("kind", ["nonexistent", "other", "outside"])
def test_separate_migration_directory_is_checked_against_manifest(fake_package_root, kind):
    metadata = settings_metadata()
    if kind == "nonexistent":
        metadata["migration_directory"] = "config/missing"
    elif kind == "other":
        metadata["migration_directory"] = "config/i18n"
    else:
        metadata["migration_directory"] = "../outside"
    path = fake_package_root / "config/plugin_settings_schema/sli.ad.settings.json"
    path.write_text(json.dumps(metadata), encoding="utf-8")
    value = package_manifest()
    value["data"]["migrations"] = deepcopy(package_manifest("sli.workstations")["data"]["migrations"][:1])
    assert value["data"]["migrations"]
    with pytest.raises(ValueError):
        contracts.validate_package_manifest(value, metadata=metadata, root=fake_package_root)


@pytest.mark.parametrize("failure", ["bounds", "missing", "identity", "translation"])
def test_invalid_separate_settings_stop_registration_before_import(fake_package_root, monkeypatch, failure):
    from server.sli.plugins import registry

    path = fake_package_root / "config/plugin_settings_schema/sli.ad.settings.json"
    metadata = settings_metadata()
    if failure == "bounds":
        metadata["settings"]["properties"]["ad.inactivity_days"]["default"] = 0
    elif failure == "identity":
        metadata["plugin_id"] = "sli.gpo"
    elif failure == "translation":
        metadata["name"] = "plugins.missing.name"
    path.write_text(json.dumps(metadata), encoding="utf-8")
    if failure == "missing":
        path.unlink()
    monkeypatch.setattr(registry, "ROOT", fake_package_root)
    monkeypatch.setattr(registry, "discover_plugins", lambda: (("sli.ad", registry.BUNDLED["sli.ad"]),))

    def forbidden(*args, **kwargs):
        pytest.fail("invalid settings reached executable plugin registration")

    monkeypatch.setattr(registry.importlib, "import_module", forbidden)
    registry._bundled_plugins.cache_clear()
    try:
        with pytest.raises(FileNotFoundError if failure == "missing" else ValueError):
            registry._bundled_plugins()
    finally:
        registry._bundled_plugins.cache_clear()


def test_valid_separate_settings_allow_fake_registration(fake_package_root, monkeypatch):
    from types import SimpleNamespace

    from server.sli.plugins import registry

    imported = []

    def load(entry):
        imported.append(entry)
        return SimpleNamespace(register=lambda contribution: contribution.hooks.update(health=lambda: True))

    monkeypatch.setattr(registry, "ROOT", fake_package_root)
    monkeypatch.setattr(registry, "discover_plugins", lambda: (("sli.ad", registry.BUNDLED["sli.ad"]),))
    monkeypatch.setattr(registry.importlib, "import_module", load)
    registry._bundled_plugins.cache_clear()
    try:
        assert registry._bundled_plugins()["sli.ad"].hooks["health"]() is True
        assert imported == [registry.BUNDLED["sli.ad"]]
    finally:
        registry._bundled_plugins.cache_clear()
