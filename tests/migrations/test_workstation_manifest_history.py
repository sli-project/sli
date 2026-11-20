"""Historical attestations stay immutable; overview is an additive package delta."""

import hashlib
import json
from pathlib import Path

from server.sli.plugin_validation import validate_package_manifest


def test_overview_manifest_preserves_attested_legacy_package_exactly():
    # Taken from main e9b78e1b before overview, with post-160 migrations removed.
    # Both original SQL attestations independently pin this fixture's contents.
    historical = json.loads(Path("tests/fixtures/workstations/package-before-overview.v3.json").read_text(encoding="utf-8"))
    original = (json.dumps(historical, indent=2) + "\n").encode("utf-8")
    assert hashlib.sha256(original).hexdigest() == "776a31b27c86e1e9d0d991f3357f57eb464ffb0770f8ce729b6f2fe2035650fe"
    current = json.loads(Path("config/plugin_packages/v3/sli.workstations.json").read_text(encoding="utf-8"))
    dataset = current["datasets"].pop(0)
    assert dataset == {"dataset_id": "workstations.overview", "contract_id": "sli.report-result.v2",
                       "contract_version": "2.0.0", "reader_id": "workstations.overview", "capabilities": []}
    report = current["reports"].pop(0)
    assert report == {"report_key": "workstations.overview", "access_key": "workstations.overview",
                      "dataset_id": "workstations.overview", "definition_id": "workstations.overview",
                      "section_id": "workstations", "title_key": "workstations.overview.title",
                      "routes": ["/report/workstations.overview", "/workstations"],
                      "required_fields": ["identity_basic", "technical", "security", "privilege"],
                      "capabilities": [], "history_reader_id": "workstations.overview"}
    current["data"]["migrations"] = [entry for entry in current["data"]["migrations"] if entry["version"] < 160]
    # Every old dataset/report/route/field/job/navigation/authority entry remains.
    assert current == historical


def test_navigation_manifest_is_a_new_version_with_only_the_declared_title_delta():
    from server.sli.reporting import navigation_registry

    legacy = json.loads(Path("config/plugin_packages/v3/sli.workstations.json").read_text("utf-8"))
    current = json.loads(Path("config/plugin_packages/v3/sli.workstations.1.1.0.json").read_text("utf-8"))
    assert validate_package_manifest(current) is current
    assert current["plugin_version"] == "1.1.0"
    assert current["reports"][0]["title_key"] == "workstations.overview.nav_title"
    _, owners = navigation_registry.load_registry()
    assert owners["workstations.overview"]["title_key"] == "workstations.overview.nav_title"
    current["plugin_version"] = legacy["plugin_version"]
    current["reports"][0]["title_key"] = "workstations.overview.title"
    assert current == legacy
