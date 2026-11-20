"""Offline integrity of the N02 lock, captured from authenticated APT indexes.

This data-only test needs no runtime settings, database, network or conftest.
Cryptographic checks and real Debian APT receipts live in the N02 evidence set.
"""

from datetime import datetime
import hashlib
import json
from pathlib import Path
import re


PINS = Path(__file__).resolve().parents[2] / "deploy/linux/native_pins.json"
EXPECTED = {
    "postgresql-18": "18.6-1.pgdg13+2",
    "postgresql-client-18": "18.6-1.pgdg13+2",
    "postgresql-common": "293.pgdg13+1",
    "postgresql-client-common": "293.pgdg13+1",
    "libpq5": "18.6-1.pgdg13+2",
    "clickhouse-common-static": "26.8.35.10",
    "clickhouse-server": "26.8.35.10",
    "clickhouse-client": "26.8.35.10",
}
# Receipt digest over name/version/architecture/SHA256/size of all 88 checked debs.
PACKAGES_SHA256 = "c7ef4c2d796d47c1d52cbf3ab2831d8b9072ee4702793befc45b2afe86e863b6"


def load():
    assert PINS.is_file(), "N02 authenticated package lock is missing"
    return json.loads(PINS.read_text(encoding="utf-8"))


def test_target_and_exact_database_versions():
    pins = load()
    assert pins["schema_version"] == 1
    assert pins["target"] == {"os": "debian", "version": "13", "codename": "trixie", "architecture": "amd64"}
    packages = {p["name"]: p for p in pins["packages"]}
    assert pins["roots"] == sorted(EXPECTED)
    assert {n: packages[n]["version"] for n in pins["roots"]} == EXPECTED
    assert "postgresql" not in packages and "postgresql-client" not in packages


def test_all_deb_hashes_match_the_verified_receipt():
    packages = load()["packages"]
    assert len(packages) == 88
    assert [p["name"] for p in packages] == sorted({p["name"] for p in packages})
    values = [[p[k] for k in ("name", "version", "architecture", "sha256", "size")] for p in packages]
    assert hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest() == PACKAGES_SHA256


def test_package_urls_and_index_provenance():
    pins = load()
    repositories = {r["id"]: r for r in pins["repositories"]}
    assert len(repositories) == 5
    for package in pins["packages"]:
        assert package["architecture"] in {"amd64", "all"}
        assert re.fullmatch(r"[0-9a-f]{64}", package["sha256"])
        assert type(package["size"]) is int and package["size"] > 0
        assert package["filename"].startswith("pool/") and package["filename"].endswith(".deb")
        assert ".." not in package["filename"].split("/")
        assert package["source_indexes"]
        sources = [repositories[r] for r in package["source_indexes"]]
        assert package["url"] in {r["base_url"] + "/" + package["filename"] for r in sources}
        assert all(r["suite"] in {"trixie", "trixie-updates", "trixie-security", "trixie-pgdg", "lts"} for r in sources)


def test_signature_chain_and_scoped_public_keys():
    pins = load()
    captured = datetime.fromisoformat(pins["captured_utc"])
    repositories = {r["id"]: r for r in pins["repositories"]}
    assert repositories["pgdg"]["primary_fingerprints"] == ["B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8"]
    assert repositories["clickhouse"]["primary_fingerprints"] == ["3A9EA1193A97B548BE1457D48919F6BD2B48D754"]
    assert repositories["clickhouse"]["signing_fingerprints"] == ["885E2BDCF96B0B45ABF058453E4AD4719DDE9A38"]
    for repo in repositories.values():
        assert repo["signature_verified"] is True
        assert repo["primary_fingerprints"] and repo["signing_fingerprints"]
        assert all(re.fullmatch(r"[0-9A-F]{40}", f) for f in repo["primary_fingerprints"] + repo["signing_fingerprints"])
        for field in ("key_sha256", "inrelease_sha256", "release_sha256", "packages_sha256"):
            assert re.fullmatch(r"[0-9a-f]{64}", repo[field])
        assert datetime.fromisoformat(repo["release_date_utc"]) <= captured
        if repo["valid_until_utc"] is not None:
            assert captured < datetime.fromisoformat(repo["valid_until_utc"])
        if repo["id"] in {"pgdg", "clickhouse"}:
            assert repo["detached_signature_verified"] is True
            assert re.fullmatch(r"[0-9a-f]{64}", repo["release_gpg_sha256"])
            assert re.fullmatch(r"[0-9a-f]{64}", repo["packages_gz_sha256"])


def test_every_required_dependency_has_an_exact_provider():
    pins = load()
    packages = {p["name"]: p for p in pins["packages"]}
    edges = pins["dependency_edges"]
    assert len(edges) == 218
    for edge in edges:
        assert edge["from"] in packages and edge["to"] in packages
        assert edge["version"] == packages[edge["to"]]["version"]
    for package in packages.values():
        for field, kind in (("depends", "Depends"), ("pre_depends", "PreDepends")):
            required = [s.strip().replace("(", "").replace(")", "") for s in package[field].split(",") if s.strip()]
            resolved = [e["constraint"] for e in edges if e["from"] == package["name"] and e["type"] == kind]
            assert resolved == required, package["name"]
    reachable = set(pins["roots"])
    while True:
        expanded = reachable | {e["to"] for e in edges if e["from"] in reachable}
        if expanded == reachable:
            break
        reachable = expanded
    assert reachable == set(packages)


def test_baseline_and_required_only_install_contract():
    pins = load()
    packages = pins["packages"]
    assert sum(p["present_in_baseline"] for p in packages) == 66
    assert sum(not p["present_in_baseline"] for p in packages) == 22
    for package in packages:
        assert package["present_in_baseline"] == (package["baseline_version"] is not None)
        assert package["baseline_matches_pin"] == (package["baseline_version"] == package["version"])
    assert pins["policy"]["install_recommends"] is False
    assert pins["policy"]["install_suggests"] is False


def test_holds_do_not_freeze_debian_or_sli_updates():
    pins = load()
    policy = pins["policy"]
    assert policy["hold_packages"] == sorted(EXPECTED)
    assert policy["manual_packages"] == sorted(EXPECTED)
    assert policy["hold_debian_dependencies"] is False
    assert policy["sli_upgrade_may_unhold"] is False
    assert policy["incompatible_sli_dependency_action"] == "abort_before_unpack"
    assert policy["database_update_requires_separate_window"] is True
    assert policy["modify_vendor_deb_protected_field"] is False
    assert policy["snapshot_valid_until_required"] is True
    assert policy["snapshot_max_age_days"] == 7


def test_preferences_allow_exact_versions_before_rejecting_others():
    text = load()["policy"]["apt_preferences"]
    records = [dict(line.split(": ", 1) for line in block.splitlines()) for block in text.strip().split("\n\n")]
    for name, version in EXPECTED.items():
        matching = [r for r in records if r["Package"] == name]
        assert matching == [
            {"Package": name, "Pin": "version " + version, "Pin-Priority": "990"},
            {"Package": name, "Pin": "version *", "Pin-Priority": "-1"},
        ]
    assert {r["Pin"] for r in records if r["Package"] == "*"} == {
        "release o=apt.postgresql.org", "release o=ClickHouse",
    }
    assert all(int(r["Pin-Priority"]) in {-1, 990} for r in records)
