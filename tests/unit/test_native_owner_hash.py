"""Owner setup and restore use the existing Argon2 parameters and hashes."""

import json
from pathlib import Path

from argon2 import extract_parameters

from deploy.linux.existing_postgres_bootstrap import create_platform_owner
from deploy.linux.sli_core.auth import PASSWORD_HASHER


def test_native_owner_hashes_are_compatible_with_legacy_credentials():
    root = Path(__file__).resolve().parents[2]
    vectors = root / "server-dotnet/tests/Sli.Server.Tests/Auth/password-phc-vectors.json"
    baseline = next(vector for vector in json.loads(vectors.read_bytes())["vectors"] if vector["name"] == "baseline")
    legacy_password, legacy_hash = baseline["password"], baseline["encoded"]
    assert PASSWORD_HASHER.verify(legacy_hash, legacy_password)
    assert not PASSWORD_HASHER.check_needs_rehash(legacy_hash)

    class Connection:
        def execute(self, statement, parameters):
            self.owner = parameters

    password = "synthetic-owner-password"
    connection = Connection()
    create_platform_owner(connection, password)
    username, native_hash, role = connection.owner
    assert (username, role) == ("platform-owner", "admin")
    assert PASSWORD_HASHER.verify(native_hash, password)
    assert extract_parameters(native_hash) == extract_parameters(legacy_hash)
