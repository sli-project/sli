"""Owner setup and restore use the existing Argon2 parameters and hashes."""

from argon2 import extract_parameters

from deploy.linux.existing_postgres_bootstrap import create_platform_owner
from deploy.linux.sli_core.auth import PASSWORD_HASHER
from server.sli.access.auth import PASSWORD_HASHER as LEGACY_HASHER


def test_native_owner_hashes_are_compatible_with_legacy_credentials():
    password = "synthetic-owner-password"
    legacy_hash = LEGACY_HASHER.hash(password)
    assert PASSWORD_HASHER.verify(legacy_hash, password)
    assert not PASSWORD_HASHER.check_needs_rehash(legacy_hash)

    class Connection:
        def execute(self, statement, parameters):
            self.owner = parameters

    connection = Connection()
    create_platform_owner(connection, password)
    username, native_hash, role = connection.owner
    assert (username, role) == ("platform-owner", "admin")
    assert LEGACY_HASHER.verify(native_hash, password)
    assert extract_parameters(native_hash) == extract_parameters(legacy_hash)
