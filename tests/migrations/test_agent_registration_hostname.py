"""Registration display metadata must not add authority or rewrite old agents."""
from pathlib import Path


def test_hostname_migration_is_nullable_metadata_without_new_privileges():
    sql = (Path(__file__).resolve().parents[2] / 'config/postgres_migrations/281_agent_registration_hostname.sql').read_text()
    statements = '\n'.join(line for line in sql.splitlines() if not line.lstrip().startswith('--')).lower()
    assert 'add column registration_host_name text' in statements
    assert 'char_length(registration_host_name) between 1 and 253' in statements
    assert all(word not in statements for word in ('grant ', 'update ', 'create index', 'security definer', 'default '))
    assert "values(281,'agent_registration_hostname')" in statements
