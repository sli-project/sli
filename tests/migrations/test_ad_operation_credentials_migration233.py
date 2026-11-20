"""Source contract: migration is append-only and never assigns AD operations."""
from pathlib import Path

SQL = (Path(__file__).resolve().parents[2] / 'config/postgres_migrations/233_ad_operation_credentials.sql').read_text()


def test_explicit_scoped_permission_has_no_owner_bypass_or_automatic_assignments():
    assert 'create table public.sli_ad_operations_grants' in SQL
    assert "where actor=p_actor and enabled is true" in SQL
    assert 'for share' in SQL
    assert 'insert into public.sli_ad_operations_grants' not in SQL
    assert 'platform_owner' not in SQL
    assert 'security definer set search_path=pg_catalog,pg_temp' in SQL
    assert 'revoke all on function public.sli_ad_operations_scopes(text) from public' in SQL


def test_registry_is_ciphertext_only_and_runtime_cannot_edit_grants_or_installation():
    assert 'envelope jsonb not null' in SQL
    assert 'password text' not in SQL and 'master_key' not in SQL
    assert 'grant select on public.sli_ad_credential_installation to adlog_user' in SQL
    assert 'grant select,insert,delete on public.sli_ad_operation_credentials to adlog_user' in SQL
    assert 'grant update on public.sli_ad_operations_grants' not in SQL
    assert "version=232 and name='file_ransom'" in SQL
    assert "values(233,'ad_operation_credentials')" in SQL
