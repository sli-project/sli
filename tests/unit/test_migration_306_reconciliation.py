import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
M = ROOT / 'config/postgres_migrations'


def test_306_binds_all_five_exact_273_function_bodies_and_full_journal_guards():
    source = (M / '273_password_attacks_v2.sql').read_text(encoding='utf-8')
    sql = (M / '306_password_policy_reconciliation.sql').read_text(encoding='utf-8')
    for name in ('read_default_password_window_v2', 'read_password_retained_proof_v2',
                 'password_v2_native_cost', 'password_v2_check_state', 'complete_password_producer_batch_v2'):
        match = re.search(r'create function public\.' + name + r'\s*\(.*?\bas \$\$(.*?)\$\$;', source, re.I | re.S)
        assert match and hashlib.sha256(match.group(1).encode()).hexdigest() in sql
    assert "identity_attack_rollback_v301" in sql
    assert 'ad_directory_observation' in sql and 'identity_attack_policy_denied' in sql
    rollback = (M / '306_password_policy_reconciliation.rollback.sql').read_text(encoding='utf-8')
    for guard in ('version>306', 'installed_definition', 'installed_owner', 'installed_acl', 'installed_comment'):
        assert guard in rollback and rollback.index(guard) < rollback.index('execute r.prior_definition')


def test_static_source_vectors_cover_password_and_both_policy_families():
    source = (M / '273_password_attacks_v2.sql').read_text(encoding='utf-8')
    identity = (M / '301_identity_attack_rules.sql').read_text(encoding='utf-8')
    precursor = (M / '302_attack_precursors.sql').read_text(encoding='utf-8')
    migration = (M / '306_password_policy_reconciliation.sql').read_text(encoding='utf-8')
    window = re.search(r'create function public\.read_default_password_window_v2\s*\(.*?\bas \$\$(.*?)\$\$;', source, re.I | re.S).group(1)
    assert 'event_id in (4625,4771,4776)' in window
    assert 'event_id in (4624,4625,4771,4776)' not in window
    for value in ('qw.kerberoasting', 'qw.asrep-roasting', 'qw.ad-preauth-disabled', 'qw.logon-fanout', 'qw.privileged-group-addition'):
        assert value in identity and value in migration
    for value in ('qw.ransom-precursor', 'qw.security-log-cleared', 'qw.audit-disabled', 'qw.agent-tamper', 'qw.agent-silenced', 'qw.file-ransom-fast', 'qw.mass-file-read'):
        assert value in precursor
    body = re.search(r'create or replace function public\.ensure_default_qw_policy_v262\(.*?\bas \$\$(.*?)\$\$;', precursor, re.I | re.S).group(1)
    assert hashlib.sha256(body.encode()).hexdigest() in migration
    assert "'successful_logon'" not in re.search(r'create function public\.password_v2_check_state\s*\(.*?\bas \$\$(.*?)\$\$;', source, re.I | re.S).group(1)
    assert 'identity_attack_policy_denied' in migration


def test_rollback_requires_prior_and_installed_metadata_before_restoration():
    sql = (M / '306_password_policy_reconciliation.rollback.sql').read_text(encoding='utf-8')
    before = sql.split('execute r.prior_definition', 1)[0]
    for token in ('version>306', 'identity_attack_rollback_v301', 'password_policy_306_prior_drift',
                  'installed_definition', 'installed_owner', 'installed_acl', 'installed_comment', 'to_regprocedure'):
        assert token in before
    assert 'stopped-system rollback' in sql
