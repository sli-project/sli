from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_archive_worker_script_exists_and_is_safe():
    text = (ROOT / 'scripts' / 'maintenance' / 'pg_archive_worker.py').read_text(encoding='utf-8')
    assert 'ADLOG_DB_BACKEND' in text
    assert 'ADLOG_DISABLE_SCHEDULER' in text
    assert 'ADLOG_ENABLE_POSTGRES_COLLECTION' in text
    assert '--archive' in text
    assert 'import_event_jsonl_to_postgres.py' in text
    assert 'pg_archive_worker_status.json' in text


def test_archive_worker_is_internal_and_not_exposed_while_collection_is_stopped():
    text = (ROOT / 'tools' / 'adlog-tool.ps1').read_text(encoding='utf-8')
    assert 'pg-archive-worker-dc1' not in text
    assert 'pg-archive-worker-dc2' not in text
    assert 'pg-archive-worker-all' not in text
    assert 'Команды запуска сбора намеренно отсутствуют' in text


def test_release_version_updated():
    import re

    text = (ROOT / 'server' / 'sli' / 'ops' / 'version.py').read_text(encoding='utf-8')
    match = re.search(r'^PROJECT_VERSION\s*=\s*["\']([^"\']+)', text, re.MULTILINE)
    assert match, 'PROJECT_VERSION marker is missing'
    version = match.group(1)
    assert version.startswith('2026.')
    assert any(marker in version for marker in ('db0.', 'pg-stable', 'pg-product'))
    assert 'BASELINE_LABEL' in text
    assert 'PostgreSQL' in text or 'PG-' in text
