"""Complete ru/en parity contracts for shipped server and frontend dictionaries."""
import json
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[2]
ENTRY = re.compile(r'^\s*("(?:\\.|[^"\\])*")\s*:\s*("(?:\\.|[^"\\])*")\s*,?\s*$')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, f'Duplicate translation: {key}'
        result[key] = value
    return result


def dictionaries(kind, locale):
    if kind == 'server':
        return json.loads((ROOT / f'config/i18n/server.{locale}.json').read_text('utf-8'),
                          object_pairs_hook=unique_object)
    source = (ROOT / f'frontend/src/i18n/{locale}.ts').read_text('utf-8')
    pairs = []
    for line in source.splitlines():
        if line.lstrip().startswith('"'):
            match = ENTRY.fullmatch(line)
            assert match, f'Unsupported translation entry: {line[:100]}'
            pairs.append(tuple(json.loads(group) for group in match.groups()))
    assert pairs, 'Frontend dictionary was not parsed'
    return unique_object(pairs)


@pytest.mark.parametrize('kind', ['server', 'frontend'])
def test_complete_ru_en_catalog_contract(kind):
    ru, en = (dictionaries(kind, locale) for locale in ('ru', 'en'))
    assert ru.keys() == en.keys(), (sorted(ru.keys() - en.keys()), sorted(en.keys() - ru.keys()))
    for key in ru:
        for value in (ru[key], en[key]):
            assert isinstance(value, str) and value.strip(), (kind, key, 'empty translation')
        placeholders = lambda text: sorted(re.findall(r'\{\w+\}', text))
        assert placeholders(ru[key]) == placeholders(en[key]), (kind, key)


@pytest.mark.parametrize('locale', ['ru', 'en'])
def test_catalog_labels_select_locale_without_mutating_or_interpolating_source(locale):
    from server.sli.core.messages import message
    labels = {'ru': 'Событие {en}', 'en': 'Event {ru}'}
    result = message('events.catalog_title', labels, locale=locale)
    assert result['text'] == labels[locale]
    assert result['params'] == labels and 'label' not in labels
