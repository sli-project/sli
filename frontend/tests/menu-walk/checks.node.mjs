import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from '@playwright/test';
import { forbiddenLabels, loadErrors, markdown, redact, waitForVisibleLoadingToFinish } from './checks.mjs';

test('menu readiness observes the visible loading state in the browser', async t => {
  const browser = await chromium.launch({ executablePath: process.env.SLI_TEST_CHROMIUM_EXECUTABLE_PATH });
  t.after(() => browser.close());
  const page = await browser.newPage();
  await t.test('waits until deferred rendering clears the visible indicator', async () => {
    await page.setContent('<main><p id="loading" aria-busy="true">Loading</p><p hidden aria-busy="true">Hidden</p></main>');
    const ready = waitForVisibleLoadingToFinish(page, 5_000);
    await page.evaluate(() => new Promise(resolve => setTimeout(resolve, 150)));
    await page.locator('#loading').evaluate(node => node.removeAttribute('aria-busy'));
    assert.equal(await ready, true);
  });
  await t.test('fails when a visible indicator never clears', async () => {
    await page.setContent('<main aria-busy="true">Loading</main>');
    assert.equal(await waitForVisibleLoadingToFinish(page, 150), false);
  });
});

test('finds prohibited visible labels, split phrases and reason/field codes', () => {
  for (const text of ['partial', 'stale', 'Данные неполные', 'Не оценено', 'Нет данных', 'Неизвестно',
    'Название недоступно', '≥0', 'snapshot', 'Полнота: не подтверждена', 'source_not_configured', 'observed_at_utc']) {
    assert.ok(forbiddenLabels(text).length, text);
  }
  assert.deepEqual(forbiddenLabels('Проверьте источник. Не отвечает DC-1 с 08:00'), []);
  assert.ok(forbiddenLabels('Причина: disconnected', ['disconnected']).includes('disconnected'));
});

test('distinguishes a load failure from a legitimate next step or client problem', () => {
  assert.deepEqual(loadErrors('Компьютеров нет. Добавьте контроллер домена.'), []);
  assert.deepEqual(loadErrors('Ошибка входа пользователя example.test'), []);
  assert.deepEqual(loadErrors('Компьютеры\nНе удалось загрузить список компьютеров\nПовторить'), ['Не удалось загрузить список компьютеров']);
  assert.deepEqual(loadErrors('Failed to fetch'), ['Failed to fetch']);
});

test('redacts a session, credential text and URL query before reporting', () => {
  const text = redact('session-secret password=secret https://example.test/api?token=secret', ['session-secret']);
  assert.ok(!text.includes('secret'));
  assert.ok(!text.includes('https://'));
});

test('table keeps loading failures separate from appearance findings', () => {
  const report = markdown([{ label: 'Пользователи', path: '/users', failures: [], labels: [{ label: 'partial', where: 'span' }] },
    { label: 'Агенты', path: '/agents', failures: ['GET /api/agents → 500'], labels: [] },
    { label: 'Компьютеры', path: '/computers', failures: [], labels: [], appearance: ['Пустая таблица без следующего шага'] }]);
  assert.match(report, /Пользователи.*загрузился.*partial \(span\)/);
  assert.match(report, /Агенты.*GET \/api\/agents → 500/);
  assert.match(report, /Компьютеры.*загрузился.*Пустая таблица/);
  const untrusted = markdown([{ label: '<script>bad</script>', path: '/x', failures: [], labels: [] }]);
  assert.ok(!untrusted.includes('<script>'));
});
