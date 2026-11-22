import { expect, test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import type { ReportColumnDto, ReportDefinitionDto, ReportResultDto } from '../../src/api/report-v2-types';

// Promote a screen only after all checks pass. Keep failures visible in the
// report while the corresponding screen is being brought up to the standard.
const screens = [
  { key: 'security.problems', enforced: false },
  { key: 'ad.users.v2', enforced: true },
  { key: 'ad.computers.v6', enforced: true },
  { key: 'ad.gpo.v2', enforced: true },
  { key: 'ad.infrastructure', enforced: true },
  { key: 'events.journal', enforced: false },
  { key: 'security.events.chains', enforced: true },
] as const;

test.use({
  viewport: { width: 1440, height: 900 },
  // Optional offline local browser; CI uses Playwright's installed Chromium.
  launchOptions: { executablePath: process.env.SLI_TEST_CHROMIUM_EXECUTABLE_PATH },
});

const readJson = (path: string) => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'));
const catalog: ReportDefinitionDto[] = readJson('../../../server-dotnet/src/Sli.Server/Reporting/V2/report-definitions.json');
const ad: Record<string, { declaration: ReportDefinitionDto }> = readJson('../../../server-dotnet/src/Sli.Server/Ad/report-definitions.json');
const gpo: { declaration: ReportDefinitionDto } = readJson('../../../server-dotnet/src/Sli.Server/Gpo/declaration.json');
const navigation = readJson('../../../config/navigation_v3.json');
const observed = '2026-11-10T12:00:00Z';
const definitions = new Map(screens.map(({ key }) => {
  // Literal AD endpoints take precedence over the generic report route.
  const raw = key === 'ad.gpo.v2' ? gpo.declaration : ad[key]?.declaration ?? catalog.find(item => item.key === key);
  if (!raw) throw new Error(`Missing .NET declaration: ${key}`);
  const definition = structuredClone(raw);
  definition.default_domain_id = 1;
  definition.default_domain_state = 'available';
  definition.filter_options = Object.fromEntries(definition.params.filter(param => param.options_from || param.kind === 'domain')
    .map(param => [param.options_from ?? param.key, [{ value: '1', label: 'example.test' }]]));
  return [key, definition] as const;
}));

function rowFor(columns: ReportColumnDto[], index: number): Record<string, unknown> {
  const name = `Объект ${index + 1}`;
  const row: Record<string, unknown> = {};
  for (const column of columns) {
    const value = column.kind === 'date' || column.kind === 'datetime' ? observed
      : column.kind === 'number' ? index + 1 : column.kind === 'boolean' ? true
      : column.kind === 'list' ? [name] : column.kind === 'state' ? Object.keys(column.labels ?? {})[0] ?? 'active' : name;
    const parts = (column.path ?? column.key).split('.');
    let target = row;
    for (const part of parts.slice(0, -1)) target = (target[part] ??= {}) as Record<string, unknown>;
    target[parts.at(-1)!] = value;
  }
  // Realistic fields used by custom cells and the default AD check lists.
  return { ...row, id: index + 1, entity_id: `object-${index + 1}`, row_id: `row-${index + 1}`, event_db_id: index + 1,
    key: `check-${index + 1}`, title: 'Проверьте настройки учётной записи', title_text: 'Изменены настройки учётной записи',
    display_name: name, sam: name, domain_id: 1, domain_name: 'example.test',
    sid: `S-1-5-21-100000001-200000002-300000003-${1000 + index}`, ip: '192.0.2.10',
    status: 'new', severity: 'high', severity_text: 'Высокая', status_text: 'Требует решения',
    total: 1, new_count: 1, remaining_objects: 0, last_seen_utc: observed,
    objects: [{ name, domain_name: 'example.test', entity_id: `object-${index + 1}`, computer_type: 'domain_controller' }],
    evidence: [], status_history: [], occurrence_count: 1, repeat_count: 1,
  };
}

function resultFor(definition: ReportDefinitionDto, count = 60): ReportResultDto {
  const items = Array.from({ length: count }, (_, index) => ({ ...rowFor(definition.columns, index),
    ...(definition.key === 'security.problems' ? { allowed_statuses: ['new', 'active', 'false_positive', 'closed'] } : {}),
    ...(definition.key === 'ad.computers.v6' && index % 2 === 0
      ? { status: 'checked', status_text: 'Проверено', total: 2, new_count: 0 } : {}),
    ...(definition.key === 'ad.infrastructure' ? { entity_type: 'domain_controller', entity_name: `dc-${index + 1}.example.test`,
      label: 'DNS', actual_value: 'passed', expected_condition: 'Пройдено', qualification: 'passed', observed_at_utc: observed } : {}),
  }));
  return {
    contract_id: 'sli.report-result.v2', report_key: definition.key, state: 'partial',
    state_details: { reason: 'freshness_exceeded', source: 'dc01.example.test', stale_since_utc: observed,
      source_issues: [{ source: 'dc01.example.test', reason: 'freshness_exceeded', since_utc: observed }] },
    items, has_more: false, next_cursor: null, filtered_count: count,
    domains: [{ id: 1, display_name: 'example.test', freshness: { observed_at_utc: observed } }],
    coverage: { state: 'partial', population: count, affected_objects: count, not_evaluated_count: 0,
      ...(definition.key === 'ad.gpo.v2' ? { observed_at_utc: observed } : {}),
      domains: [{ domain_id: 1, domain_name: 'example.test', observed_at_utc: observed, state: 'partial' }] },
    metrics: definition.key === 'ad.gpo.v2' ? ['attention', 'unverified', 'assignment', 'all', 'linked', 'unlinked'].map(view => ({
      key: view, label: view, value: ['attention', 'unlinked'].includes(view) ? 0 : count, filter: { view },
    })) : [], series: {}, filter_options: definition.filter_options, limitations: [], window: {},
    collections: Object.fromEntries(definition.views.filter(view => view.source && view.source !== 'items')
      .map(view => [view.source!, Array.from({ length: count }, (_, index) => rowFor(view.columns ?? definition.columns, index))])),
  };
}

async function installStandardFixtures(page: Page, count = 60) {
  const unexpected: string[] = [];
  const servedData: string[] = [];
  const decisions: unknown[] = [];
  let firstProblemStatus = 'new';
  await page.addInitScript(() => {
    localStorage.setItem('sli.locale', 'ru');
    localStorage.setItem('sli.theme', 'light');
  });
  await page.route(url => url.pathname.startsWith('/api/'), async route => {
    const { pathname, searchParams } = new URL(route.request().url());
    let body: unknown;
    let status = 200;
    if (pathname === '/api/v1/ui/bootstrap') body = { api_version: 'v1', effective_role: 'admin',
      principal: { username: 'synthetic.operator', role: 'admin' }, capabilities: ['operations.view', 'investigations.manage'], navigation: [] };
    else if (pathname === '/api/v1/access/effective') body = { subject: { type: 'user', id: 1, username: 'synthetic.operator' },
      platform_owner: false, capabilities: ['operations.view', 'problem.view', 'investigations.manage'],
      reports: [...screens.map(({ key }) => ({ report_key: key, allowed: true })), { report_key: 'ad.computer-logons', allowed: true }] };
    else if (pathname === '/api/v2/reports') body = { contract_id: 'sli.report-catalog.v2', navigation, items: [] };
    else if (pathname === '/api/v1/overview') body = { collection_freshness: { state: 'partial' } };
    else if (pathname === '/api/v1/domains') body = { items: [{ id: 1, display_name: 'example.test',
      freshness: { snapshot_state: 'partial', observed_at_utc: observed } }] };
    else if (pathname === '/api/findings/risk-responsibles' && route.request().method() === 'GET') {
      body = { items: [] };
    }
    else if (pathname === '/api/findings/queue-decisions' && route.request().method() === 'POST') {
      const decision = route.request().postDataJSON();
      decisions.push(decision);
      firstProblemStatus = decision.state;
      body = { status: 'ok', changed: 1 };
    }
    else if (pathname === '/api/v2/reports/security.problems/rows/1/detail' && route.request().method() === 'GET') {
      body = { ...resultFor(definitions.get('security.problems')!, 0), items: [{
        event_id: 4625, event_db_id: 1, evidence_id: 1, time_created_utc: observed,
      }] };
    }
    else if (pathname === '/api/v2/reports/security.problems/password-coverage' && route.request().method() === 'GET') {
      body = {
        contract_id: 'sli.report-result.v2', report_key: 'security.problems', state: 'partial',
        items: [], has_more: false, next_cursor: null, filtered_count: null,
        coverage: { password_detection: { availability: 'unavailable', as_of: null, rows: [], has_more: false } },
        limitations: [{ code: 'password_coverage_incomplete', text: 'Password detection coverage is incomplete.' }],
        metrics: [], series: {}, filter_options: {}, window: {},
      } satisfies ReportResultDto;
    }
    else {
      const match = pathname.match(/^\/api\/v2\/reports\/([^/]+)(\/data)?$/);
      const definition = match && definitions.get(decodeURIComponent(match[1]) as typeof screens[number]['key']);
      if (definition) {
        if (match![2]) {
          const result = resultFor(definition, count);
          if (definition.key === 'security.problems') {
            result.items[0].status = firstProblemStatus;
            if (searchParams.has('id')) {
              result.items = result.items.filter(item => String(item.id) === searchParams.get('id'));
              result.filtered_count = result.items.length;
            }
          }
          body = result;
          servedData.push(definition.key);
        } else body = definition;
      } else {
        unexpected.push(`${route.request().method()} ${pathname}`);
        status = 501; body = { error: 'standard_unmocked_request' };
      }
    }
    await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  });
  return { unexpected, servedData, decisions };
}

async function measureStandard(page: Page) {
  return page.locator('main').evaluate(main => {
    const visible = (element: Element) => {
      if (!element.checkVisibility({ checkVisibilityCSS: true, checkOpacity: true })) return false;
      // Closed details may retain layout boxes for their unpainted children.
      for (let parent = element.parentElement; parent; parent = parent.parentElement) {
        if (parent.matches('details:not([open])') && !parent.querySelector(':scope > summary')?.contains(element)) return false;
      }
      return element.getBoundingClientRect().height > 0;
    };
    const table = [...main.querySelectorAll('table, .sli-ds-review-list[data-compact]')].find(visible);
    const top = table?.getBoundingClientRect().top ?? null;
    let words = 0;
    const text: string[] = [];
    const walker = document.createTreeWalker(main, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const parent = walker.currentNode.parentElement;
      if (!parent || !visible(parent)) continue;
      const value = walker.currentNode.textContent?.trim() ?? '';
      text.push(value);
      if (top !== null && parent.getBoundingClientRect().bottom <= top) words += value.split(/\s+/).filter(Boolean).length;
    }
    const rows = table ? [...table.querySelectorAll('tbody tr, .sli-ds-review-list__item')].filter(visible) : [];
    const above = (selector: string) => [...main.querySelectorAll(selector)].filter(element =>
      visible(element) && (top === null || element.getBoundingClientRect().top < top)).length;
    const visibleText = text.join(' ').replace(/\s+/g, ' ').toLowerCase();
    const forbidden = ['не подтвержд', 'не доказ', 'полнот', 'не означает', 'evidence', 'когорт', 'нет данных', 'не оценено',
      'not confirmed', 'not proven', 'completeness', 'does not mean', 'cohort', 'no data', 'not evaluated'];
    return {
      rowHeight: rows[0] ? Math.round(rows[0].getBoundingClientRect().height) : null,
      rowsVisible: rows.filter(row => { const rect = row.getBoundingClientRect(); return rect.bottom <= innerHeight && rect.top >= 0; }).length,
      tableTop: top === null ? null : Math.round(top), wordsAboveTable: top === null ? null : words,
      columns: table ? [...table.querySelectorAll('thead th, .sli-ds-review-list__heading > span')].filter(visible).length : 0,
      bannersAboveTable: above('.sli-ds-state--banner'), calloutsAboveTable: above('.sli-ds-callout'), paragraphsAboveTable: above('p'),
      forbiddenText: forbidden.filter(word => visibleText.includes(word)),
      horizontalOverflow: [document.documentElement, document.body, document.getElementById('root')].some(element =>
        element && element.scrollWidth > element.clientWidth),
    };
  });
}

function standardViolations(m: Awaited<ReturnType<typeof measureStandard>>, minimumRows = 14) {
  const failures: string[] = [];
  if (m.rowsVisible < minimumRows) failures.push(`rowsVisible: ${m.rowsVisible} < ${minimumRows}`);
  if (m.rowHeight === null || m.rowHeight > 30) failures.push(`rowHeight: ${m.rowHeight} (max 30)`);
  if (m.wordsAboveTable === null || m.wordsAboveTable > 30) failures.push(`wordsAboveTable: ${m.wordsAboveTable} (max 30)`);
  if (m.tableTop === null || m.tableTop > 300) failures.push(`tableTop: ${m.tableTop} (max 300)`);
  if (m.columns === 0 || m.columns > 7) failures.push(`columns: ${m.columns} (1–7)`);
  for (const key of ['bannersAboveTable', 'calloutsAboveTable', 'paragraphsAboveTable'] as const) {
    if (m[key]) failures.push(`${key}: ${m[key]}`);
  }
  if (m.forbiddenText.length) failures.push(`forbiddenText: ${m.forbiddenText.join(', ')}`);
  if (m.horizontalOverflow) failures.push('horizontalOverflow');
  return failures;
}

for (const screen of screens) {
  test(`UI standard: ${screen.key}`, async ({ page }, testInfo) => {
    const { unexpected, servedData, decisions } = await installStandardFixtures(page);
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(`/app/report/${screen.key}`);
    const definition = definitions.get(screen.key)!;
    const title = screen.key === 'ad.infrastructure' ? 'Состояние AD' : definition.title;
    await expect(page.locator('main').getByRole('heading', { level: 1 })).toHaveText(title, { timeout: 30_000 });
    // AD checks have hidden object-preview tables inside each closed row.
    const rows = definition.views[0]?.key === 'checks' ? '.sli-ds-review-list__item' : 'tbody tr:not([data-group])';
    await expect(page.locator('main').locator(rows)).toHaveCount(60);
    await page.evaluate(async () => {
      await document.fonts.ready;
      await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
    });
    const measurements = await measureStandard(page);
    const violations = standardViolations(measurements);
    const report = { screen: screen.key, enforced: screen.enforced, ...measurements, violations };
    console.log(JSON.stringify(report));
    await testInfo.attach('standard.json', { body: Buffer.from(JSON.stringify(report, null, 2)), contentType: 'application/json' });
    const screenshot = testInfo.outputPath('screen.png');
    await page.screenshot({ path: screenshot });
    await testInfo.attach('screen.png', { path: screenshot, contentType: 'image/png' });
    if (screen.key === 'security.problems') {
      expect(measurements.horizontalOverflow).toBe(false);
      const scroll = page.locator('main .sli-ds-table__scroll').first();
      expect(await scroll.evaluate(box => box.scrollWidth - box.clientWidth)).toBeLessThanOrEqual(1);
      const first = page.locator('main').locator(rows).first();
      const title = 'Изменены настройки учётной записи';
      await first.getByRole('link', { name: `${title} · Объект 1`, exact: true }).click();
      const panel = page.getByRole('dialog', { name: title });
      await expect(panel).toBeInViewport({ ratio: 1 });
      await expect(panel.getByText('4625', { exact: true })).toBeVisible();
      expect(await panel.locator('.sli-ds-drawer__body').evaluate(box => box.scrollWidth - box.clientWidth)).toBeLessThanOrEqual(1);
      const panelScreenshot = testInfo.outputPath('problem-panel.png');
      await page.screenshot({ path: panelScreenshot });
      await testInfo.attach('problem-panel.png', { path: panelScreenshot, contentType: 'image/png' });
      const state = panel.getByRole('combobox', { name: 'Состояние' });
      await state.selectOption('closed');
      const decision = page.getByRole('dialog', { name: 'Изменить состояние' });
      await decision.getByLabel('Причина решения').selectOption('fixed');
      await decision.getByRole('button', { name: 'Сохранить решение' }).click();
      await expect(decision).toBeHidden();
      await expect(state).toHaveValue('closed');
      expect(decisions).toEqual([{ ids: [1], state: 'closed', classification: 'fixed' }]);
    }
    expect(unexpected, 'all API traffic must be synthetic and handled').toEqual([]);
    expect(errors, 'screen must render without errors even in monitoring mode').toEqual([]);
    expect(servedData).toContain(screen.key);
    if (screen.enforced) expect(violations, screen.key).toEqual([]);
    else testInfo.annotations.push({ type: 'ui-standard-monitor', description: violations.join('; ') || 'Ready to enforce' });
    if (screen.key === 'ad.users.v2') {
      const first = page.locator('.sli-ds-review-list__item').first();
      await expect(first.getByRole('button', { name: 'Объект 1', exact: true })).toHaveCount(0);
      await first.locator(':scope > summary').click();
      await expect(first.getByRole('button', { name: 'Объект 1', exact: true })).toBeVisible();
      await first.locator(':scope > summary').click();
      const search = page.getByRole('searchbox', { name: 'Поиск', exact: true });
      await search.fill('Объект');
      await Promise.all([
        page.waitForRequest(request => new URL(request.url()).searchParams.get('q') === 'Объект'),
        search.press('Enter'),
      ]);
      await expect(page).toHaveURL(/q=/);
    }
  });
}

test('GPO short list shows all eleven policies', async ({ page }, testInfo) => {
  const { unexpected } = await installStandardFixtures(page, 11);
  await page.goto('/app/report/ad.gpo.v2?domain=1');
  await expect(page.locator('main').getByRole('heading', { level: 1 })).toHaveText(definitions.get('ad.gpo.v2')!.title, { timeout: 30_000 });
  await expect(page.locator('main tbody tr')).toHaveCount(11);
  await page.evaluate(async () => { await document.fonts.ready; });
  const measurement = await measureStandard(page);
  expect((await page.locator('.sli-ds-field > label').filter({ hasText: 'Поиск' }).boundingBox())!.height).toBeLessThanOrEqual(30);
  console.log(JSON.stringify({ screen: 'ad.gpo.v2', shortList: true, ...measurement }));
  expect(standardViolations(measurement, 11)).toEqual([]);
  expect(new URL(page.url()).searchParams.get('domain')).toBe('1');
  expect(unexpected).toEqual([]);
  await page.screenshot({ path: testInfo.outputPath('gpo-11.png') });
});

test('computer checks: a short list fits without data commentary', async ({ page }, testInfo) => {
  const { unexpected } = await installStandardFixtures(page, 6);
  await page.goto('/app/report/ad.computers.v6');
  await expect(page.locator('main .sli-ds-review-list__item')).toHaveCount(6);
  await expect(page.locator('main').getByRole('tablist')).toHaveCount(1);
  await expect(page.locator('main').getByRole('tab')).toHaveText([
    'Требуют проверки', 'Изменения', 'Все компьютеры', 'Входы на компьютеры',
  ]);
  await page.evaluate(() => document.fonts.ready);
  const measurements = await measureStandard(page);
  console.log(JSON.stringify({ screen: 'ad.computers.v6', dataset: 'short-list', ...measurements }));
  expect(standardViolations(measurements, 6)).toEqual([]);
  expect(unexpected).toEqual([]);
  const screenshot = testInfo.outputPath('computers-after.png');
  await page.screenshot({ path: screenshot });
  await testInfo.attach('computers-after.png', { path: screenshot, contentType: 'image/png' });
});

test('measurement detects a banner and paragraph above the table', async ({ page }) => {
  await page.setContent(`<style>body { margin: 0 } table { border-collapse: collapse; width: 100% } tr { height: 28px }</style>
    <main><details><summary>Подробнее</summary><p>No data. Не оценено. Evidence.</p></details>
    <div hidden><p>Нет данных</p></div><p style="display:none">Not confirmed</p>
    <table><thead><tr><th>Объект</th></tr></thead><tbody>${'<tr><td>example.test</td></tr>'.repeat(60)}</tbody></table></main>`);
  expect(standardViolations(await measureStandard(page))).toEqual([]);
  await page.locator('table').evaluate(table => {
    table.insertAdjacentHTML('beforebegin', '<div class="sli-ds-state--banner">Источник отстаёт</div><p>Not proven</p><div class="sli-ds-callout">Проверьте источник</div>');
  });
  const measurement = await measureStandard(page);
  expect(measurement.bannersAboveTable).toBe(1);
  expect(measurement.paragraphsAboveTable).toBe(1);
  expect(measurement.calloutsAboveTable).toBe(1);
  expect(measurement.forbiddenText).toEqual(['not proven']);
  expect(standardViolations(measurement)).toEqual(expect.arrayContaining([
    'bannersAboveTable: 1', 'paragraphsAboveTable: 1', 'calloutsAboveTable: 1', 'forbiddenText: not proven',
  ]));
});
