import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { expect as playwrightExpect } from '@playwright/test';
import { redact, waitForVisibleLoadingToFinish } from './checks.mjs';

const expect = playwrightExpect.configure({ timeout: 20_000 });
const reportPath = '/api/v2/reports/workstations.overview';
const dataPath = `${reportPath}/data`;
const requestKeys = new Set([
  'period', 'from', 'to', 'tz', 'domain', 'search', 'collection', 'source_instance_id',
  'limit', 'cursor', 'view', 'event_cursor', 'event_limit',
]);

function assertRequest(params) {
  for (const key of params.keys())
    assert.ok(requestKeys.has(key), `Workstation API received an undeclared or UI-only parameter: ${key}`);
}

async function failureBody(response) {
  // Save only the bounded error envelope. Never persist a successful response,
  // credentials, source payloads, or arbitrary nested objects.
  let body;
  try { body = await response.json(); } catch { return { content_type: response.headers()['content-type'] ?? '' }; }
  const result = {};
  for (const key of ['error', 'code', 'message', 'reason', 'detail']) {
    const value = body?.[key];
    if (typeof value === 'string') result[key] = redact(value);
    else if (key === 'error' && value && typeof value === 'object')
      for (const field of ['code', 'message', 'reason'])
        if (typeof value[field] === 'string') result[`error.${field}`] = redact(value[field]);
  }
  return result;
}

async function readResponse(page, step, path, action, accepts = () => true) {
  console.log(`menu-walk: Workstations ${step}; waiting for GET ${path}`);
  const observed = [];
  const observe = response => {
    const target = new URL(response.url());
    if (target.pathname.startsWith(reportPath) || target.pathname.startsWith('/api/v1/events/'))
      observed.push({ path: target.pathname, status: response.status(), limit: target.searchParams.get('limit') });
  };
  page.on('response', observe);
  const pending = page.waitForResponse(response => {
    const target = new URL(response.url());
    return response.request().method() === 'GET' && target.pathname === path && accepts(target.searchParams);
  }, { timeout: 20_000 }).then(response => ({ response }), error => ({ error }));
  let phase = 'UI action';
  let errorBody;
  try {
    await action();
    phase = 'API response';
    const outcome = await pending;
    if (outcome.error) throw outcome.error;
    const response = outcome.response;
    if (response.status() !== 200) {
      errorBody = await failureBody(response);
      throw new Error(`Expected HTTP 200, received ${response.status()}: ${JSON.stringify(errorBody)}`);
    }
    const params = new URL(response.url()).searchParams;
    if (path.startsWith(reportPath)) assertRequest(params);
    console.log(`menu-walk: Workstations ${step}; received HTTP 200`);
    return { body: await response.json(), params };
  } catch (cause) {
    const error = new Error(`Workstations ${step}: ${phase} failed; expected GET ${path}: ${cause.message}`, { cause });
    error.workstations = { step, phase, expected_api: path, error_body: errorBody, observed: observed.slice(-10) };
    throw error;
  } finally {
    page.off('response', observe);
  }
}

function assertWindow(params, fixture, scoped = false, list = true) {
  assert.equal(params.get('period'), 'custom');
  assert.equal(Date.parse(params.get('from')), Date.parse(fixture.from_utc), 'The exact start must survive navigation');
  assert.equal(Date.parse(params.get('to')), Date.parse(fixture.to_utc), 'The exact end must survive navigation');
  assert.equal(params.get('domain'), String(fixture.domain_id));
  if (list) assert.equal(params.get('search'), fixture.search);
  if (scoped) assert.equal(params.get('source_instance_id'), fixture.source_instance_id, 'The selected source must survive navigation');
}

// A highlighted fleet row is presentation state, not a change to its filter.
const context = params => [...params].filter(([key]) => key !== 'selected_station').sort(([left, leftValue], [right, rightValue]) =>
  left.localeCompare(right) || leftValue.localeCompare(rightValue));

async function assertReturn(page, original) {
  const expected = new URL(original);
  await expect(page).toHaveURL(current => current.pathname === expected.pathname
    && JSON.stringify(context(current.searchParams)) === JSON.stringify(context(expected.searchParams)));
}

async function assertFullPage(page) {
  assert.equal(await waitForVisibleLoadingToFinish(page, 20_000), true, 'Workstations loading must finish');
  await expect(page.locator('.sli-ds-drawer:visible, [role="dialog"]:visible')).toHaveCount(0);
  const geometry = await page.locator('main').evaluate(main => ({
    width: main.getBoundingClientRect().width,
    viewport: window.innerWidth,
    documentWidth: document.documentElement.scrollWidth,
  }));
  assert.ok(geometry.width >= geometry.viewport * .65, 'Workstations must use the main workspace width');
  assert.ok(geometry.documentWidth <= geometry.viewport + 2, 'Wide workstation content must stay inside its scroll container');
}

async function returnLink(page, original) {
  const links = page.locator('main').getByRole('link');
  const targets = await links.evaluateAll(nodes => nodes.map(node => node.href));
  const expected = new URL(original);
  const index = targets.findIndex(href => {
    const target = new URL(href);
    return target.pathname === expected.pathname
      && JSON.stringify(context(target.searchParams)) === JSON.stringify(context(expected.searchParams));
  });
  assert.ok(index >= 0, 'The permitted source must provide a return link with the exact workstation context');
  await links.nth(index).click();
}

/** Uses the existing owned PostgreSQL/app/browser; no mocked report replies. */
export async function walkWorkstations(page, { url, results, fixture }) {
  assert.ok(fixture, 'The owned PostgreSQL workstation fixture is required');
  for (const key of ['station_id', 'agent_id', 'source_instance_id', 'host_name', 'domain_id', 'from_utc', 'to_utc', 'search',
    'exact_event_id', 'event_count', 'group_summary_key', 'group_count', 'group_first_seen_utc', 'group_last_seen_utc'])
    assert.ok(fixture[key], `Missing workstation fixture ${key}`);
  assert.ok(fixture.fixture_count > 200, 'The fixture must exercise a real 200-row page');
  const directory = join(results, 'workstations');
  await mkdir(directory, { recursive: true });
  page.setDefaultTimeout(20_000);
  page.setDefaultNavigationTimeout(20_000);
  try {
    await verifyWorkstations(page, { url, directory, fixture });
  } catch (error) {
    await writeFile(join(directory, 'failure.json'), JSON.stringify({
      ...error.workstations, current_path: new URL(page.url()).pathname, message: redact(error.message),
    }, null, 2));
    await page.screenshot({ path: join(directory, 'failure.png'), fullPage: true, timeout: 5_000 }).catch(() => {});
    throw error;
  }
}

async function verifyWorkstations(page, { url, directory, fixture }) {
  const evidence = [];
  const record = async claim => {
    evidence.push(claim);
    await writeFile(join(directory, 'checks.json'), JSON.stringify(evidence, null, 2));
  };
  const screenshot = async (name, claim) => {
    await assertFullPage(page);
    await page.screenshot({ path: join(directory, name), fullPage: true });
    await record({ screenshot: name, claim });
  };
  const initial = new URL('app/workstations', url);
  initial.search = new URLSearchParams({
    period: 'custom', from: fixture.from_utc, to: fixture.to_utc,
    domain: String(fixture.domain_id), search: fixture.search, limit: '50',
  }).toString();
  console.log('menu-walk: Workstations fleet → station events → retained facts → collection → exact return');

  let overview = await readResponse(page, 'open fleet', dataPath, () => page.goto(initial.href));
  assertWindow(overview.params, fixture);
  assert.equal(overview.body.items.length, 50);
  const fleet = page.getByRole('table', { name: 'Все станции', exact: true });
  await expect(fleet.locator('tbody > tr')).toHaveCount(50);
  const size = page.getByRole('combobox', { name: 'Строк на странице', exact: true });
  assert.deepEqual(await size.locator('option').evaluateAll(nodes => nodes.map(node => node.value)), ['25', '50', '100', '200']);
  overview = await readResponse(page, 'select 200 fleet rows', dataPath, () => size.selectOption('200'),
    params => params.get('limit') === '200');
  assertWindow(overview.params, fixture);
  assert.equal(overview.body.items.length, 200, 'The API must return a real 200-row page');
  assert.equal(overview.body.has_more, true);
  await expect(fleet.locator('tbody > tr')).toHaveCount(200);
  const station = overview.body.items.find(row => row.station_id === fixture.station_id);
  assert.ok(station, 'The current registered station must be visible in the real fleet reply');
  assert.equal(station.source_instance_id, fixture.source_instance_id);
  await screenshot('01-fleet.png', '200 current registered workstations, selected period and search; real API page size 200.');

  const scoped = new URL(page.url());
  scoped.searchParams.set('source_instance_id', fixture.source_instance_id);
  overview = await readResponse(page, 'open selected source', dataPath, () => page.goto(scoped.href));
  assertWindow(overview.params, fixture, true);
  assert.equal(overview.body.items.length, 1, 'An exact source filter must isolate the current binding');
  await expect(fleet.locator('tbody > tr')).toHaveCount(1);
  const fleetUrl = page.url();
  const detailPath = `${reportPath}/rows/${encodeURIComponent(fixture.station_id)}/detail`;
  const detail = await readResponse(page, 'open station', detailPath,
    () => fleet.getByRole('link', { name: fixture.host_name, exact: true }).click());
  assertWindow(detail.params, fixture, true, false);
  assert.equal(detail.body.detail?.station?.source_instance_id, fixture.source_instance_id);
  await verifyStation(page, { detail, detailPath, fixture, fleetUrl, record, screenshot });
}

async function verifyStation(page, { detail, detailPath, fixture, fleetUrl, record, screenshot }) {
  const events = detail.body.detail?.events?.items ?? [];
  assert.ok(events.length, 'The workstation must read retained rows from the canonical journal');
  assert.equal(events.reduce((total, row) => total + row.event_count, 0), fixture.event_count,
    'The selected source must include only its retained observations, excluding another source with the same hostname');
  const table = page.getByRole('table', { name: 'События станции', exact: true });
  await expect(table.locator('tbody > tr')).toHaveCount(events.length);
  const eventsUrl = page.url();
  await screenshot('02-station-events.png', 'Full-page station events retain native event/group counts and the exact selected source and period.');

  const groupIndex = events.findIndex(row => row.summary_key === fixture.group_summary_key);
  assert.ok(groupIndex >= 0, 'The retained journal group must be present without inventing source events');
  const group = events[groupIndex];
  assert.equal(group.event_count, fixture.group_count);
  assert.equal(Date.parse(group.first_seen_utc), Date.parse(fixture.group_first_seen_utc));
  assert.equal(Date.parse(group.last_seen_utc), Date.parse(fixture.group_last_seen_utc));
  assert.equal(group.journal_evidence_available, false);
  const countColumn = await table.getByRole('columnheader', { name: 'Наблюдений', exact: true })
    .evaluate(header => header.cellIndex);
  const groupRow = table.locator('tbody > tr').nth(groupIndex);
  await expect(groupRow.locator(':scope > td').nth(countColumn)).toHaveText(String(fixture.group_count));
  await groupRow.click();
  await expect(page.getByText('Сохранённая группа событий', { exact: true })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Исходное событие', exact: true })).toHaveCount(0);
  await assertFullPage(page);
  await record({ claim: 'Retained group facts show their actual count and interval; no individual-source link is invented.' });
  await page.getByRole('button', { name: 'К событиям', exact: true }).click();
  await expect(table).toBeVisible();
  await assertReturn(page, eventsUrl);

  const exactIndex = events.findIndex(row => String(row.id) === String(fixture.exact_event_id));
  assert.ok(exactIndex >= 0, 'The fixture exact event must be returned by the canonical journal');
  const exact = events[exactIndex];
  await table.locator('tbody > tr').nth(exactIndex).click();
  const source = page.getByRole('link', { name: 'Исходное событие', exact: true });
  if (exact.journal_evidence_available === true) {
    await expect(source).toBeVisible();
    const factsUrl = page.url();
    const original = await readResponse(page, 'open permitted original event', `/api/v1/events/${fixture.exact_event_id}`,
      () => source.click());
    assert.equal(String(original.body.item?.event_db_id), String(fixture.exact_event_id));
    await assertFullPage(page);
    await readResponse(page, 'return from original event', detailPath, () => returnLink(page, factsUrl));
    await assertReturn(page, factsUrl);
    await record({ claim: 'The server-permitted exact event opens through its real source API and returns with all workstation filters intact.' });
  } else {
    await expect(source).toHaveCount(0);
    await record({ claim: 'The source action remains absent when the canonical journal does not grant exact evidence.' });
  }
  await page.getByRole('button', { name: 'К событиям', exact: true }).click();
  await expect(table).toBeVisible();
  await assertReturn(page, eventsUrl);

  const collectionTab = page.getByRole('tab', { name: 'Сбор данных', exact: true });
  await collectionTab.click();
  await expect(collectionTab).toHaveAttribute('aria-selected', 'true');
  const station = detail.body.detail.station;
  assert.equal(station.profile.state, 'supported');
  assert.ok(station.profile.event_ids.length > 0);
  assert.equal(station.profile.event_ids.some(code => [4688, 4689, 6416].includes(code)), false,
    'The current accepted profile must not advertise unadmitted process or USB events');
  const profile = page.getByRole('table', { name: 'События профиля', exact: true });
  await expect(profile.locator('tbody > tr')).toHaveCount(station.profile.event_ids.length);
  const collection = page.locator('.sli-workstations__collection');
  await expect(collection.getByText(fixture.source_instance_id, { exact: true })).toBeVisible();
  for (const [label, value] of [
    ['Назначенная версия политики', station.policy_revision],
    ['Версия, подтверждённая агентом', station.applied_policy_revision],
  ]) await expect(collection.getByText(label, { exact: true }).locator('..').locator('dd')).toHaveText(String(value));
  await screenshot('03-collection.png', 'Current workstation collection health is separate from retained event facts.');
  await page.getByRole('link', { name: 'К списку станций', exact: true }).click();
  await expect(page.getByRole('table', { name: 'Все станции', exact: true })).toBeVisible();
  await assertReturn(page, fleetUrl);
  await expect(page.getByRole('combobox', { name: 'Строк на странице', exact: true })).toHaveValue('200');
  await record({ claim: 'Returning from Collection restores the exact fleet period, selected source, search and page size.' });
}
