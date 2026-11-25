import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { expect as playwrightExpect } from '@playwright/test';
import { redact, waitForVisibleLoadingToFinish } from './checks.mjs';

const expect = playwrightExpect.configure({ timeout: 20_000 });
const reportPath = tab => `/api/v2/reports/file-audit.${tab}/data`;
const permissionsTitle = 'NTFS · Назначенные права';

async function readResponse(page, step, path, action, accepts = () => true) {
  console.log(`menu-walk: FileServers ${step}; waiting for GET ${path}`);
  const observed = [];
  const observe = response => {
    const target = new URL(response.url());
    if (target.pathname.startsWith('/api/v2/reports/file-audit.'))
      observed.push({ path: target.pathname, status: response.status(), limit: target.searchParams.get('limit') });
  };
  page.on('response', observe);
  // Attach the response listener before acting, but report a failed UI action
  // first. A response timeout must not hide a selector/action failure.
  const pending = page.waitForResponse(response => {
      const target = new URL(response.url());
      return target.pathname === path && accepts(target.searchParams);
    }, { timeout: 20_000 }).then(response => ({ response }), error => ({ error }));
  let phase = 'UI action';
  try {
    await action();
    phase = 'API response';
    const outcome = await pending;
    if (outcome.error) throw outcome.error;
    const response = outcome.response;
    assert.equal(response.status(), 200, `Expected HTTP 200 from ${path}`);
    console.log(`menu-walk: FileServers ${step}; received HTTP ${response.status()}`);
    return { body: await response.json(), params: new URL(response.url()).searchParams };
  } catch (cause) {
    const error = new Error(`FileServers ${step}: ${phase} failed; expected GET ${path}: ${cause.message}`, { cause });
    error.fileServers = { step, phase, expected_api: path, observed: observed.slice(-10) };
    throw error;
  } finally {
    page.off('response', observe);
  }
}

function assertWindow(params, fixture, scoped = true) {
  assert.equal(params.get('source_kind'), 'server');
  assert.equal(Date.parse(params.get('from')), Date.parse(fixture.from_utc), 'The selected start must survive navigation');
  assert.equal(Date.parse(params.get('to')), Date.parse(fixture.to_utc), 'The selected end must survive navigation');
  if (scoped) {
    assert.deepEqual(params.getAll('share').map(value => JSON.parse(value)), [JSON.parse(fixture.share_key)], 'The root identity must survive navigation');
    assert.equal(params.get('path'), fixture.path);
  }
}

function assertResourceReturn(actual, original) {
  const current = new URL(actual), expected = new URL(original);
  assert.equal(current.pathname, expected.pathname, 'Return must restore the resource list');
  const context = params => [...params].filter(([key]) => key !== 'selected_row').sort(([left], [right]) => left.localeCompare(right));
  assert.deepEqual(context(current.searchParams), context(expected.searchParams), 'Return must retain filters, period and page size');
}

async function assertFullPage(page) {
  assert.equal(await waitForVisibleLoadingToFinish(page, 20_000), true, 'FileServers loading must finish');
  await expect(page.locator('.sli-ds-drawer:visible, [role="dialog"]:visible')).toHaveCount(0);
  const geometry = await page.locator('main').evaluate(main => ({
    width: main.getBoundingClientRect().width,
    viewport: window.innerWidth,
    documentWidth: document.documentElement.scrollWidth,
  }));
  assert.ok(geometry.width >= geometry.viewport * .65, 'FileServers must use the main workspace width');
  assert.ok(geometry.documentWidth <= geometry.viewport + 2, 'Wide ACL content must stay inside its scroll container');
}

/** Runs in the existing beta-menu browser, with only its real loopback API. */
export async function walkFileServers(page, { url, results, fixture }) {
  assert.ok(fixture, 'The owned PostgreSQL FileServers fixture is required');
  for (const key of ['share_key', 'path', 'snapshot_id', 'before_snapshot_id', 'from_utc', 'to_utc'])
    assert.ok(fixture[key], `Missing FileServers fixture ${key}`);
  assert.equal(fixture.event_count, 7);
  const directory = join(results, 'fileservers');
  await mkdir(directory, { recursive: true });
  page.setDefaultTimeout(20_000);
  page.setDefaultNavigationTimeout(20_000);
  try {
    await verifyFileServers(page, { url, directory, fixture });
  } catch (error) {
    await writeFile(join(directory, 'failure.json'), JSON.stringify({
      ...error.fileServers, current_path: new URL(page.url()).pathname, message: redact(error.message),
    }, null, 2));
    await page.screenshot({ path: join(directory, 'failure.png'), fullPage: true, timeout: 5_000 }).catch(() => {});
    throw error;
  }
}

async function verifyFileServers(page, { url, directory, fixture }) {
  const evidence = [];
  const screenshot = async (name, claim) => {
    await assertFullPage(page);
    await page.screenshot({ path: join(directory, name), fullPage: true });
    evidence.push({ screenshot: name, claim });
    await writeFile(join(directory, 'checks.json'), JSON.stringify(evidence, null, 2));
  };
  const initial = new URL('app/report/file-audit.overview', url);
  initial.search = new URLSearchParams({
    source_kind: 'server', source_instance_id: fixture.source_instance_id,
    period: 'custom', from: fixture.from_utc, to: fixture.to_utc,
    domain: String(fixture.domain_id), limit: '50',
  }).toString();
  console.log('menu-walk: FileServers resource → saved observations → full-page ACL → comparison');

  let overview = await readResponse(page, 'open resource overview', reportPath('overview'), () => page.goto(initial.href));
  assertWindow(overview.params, fixture, false);
  const rootRow = () => page.getByRole('table').getByRole('row').filter({ hasText: fixture.path });
  await expect(rootRow()).toHaveCount(1);
  overview = await readResponse(page, 'select 200 resource rows', reportPath('overview'),
    () => page.getByRole('combobox', { name: 'Строк на странице', exact: true }).selectOption('200'),
    params => params.get('limit') === '200');
  assertWindow(overview.params, fixture, false);
  const resource = overview.body.items.find(row => row.agent_id === fixture.agent_id
    && row.source_instance_id === fixture.source_instance_id && row.collection_scope_id === fixture.collection_scope_id);
  assert.ok(resource, 'The authorized resource must be present in the API response');
  assert.equal(resource.permission_changes, fixture.event_count, 'The resource counter must count saved observations');
  await expect(rootRow().getByRole('link', { name: '7', exact: true })).toBeVisible();
  const resourceUrl = page.url();
  await screenshot('01-resources.png', 'Authorized resource; seven retained 4670 observations; real API limit=200.');

  const changes = await readResponse(page, 'open observation count', reportPath('permission-changes'),
    () => rootRow().getByRole('link', { name: '7', exact: true }).click());
  assertWindow(changes.params, fixture);
  assert.equal(changes.params.get('limit'), '200');
  assert.equal(changes.params.get('operation'), 'permissions');
  assert.equal(changes.params.get('record_unit'), 'saved_event_group', 'The counter must open the same observation population');
  const groups = changes.body.items.filter(row => row.record_unit === 'saved_event_group');
  assert.equal(groups.length, 1, 'Seven observations must remain one retained group');
  assert.equal(groups[0].aggregate.count, fixture.event_count);
  assert.equal(groups[0].aggregate.boundary, 'inside');
  assert.equal(Date.parse(groups[0].aggregate.first_seen_utc), Date.parse(fixture.first_seen_utc));
  assert.equal(Date.parse(groups[0].aggregate.last_seen_utc), Date.parse(fixture.last_seen_utc));
  const actions = page.getByRole('table', { name: 'Изменения прав и шар', exact: true });
  await expect(actions.locator('tbody > tr[data-clickable]')).toHaveCount(1);
  await expect(actions.getByRole('cell', { name: '7', exact: true })).toBeVisible();
  await actions.locator('tbody > tr[data-clickable]').click();
  await expect(page.getByText('Сохранённая группа наблюдений одного пути, субъекта, области и минуты.', { exact: true })).toBeVisible();
  await expect(page.locator('button, a').filter({ hasText: /7 исходных|семь исходных/i })).toHaveCount(0);
  await expect(page.getByRole('region', { name: 'Сохранённая запись', exact: true })).toBeVisible();
  await screenshot('04-actions.png', 'One retained group carries count=7 and its interval; its saved facts use the full workspace.');

  await page.getByRole('button', { name: 'К списку', exact: true }).click();
  await expect(actions.locator('tbody > tr[data-clickable]')).toHaveCount(1);
  await page.getByRole('link', { name: 'К списку', exact: true }).click();
  await expect(rootRow()).toHaveCount(1);
  assertResourceReturn(page.url(), resourceUrl);
  const resourceButton = rootRow().getByRole('button', { name: fixture.share_name, exact: true });
  await expect(resourceButton).toBeVisible();
  const detailPath = `/api/v2/reports/file-audit.permissions/rows/${fixture.snapshot_id}/detail`;
  const permissions = await readResponse(page, 'open resource ACL', detailPath, () => resourceButton.click());
  assertWindow(permissions.params, fixture);
  assert.equal(permissions.body.detail.object.file_id, fixture.object_id);
  assert.equal(permissions.body.detail.object.dacl.state, 'complete');
  assert.equal(permissions.body.detail.object.dacl.aces.length, 126, 'The large ACL must come from the retained API projection');
  const acl = page.getByRole('region', { name: permissionsTitle, exact: true });
  await expect(acl).toBeVisible();
  await acl.getByRole('combobox', { name: 'Строк на странице', exact: true }).selectOption('200');
  const aceRows = acl.getByRole('table', { name: permissionsTitle, exact: true }).locator('tbody > tr[data-clickable]');
  await expect(aceRows).toHaveCount(126);
  await expect(acl.getByText('1–126 из 126', { exact: true })).toBeVisible();
  await expect(acl.getByRole('button', { name: 'Вперёд', exact: true })).toBeDisabled();
  const lastSid = permissions.body.detail.object.dacl.aces.at(-1).sid;
  const search = acl.getByLabel('Поиск по субъекту, SID или маске', { exact: true });
  await search.fill(lastSid);
  await expect(aceRows).toHaveCount(1);
  await expect(aceRows).toContainText(lastSid);
  await search.fill('');
  await expect(aceRows).toHaveCount(126);
  await screenshot('02-permissions.png', 'Full-page NTFS ACL renders all 126 retained ACE at page size 200, alongside the independent SMB ACL.');

  const compared = await readResponse(page, 'compare retained snapshots', detailPath,
    () => page.getByRole('button', { name: 'Сравнение снимков', exact: true }).click(),
    params => params.get('compare_snapshot_id') === fixture.before_snapshot_id);
  assertWindow(compared.params, fixture);
  assert.equal(compared.body.detail.comparison.state, 'available');
  assert.equal(compared.body.detail.comparison.before.snapshot.id, fixture.before_snapshot_id);
  assert.equal(compared.body.detail.comparison.after.snapshot.id, fixture.snapshot_id);
  await expect(page.getByRole('combobox', { name: 'Было', exact: true })).toHaveValue(fixture.before_snapshot_id);
  await expect(page.getByRole('combobox', { name: 'Стало', exact: true })).toHaveValue(fixture.snapshot_id);
  const comparison = page.getByRole('region', { name: 'Сравнение снимков', exact: true });
  await expect(comparison).toBeVisible();
  const difference = comparison.getByRole('table').locator('tbody > tr[data-clickable]').first();
  await expect(difference).toBeVisible();
  await difference.click();
  const sides = comparison.locator('tbody .sli-file-audit__comparison-sides');
  await expect(sides).toBeVisible();
  await expect(sides.locator(':scope > section')).toHaveCount(2);
  const widths = await sides.locator(':scope > section').evaluateAll(nodes => nodes.map(node => node.getBoundingClientRect().width));
  assert.ok(Math.abs(widths[0] - widths[1]) <= 2, 'Before and after must receive equal comparison width');
  const comparisonUrl = new URL(page.url());
  assert.equal(comparisonUrl.searchParams.get('snapshot_id'), fixture.snapshot_id);
  assert.equal(comparisonUrl.searchParams.get('compare_snapshot_id'), fixture.before_snapshot_id);
  assertWindow(comparisonUrl.searchParams, fixture);
  await screenshot('03-comparison.png', 'Two compatible retained snapshots show an expanded before/after ACL difference.');

  await page.getByRole('link', { name: 'К списку', exact: true }).click();
  await expect(rootRow()).toHaveCount(1);
  assertResourceReturn(page.url(), resourceUrl);
  await expect(page.getByRole('combobox', { name: 'Строк на странице', exact: true })).toHaveValue('200');
}
