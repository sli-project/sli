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
    const body = await response.json();
    return { body, params: new URL(response.url()).searchParams, milliseconds: Math.round(response.request().timing().responseEnd) };
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

async function assertResourceReturn(page, original) {
  const expected = new URL(original);
  await expect(page).toHaveURL(current => current.pathname === expected.pathname);
  const current = new URL(page.url());
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
  const screenshot = async (name, measurement) => {
    await assertFullPage(page);
    const rows = await page.locator('main table tbody > tr').evaluateAll(nodes => nodes.filter(node => {
      const box = node.getBoundingClientRect();
      const scroll = node.closest('.sli-ds-table__scroll')?.getBoundingClientRect();
      return box.height > 0 && box.bottom <= Math.min(innerHeight, scroll?.bottom ?? innerHeight) && box.top >= (scroll?.top ?? 0)
        && !node.querySelector('td[colspan]');
    }).length);
    await page.screenshot({ path: join(directory, name) });
    evidence.push({ name, rows, milliseconds: measurement.milliseconds });
    console.log('file-servers screenshot ' + JSON.stringify(evidence.at(-1)));
  };
  const initial = new URL('app/report/file-audit.actions', url);
  initial.search = new URLSearchParams({
    source_kind: 'server', source_instance_id: fixture.source_instance_id,
    period: 'custom', from: fixture.from_utc, to: fixture.to_utc,
    domain: String(fixture.domain_id), limit: '50',
  }).toString();
  console.log('menu-walk: FileServers resource → saved observations → full-page ACL → comparison');

  const initialActions = await readResponse(page, 'open default Actions', reportPath('actions'), () => page.goto(initial.href));
  await expect(page.getByRole('tab', { name: 'Действия', exact: true })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('tab', { name: 'Ресурсы', exact: true })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Права', exact: true })).toBeVisible();
  await expect(page.getByRole('navigation').getByRole('link', { name: 'Файловые серверы', exact: true })).toHaveCount(1);
  const overviewTab = page.getByRole('tab', { name: 'Ресурсы', exact: true });
  let overview = await readResponse(page, 'open resources', reportPath('overview'), () => overviewTab.click());
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
  await screenshot('01-resources.png', overview);
  await readResponse(page, 'open permission checks', reportPath('permissions'),
    () => page.getByRole('tab', { name: 'Права', exact: true }).click());
  await expect(page.getByRole('table', { name: 'Права', exact: true })).toBeVisible();
  await overviewTab.click();
  await expect(rootRow()).toHaveCount(1);

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
  const actions = page.getByRole('table', { name: 'Действия', exact: true });
  const actionRow = actions.locator('tbody > tr[data-clickable]');
  await expect(actionRow).toHaveCount(1);
  await expect(actionRow.getByText('×7', { exact: true })).toBeVisible();
  await actionRow.click();
  await expect(actions.locator('tbody > tr > td[colspan]')).toBeVisible();
  await screenshot('04-actions.png', changes);
  assert.equal(initialActions.body.items.length, changes.body.items.length);

  await page.getByRole('link', { name: 'К списку', exact: true }).click();
  await expect(rootRow()).toHaveCount(1);
  await assertResourceReturn(page, resourceUrl);
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
  await screenshot('02-permissions.png', permissions);

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
  await screenshot('03-comparison.png', compared);

  await page.getByRole('link', { name: 'К списку', exact: true }).click();
  await expect(rootRow()).toHaveCount(1);
  await assertResourceReturn(page, resourceUrl);
  await expect(page.getByRole('combobox', { name: 'Строк на странице', exact: true })).toHaveValue('200');
}
