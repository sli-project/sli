import { expect, test } from '@playwright/test';
import type { AgentItem } from '../../src/api/client';
import { readFileSync } from 'node:fs';

const navigation = JSON.parse(readFileSync(new URL('../../../config/navigation_v3.json', import.meta.url), 'utf8'));

test.use({ viewport: { width: 1440, height: 900 }, launchOptions: { executablePath: process.env.SLI_TEST_CHROMIUM_EXECUTABLE_PATH } });

test('agents list, computer card and registration panel', async ({ page }, testInfo) => {
  const observed = new Date().toISOString();
  const items: AgentItem[] = Array.from({ length: 20 }, (_, index) => ({
    id: `00000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`,
    host_id: `00000000-0000-4000-8001-${String(index + 1).padStart(12, '0')}`,
    host_name: `dc${index + 1}.example.test`, status: index === 19 ? 'disabled' : 'active', last_seen: observed,
    assigned_modules: [{ module_id: 'sli.windows.ad-dc', enabled: true, config: { channels: { Security: true } } }],
    policy_revision: 2, applied_policy_revision: 2, applied_collection_state: 'active',
    collection_policy: { state: 'active', interval_seconds: 60, batch_size: 32, rate_limit_per_minute: 120, spool_max_bytes: 67108864 },
    certificates: [{ serial: `fixture-${index}`, not_after: '2030-01-01T00:00:00Z', revoked_at: null }], rights_probe: {},
    windows_audit: { policy_revision: 2, reported_at: observed, command_line_enabled: true, management_state: 'applied',
      families: { logons: { state: 'ok', required: [{ guid: 'fixture-logon', subcategory: 'logon', success: true, failure: true, actual_success: true, actual_failure: true }], non_security_channels: [] } } },
    policy_audit: [{ id: index + 1, action: 'policy_ack', actor: 'fixture-admin', occurred_at: observed, details: {} }],
  }));
  await page.addInitScript(() => { localStorage.setItem('sli.locale', 'ru'); localStorage.setItem('sli.theme', 'light'); });
  const unexpected: string[] = [];
  await page.route(url => url.pathname.startsWith('/api/'), async route => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown;
    if (path === '/api/v1/ui/bootstrap') body = { api_version: 'v1', effective_role: 'admin', principal: { username: 'fixture-admin', role: 'admin' }, capabilities: ['access.manage'], navigation: [] };
    else if (path === '/api/v1/access/effective') body = { subject: { type: 'user', id: 1, username: 'fixture-admin' }, platform_owner: true, capabilities: ['access.manage'], reports: [] };
    else if (path === '/api/v2/reports') body = { contract_id: 'sli.report-catalog.v2', navigation, items: [] };
    else if (path === '/api/v1/overview') body = {};
    else if (path === '/api/v1/admin/agents') body = { items };
    else if (path === '/api/v1/admin/agent-deployment-directory') body = { domains: [{ id: 1, name: 'example.test' }] };
    else if (['/api/v1/admin/agent-templates', '/api/v1/admin/agent-group-tokens', '/api/v1/admin/agent-update-waves'].includes(path)) body = { items: [] };
    else { unexpected.push(path); await route.fulfill({ status: 501, json: { error: 'unmocked_agent_request' } }); return; }
    await route.fulfill({ json: body });
  });
  await page.goto('/app/agents');
  const table = page.getByRole('table', { name: 'Агенты' });
  await expect(table.getByText('dc1.example.test', { exact: true })).toBeVisible({ timeout: 20000 });
  await expect(table.locator('tbody details')).toHaveCount(0);
  const measurements = await table.evaluate(table => {
    const rows = [...table.querySelectorAll('tbody tr')];
    const header = document.querySelector('main .sli-ds-header');
    const filters = document.querySelector('main .sli-ds-filters');
    return {
      rowHeight: rows[0].getBoundingClientRect().height,
      columns: table.querySelectorAll('thead th').length,
      wordsAboveTable: `${header?.textContent} ${filters?.textContent}`.split(/\s+/).filter(Boolean).length,
      firstRowTop: rows[0].getBoundingClientRect().top,
      visibleRows: rows.filter(row => row.getBoundingClientRect().bottom <= innerHeight).length,
    };
  });
  console.log('Agents 1440x900:', measurements);
  expect(measurements.rowHeight).toBeLessThanOrEqual(30);
  expect(measurements.columns).toBeLessThanOrEqual(7);
  expect(measurements.wordsAboveTable).toBeLessThanOrEqual(30);
  expect(measurements.firstRowTop).toBeLessThanOrEqual(300);
  expect(measurements.visibleRows).toBeGreaterThanOrEqual(14);
  await page.screenshot({ path: testInfo.outputPath('agents-list.png') });
  await table.getByText('dc1.example.test', { exact: true }).click();
  const card = page.getByRole('dialog', { name: 'dc1.example.test' });
  for (const name of ['Сбор событий', 'Аудит Windows', 'Сертификат', 'История настроек', 'Действия']) await expect(card.getByRole('heading', { name, exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('agents-card.png') });
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: 'Отключённые · 1', exact: true }).click();
  await expect(table.getByText('dc20.example.test')).toBeVisible();
  await page.getByRole('button', { name: 'Все · 19', exact: true }).click();
  await expect(table.getByText('dc20.example.test')).toHaveCount(0);
  await page.getByRole('button', { name: 'Добавить компьютер', exact: true }).click();
  const panel = page.getByRole('dialog', { name: 'Добавить компьютер', exact: true });
  await expect(panel.getByRole('tab', { name: 'Групповая регистрация', exact: true })).toBeVisible();
  await expect(panel.getByRole('button', { name: 'Создать групповой токен', exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('agents-add.png') });
  expect(unexpected).toEqual([]);
});
