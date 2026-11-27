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
    collection_policy: { state: 'active', interval_seconds: 60, batch_size: 32, rate_limit_per_minute: 120, spool_max_bytes: 67108864, manage_windows_audit: true },
    certificates: [{ serial: `fixture-${index}`, not_after: '2030-01-01T00:00:00Z', revoked_at: null }], rights_probe: {},
    windows_audit: { policy_revision: 2, reported_at: observed, command_line_enabled: false, management_state: index === 0 ? 'blocked' : 'applied',
      families: { domain_controller: { state: index === 0 ? 'managed_by_gpo' : 'ok', required: [{ guid: 'fixture-logon', subcategory: 'logon',
        state: index === 0 ? 'managed_by_gpo' : 'ok', success: true, failure: true, actual_success: index !== 0, actual_failure: index !== 0,
        policy_name: index === 0 ? 'Audit Policy' : null }], non_security_channels: [] } } },
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
    else { unexpected.push(path); await route.fulfill({ status: 501, json: { error: 'unmocked_agent_request' } }); return; }
    await route.fulfill({ json: body });
  });
  await page.goto('/app/agents');
  const table = page.getByRole('table', { name: 'Агенты' });
  await expect(table.getByText('dc1.example.test', { exact: true })).toBeVisible({ timeout: 20000 });
  const auditIssue = table.getByText('Аудит блокирует GPO — настройте её', { exact: true });
  await expect(auditIssue).toBeVisible();
  expect(await auditIssue.evaluate(cell => cell.scrollWidth <= cell.clientWidth)).toBe(true);
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
  await expect(card.getByRole('checkbox', { name: 'Настраивать аудит автоматически' })).toBeChecked();
  await page.screenshot({ path: testInfo.outputPath('agents-card.png') });
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: 'Отключённые · 1', exact: true }).click();
  await expect(table.getByText('dc20.example.test')).toBeVisible();
  await page.getByRole('button', { name: 'Все · 19', exact: true }).click();
  await expect(table.getByText('dc20.example.test')).toHaveCount(0);
  await page.getByRole('button', { name: 'Добавить агента', exact: true }).click();
  const panel = page.getByRole('dialog', { name: 'Добавить агента', exact: true });
  const limit = panel.getByRole('spinbutton', { name: 'Число компьютеров' });
  const create = panel.getByRole('button', { name: 'Создать команду', exact: true });
  await expect(limit).toHaveValue('1');
  await expect(create).toBeVisible();
  await expect(panel.getByRole('checkbox', { name: 'Настраивать аудит на контроллере домена' })).toBeChecked();
  await expect(panel.getByRole('link', { name: 'Скачать пакет' })).toHaveAttribute('href', '/api/v1/agent/installer/SliAgent.msi');
  const inputBox = (await limit.boundingBox())!;
  const buttonBox = (await create.boundingBox())!;
  expect(Math.abs(inputBox.y + inputBox.height - buttonBox.y - buttonBox.height)).toBeLessThanOrEqual(2);
  expect(buttonBox.x).toBeGreaterThanOrEqual(inputBox.x + inputBox.width);
  await page.screenshot({ path: testInfo.outputPath('agents-add.png') });
  expect(unexpected).toEqual([]);
});
