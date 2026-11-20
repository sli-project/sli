import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { Page } from '@playwright/test';
import type { ReportColumnDto, ReportDefinitionDto, ReportResultDto } from '../../src/api/report-v2-types';

const root = fileURLToPath(new URL('../../../', import.meta.url));
export const longLabel = 'Дополнительные ограничения доступности и подтверждения источников для выбранного периода';
export const longError = `Синтетическая ошибка: ${longLabel}. ${'СинтетическийИдентификатор'.repeat(6)}`;
export const screens = [
  { name: 'home', path: '/app/', ready: '.sli-ds-home-freshness' },
  { name: 'problems', path: '/app/report/security.problems', key: 'security.problems', ready: '.sli-ds-table tbody tr' },
  { name: 'users', path: '/app/report/ad.users.v2', key: 'ad.users.v2', ready: '.sli-ds-table tbody tr' },
  { name: 'settings', path: '/app/platform-settings', ready: '[id="platform-setting-ui02.synthetic"]' },
  // There is no /agents route in this checkout. This exercises the existing
  // agent-key report, not a newly invented agent administration page.
  { name: 'agents', path: '/app/report/workstations.protection', key: 'workstations.protection', ready: '.sli-ds-table tbody tr' },
] as const;

// Serialize the real declarations, without executing readers or options (DB).
// No checked-in copy can drift away from the report being tested.
const declarations: ReportDefinitionDto[] = JSON.parse(execFileSync(process.env.SLI_TEST_PYTHON || 'python', ['-c', [
  'import json',
  'from server.sli.reporting.v2.reports.users import REPORT as users',
  'from server.sli.reporting.v2.reports.security_problems import REPORT as problems',
  'from server.sli.plugins.workstations.reports import make_report',
  'print(json.dumps([r.to_json() for r in (users, problems, make_report("protection"))]))',
].join('\n')], { cwd: root, encoding: 'utf8' }));

const definitions = new Map(declarations.map(raw => {
  const definition = structuredClone(raw);
  definition.title += ` — ${longLabel}`;
  definition.description = longError;
  definition.filter_options = {};
  for (const param of definition.params) {
    param.label += ` — ${longLabel}`;
    if (param.options_from) definition.filter_options[param.options_from] = [{ value: 'synthetic', label: longLabel }];
    param.options?.forEach(option => { option.label += ` — ${longLabel}`; });
  }
  definition.presets.forEach(preset => { preset.label += ` — ${longLabel}`; });
  return [definition.key, definition] as const;
}));

function rowFor(columns: ReportColumnDto[]) {
  const row: Record<string, unknown> = { id: 1, status: 'new', entity_id: 'synthetic', evidence: [], status_history: [] };
  for (const column of columns) {
    const value = column.kind === 'datetime' || column.kind === 'date' ? '2026-10-01T00:00:00Z'
      : column.kind === 'number' ? 3 : column.kind === 'boolean' ? true : column.kind === 'list' ? [longLabel] : longLabel;
    const parts = column.path.split('.');
    let target = row;
    for (const part of parts.slice(0, -1)) target = (target[part] ??= {}) as Record<string, unknown>;
    target[parts.at(-1)!] = value;
  }
  return row;
}

function result(definition: ReportDefinitionDto, detail = false): ReportResultDto {
  const columns = detail && typeof definition.detail === 'object' ? definition.detail.columns : definition.columns;
  return {
    contract_id: 'sli.report-result.v2', report_key: definition.key, state: 'partial',
    items: [rowFor(columns)], has_more: false, next_cursor: null, filtered_count: 1,
    metrics: [{ key: 'synthetic', label: longLabel, value: 1, caption: longError }],
    series: {}, coverage: {}, filter_options: definition.filter_options, collections: {},
    limitations: [{ code: 'ui02.synthetic', text: longError }], window: {},
  };
}

export async function installFixtures(page: Page, theme: string) {
  const unexpected: string[] = [];
  const state = { error: false };
  await page.addInitScript(({ theme }) => {
    localStorage.setItem('sli.locale', 'ru'); localStorage.setItem('sli.theme', theme);
  }, { theme });
  // Inject translations into the dev-served dictionary; never alter app source.
  await page.route('**/src/i18n/ru.ts*', async route => {
    const response = await route.fetch();
    let body = await response.text();
    let replacements = 0;
    for (const key of ['filters.title', 'filters.apply', 'filters.reset', 'home.title', 'platformSettings.page.title', 'platformSettings.save', 'reports.renderer.export_csv']) {
      const pattern = new RegExp(`("${key.replaceAll('.', '\\.')}"\\s*:\\s*)"([^"\\n]*)"`);
      body = body.replace(pattern, (_, prefix, value) => { replacements++; return `${prefix}${JSON.stringify(`${value} — ${longLabel}`)}`; });
    }
    if (replacements < 5) throw new Error('UI02 long translation injection no longer matches the dictionary');
    await route.fulfill({ response, body });
  });
  const navigation = JSON.parse(readFileSync(`${root}/config/navigation_v3.json`, 'utf8'));
  await page.route('**/api/**', async route => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    let body: unknown;
    let status = 200;
    if (pathname === '/api/v1/ui/bootstrap') body = { api_version: 'v1', effective_role: 'admin', principal: { username: 'synthetic.operator', role: 'admin' }, capabilities: ['operations.view'], navigation: [] };
    else if (pathname === '/api/v1/access/effective') body = { subject: { type: 'user', id: 1, username: 'synthetic.operator' }, platform_owner: false, capabilities: ['operations.view', 'problem.view'], reports: declarations.map(definition => ({ report_key: definition.key, allowed: true })) };
    else if (pathname === '/api/v2/reports') body = { contract_id: 'sli.report-catalog.v2', navigation, items: [] };
    else if (pathname === '/api/v1/overview') body = { collection_freshness: { state: 'partial', label: longLabel } };
    else if (pathname === '/api/v1/home/summary') body = {
      contract_id: 'sli.home-summary.v1', freshness: [{ key: 'ad.users.v2', title: longLabel, href: '/app/report/ad.users.v2', state: 'partial', observed_at_utc: null, limitation: longError }],
      deviations: [{ report_key: 'ad.users.v2', key: 'synthetic', report_title: longLabel, label: longLabel, value: 3, tone: 'warning', href: '/app/report/ad.users.v2' }],
      action_queue: { state: 'partial', has_more: true, items: [{ id: 1, title: longLabel, severity: 'high', assigned_to: null, href: '/app/report/security.problems' }] },
      reports: [{ key: 'ad.users.v2', title: longLabel, href: '/app/report/ad.users.v2' }], pinned: [],
    };
    else if (pathname === '/api/v1/platform-settings') body = { items: [{ key: 'ui02.synthetic', label: longLabel, description: longError, value: longLabel, source: 'database', environment: '', updated_at: null, updated_by: null }] };
    else {
      const match = pathname.match(/^\/api\/v2\/reports\/([^/]+)(.*)$/);
      const definition = match && definitions.get(decodeURIComponent(match[1]));
      if (definition) body = match![2] === '' ? definition : result(definition, match![2].includes('/rows/'));
      else { unexpected.push(`${request.method()} ${pathname}`); status = 501; body = { error: 'ui02_unmocked_request' }; }
    }
    // Shell stays successful: failures exercise the page's actual error view.
    if (state.error && (pathname === '/api/v1/home/summary' || pathname === '/api/v1/platform-settings' || pathname.endsWith('/data'))) {
      status = 503; body = { error: 'ui02_synthetic_failure', message: longError };
    }
    await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  });
  return { state, unexpected };
}
