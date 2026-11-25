import { randomBytes } from 'node:crypto';
import { chromium } from 'playwright-core';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { forbiddenLabels, loadErrors, redact, waitForVisibleLoadingToFinish } from './checks.mjs';

let input = '';
for await (const chunk of process.stdin) input += chunk;
const { url, token, commit } = JSON.parse(input);
const origin = new URL(url).origin;
const results = process.argv[2];
if (!/^https:/.test(origin) || !token || !results || !/^[a-f0-9]{40}$/.test(commit)) {
  throw new Error('Expected a verified guest HTTPS origin and an owner session');
}
const registry = JSON.parse(await readFile(new URL('./navigation_v3.json', import.meta.url), 'utf8'));
const all = registry.sections.flatMap(section => section.groups.flatMap(group =>
  group.entries.map(entry => ({ ...entry, administration: ['admin', 'operations'].includes(section.id) }))));
const allBetaEntries = registry.beta_entries.map(id => {
  const entry = all.find(item => item.id === id);
  if (!entry || !/^[a-z][a-z-]+$/.test(id)) throw new Error('Invalid beta navigation declaration');
  return { ...entry, path: entry.path === '/admin/language-time' ? '/settings' : entry.path };
});
const firstAgentPages = new Set(['workspace', 'security-events', 'ad-report', 'users-report', 'computers-report']);
const candidates = new Set([...firstAgentPages, 'notifications']);
const agentForm = '/app/agents?register=1';
const agentAction = 'Добавить агента';
const entries = allBetaEntries.filter(entry => candidates.has(entry.id));
const readStatusPosts = new Set([
  '/api/v1/notification-channels/smtp/setup/status',
  '/api/v1/notification-channels/telegram/setup/status',
]);
const reasonCode = value => typeof value === 'string' && /^[a-z][a-z0-9_]{0,95}$/.test(value) ? value : null;
const base = new URL('/app/', origin).href;
const targetPath = path => new URL('app' + path, origin).pathname.replace(/\/$/, '');
const nav = '.sli-ds-shell__nav';
const clean = value => redact(value, [token]).replace(/[A-Za-z0-9+_/-]{38,}(?:={1,2})?/g, '[redacted]');
const lines = value => [...new Set(value.split('\n').map(line => clean(line.trim())).filter(Boolean))].slice(0, 38);
const browser = await chromium.launch({ executablePath: '/usr/bin/chromium-headless-shell', timeout: 30_000 });
const context = await browser.newContext({ locale: 'ru-RU', timezoneId: 'UTC', viewport: { width: 1440, height: 900 },
  serviceWorkers: 'block' });
context.setDefaultTimeout(12_000);
context.setDefaultNavigationTimeout(18_000);
await context.addInitScript(() => { localStorage.setItem('sli.locale', 'ru'); localStorage.setItem('sli.theme', 'light'); });
await context.addCookies([{ name: 'adlog_session', value: token, url: origin, httpOnly: true, secure: true, sameSite: 'Strict' }]);

let activeRow;
await context.route('**/*', route => {
  const request = route.request();
  const target = new URL(request.url());
  if (['data:', 'blob:'].includes(target.protocol)) return route.continue();
  if (target.origin === origin && ['GET', 'HEAD'].includes(request.method())) return route.continue();
  if (target.origin === origin && request.method() === 'POST' && !target.search && readStatusPosts.has(target.pathname)
      && (request.postData() === null || /^\{\s*\}$/.test(request.postData().trim()))) return route.continue();
  if (activeRow && target.origin === origin) activeRow.blocked.push(request.method() + ' ' + target.pathname);
  return route.abort('blockedbyclient');
});

const rows = [];
const seen = new Set();
let home = null;
let domainList = null;
let permissionChecks = null;

async function api(path, { session = token, body } = {}) {
  const headers = { Accept: 'application/json', Origin: origin };
  if (session) headers.Cookie = 'adlog_session=' + session;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(new URL(path, origin), {
    method: body === undefined ? 'GET' : 'POST', headers, redirect: 'error',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: response.status, body: await response.json(), cookie: response.headers.get('set-cookie') };
}

function requireResult(condition, step) {
  if (!condition) throw new Error(step);
}

async function assertDeniedPage(path) {
  const page = await context.newPage();
  try {
    await page.goto(new URL(path, origin).href, { waitUntil: 'domcontentloaded' });
    const main = page.locator('main').first();
    await main.getByText('Нет доступа', { exact: true }).first().waitFor();
    return await main.locator('a[href="' + agentForm + '"]').count() === 0;
  } finally {
    await page.close();
  }
}

async function checkPermissions(evidence) {
  const report = '/api/v2/reports/ad.infrastructure/data';
  const reportPage = '/app/report/ad.infrastructure';
  const invalid = '?domain_id=999999';
  const owner = await api(report + invalid);
  evidence.ownerExplicit = { status: owner.status, code: reasonCode(owner.body.error) };
  requireResult(owner.status === 403 && owner.body.error === 'domain_scope_denied', 'owner_explicit_domain_api');
  evidence.ownerExplicit.noEnrollment = await assertDeniedPage(reportPage + invalid);
  requireResult(evidence.ownerExplicit.noEnrollment, 'owner_explicit_domain_ui');

  // The first-run observations above precede this synthetic authorization setup.
  const names = ['menu-allowed.example.test', 'menu-restricted.example.test'];
  for (const fqdn of names) {
    const registered = await api('/api/v1/setup/domains', { body: { fqdn } });
    evidence.domainRegistration = [...(evidence.domainRegistration ?? []), { status: registered.status, code: reasonCode(registered.body.error) }];
    requireResult(registered.status === 201, 'register_synthetic_domain');
  }
  const list = await api('/api/v1/domains');
  const ids = names.map(name => list.body.items?.find(domain => domain.display_name === name)?.id);
  requireResult(list.status === 200 && ids.every(id => Number.isSafeInteger(id) && id > 0), 'verify_synthetic_domain_ids');

  const username = 'menu-scope-viewer';
  const password = randomBytes(30).toString('base64url');
  const created = await api('/api/auth/users', { body: { username, password, role: 'viewer' } });
  evidence.viewerCreation = { status: created.status, code: reasonCode(created.body.error) };
  requireResult(created.status === 201 && Number.isSafeInteger(created.body.item?.id), 'create_synthetic_viewer');
  const grant = await api('/api/v1/access/assignments', { body: {
    subject_type: 'user', subject_id: created.body.item.id, report_key: 'ad.state',
    scope: { kind: 'domain', ids: [ids[0]] },
    field_categories: ['identity_basic', 'security', 'technical'], allowed_actions: ['view'],
    business_reason: 'Isolated installed beta menu scope verification',
  } });
  evidence.viewerGrant = { status: grant.status, code: reasonCode(grant.body.error) };
  requireResult(grant.status === 201, 'grant_only_first_domain');
  const login = await api('/api/auth/login', { session: null, body: { username, password } });
  const viewer = login.cookie?.match(/(?:^|[, ]\s*)adlog_session=([^;]+)/)?.[1];
  evidence.viewerLogin = { status: login.status, authenticated: login.body.authenticated === true };
  requireResult(login.status === 200 && login.body.authenticated === true && viewer, 'authenticate_synthetic_viewer');

  const permitted = await api(report + '?domain_id=' + ids[0], { session: viewer });
  const denied = await api(report + '?domain_id=' + ids[1], { session: viewer });
  evidence.viewerAllowed = { status: permitted.status, code: reasonCode(permitted.body.error) };
  evidence.viewerDenied = { status: denied.status, code: reasonCode(denied.body.error) };
  requireResult(permitted.status === 200 && denied.status === 403 && denied.body.error === 'domain_scope_denied', 'viewer_api_scope');
  await context.clearCookies();
  await context.addCookies([{ name: 'adlog_session', value: viewer, url: origin, httpOnly: true, secure: true, sameSite: 'Strict' }]);
  evidence.viewerDenied.noEnrollment = await assertDeniedPage(reportPage + '?domain_id=' + ids[1]);
  requireResult(evidence.viewerDenied.noEnrollment, 'viewer_cross_domain_ui');
}

async function menuLinks(page) {
  const result = await page.locator(nav + ' a[data-route]').evaluateAll(nodes => nodes.map(node => ({
    route: node.dataset.route, path: new URL(node.href).pathname.replace(/\/$/, ''), label: node.innerText.trim(),
  })));
  for (const link of result) {
    if (!['administration', 'back-to-work'].includes(link.route)) seen.add(link.path);
  }
  return result;
}

try {
  console.log('BETA_README_EVIDENCE installed_chromium=' + browser.version());
  for (const entry of entries) {
    const expected = targetPath(entry.path);
    const row = { id: entry.id, path: expected, clicked: false, failure: [], labels: [], api: [], responses: [], blocked: [], text: [] };
    rows.push(row);
    activeRow = row;
    const page = await context.newPage();
    const outstanding = new Set();
    const reasonCodes = new Set();
    let checkDestination = false;
    page.on('response', response => {
      if (!checkDestination) return;
      const path = new URL(response.url()).pathname;
      const status = response.status();
      if (readStatusPosts.has(path)) row.responses.push({ path, status });
      if (status >= 400) {
        const line = response.request().method() + ' ' + path + ' → ' + status;
        (path.startsWith('/api/') ? row.api : row.failure).push(clean(line));
      }
      if (!path.startsWith('/api/') || !response.headers()['content-type']?.includes('json')) return;
      const read = response.json().then(body => {
        const visit = node => {
          if (!node || typeof node !== 'object') return;
          for (const [key, value] of Object.entries(node)) {
            if (['reason', 'reason_code'].includes(key) && typeof value === 'string') reasonCodes.add(value);
            else if (typeof value === 'object') visit(value);
          }
        };
        visit(body);
        if (path === '/api/v1/domains') {
          domainList = { status, items: Array.isArray(body.items) ? body.items.length : null };
        }
        if (/^\/api\/v2\/reports\/[a-z0-9.-]+(?:\/data)?$/.test(path)) {
          row.responses.push({ path, status, state: reasonCode(body.state), reason: reasonCode(body.state_details?.reason ?? body.reason ?? body.error),
            scope: reasonCode(body.domain_scope?.state), scopeCount: Array.isArray(body.domain_scope?.domain_ids) ? body.domain_scope.domain_ids.length : null,
            defaultDomainState: reasonCode(body.default_domain_state), allowed: typeof body.access?.allowed === 'boolean' ? body.access.allowed : null });
        }
        if (entry.id === 'workspace' && path === '/api/v1/home/summary' && status === 200) {
          home = { domains: Array.isArray(body.domains) ? body.domains.length : null,
            open: Number.isInteger(body.problems?.open_count) ? body.problems.open_count : null,
            items: Array.isArray(body.problems?.items) ? body.problems.items.length : null };
        }
      }).catch(() => {}).finally(() => outstanding.delete(read));
      outstanding.add(read);
    });
    page.on('requestfailed', request => {
      if (checkDestination && new URL(request.url()).origin === origin &&
          !/ERR_(?:ABORTED|BLOCKED_BY_CLIENT)/.test(request.failure()?.errorText ?? '')) {
        row.failure.push(clean(request.method() + ' ' + new URL(request.url()).pathname + ' → ' + request.failure()?.errorText));
      }
    });
    page.on('console', message => {
      if (checkDestination && message.type() === 'error') row.failure.push(clean(message.text()));
    });
    page.on('pageerror', error => { if (checkDestination) row.failure.push(clean(error.message)); });
    try {
      if (entry.id === 'workspace') checkDestination = true;
      await page.goto(base, { waitUntil: 'domcontentloaded' });
      await page.locator(nav + ' a[data-route="workspace"]').waitFor();
      if (entry.administration) {
        const gate = page.locator(nav + ' a[data-route="administration"]');
        await gate.click();
        await page.locator(nav + ' a[data-route="back-to-work"]').waitFor();
      }
      await page.waitForLoadState('networkidle', { timeout: 12_000 }).catch(() => {});
      const menu = await menuLinks(page);
      const link = menu.find(item => item.path === expected && !['administration', 'back-to-work'].includes(item.route));
      checkDestination = true;
      if (link) {
        const current = page.locator(nav + ' a[data-route=' + JSON.stringify(link.route) + ']');
        row.label = clean(link.label);
        await current.click();
        row.clicked = true;
      } else {
        row.failure.push('Пункт отсутствует в меню владельца');
        await page.goto(new URL('app' + entry.path, origin).href, { waitUntil: 'domcontentloaded' });
      }
      await page.waitForURL(current => current.pathname.replace(/\/$/, '') === expected, { timeout: 8_000 })
        .catch(() => row.failure.push('Перенаправление вместо страницы: ' + new URL(page.url()).pathname));
      const main = page.locator('main').first();
      await main.waitFor({ state: 'visible' });
      await page.waitForLoadState('networkidle', { timeout: 12_000 }).catch(() => {});
      await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      if (!await waitForVisibleLoadingToFinish(page)) row.failure.push('Загрузка не завершилась после ответов API');
      if (entry.id === 'workspace' && !domainList) {
        domainList = await page.evaluate(async () => {
          const response = await fetch('/api/v1/domains', { credentials: 'same-origin' });
          const body = await response.json();
          return { status: response.status, items: Array.isArray(body.items) ? body.items.length : null };
        });
      }
      await Promise.all([...outstanding]);
      const visible = await main.innerText();
      if (!visible.trim()) row.failure.push('Пустой рабочий экран');
      row.text = lines(visible);
      row.dataRows = await main.locator('tbody td:not([colspan]):visible, .sli-ds-review-list__item:visible').count();
      row.emptyCopy = row.text.filter(line => /(?:^|\s)(?:подключите|добавьте|настройте|выберите|укажите|откройте|запустите|перейдите|очистите|измените|проверьте|установите|включите|создайте)(?:\s|$)/i.test(line));
      row.controls = await main.locator('button:visible, a[href]:visible').evaluateAll(nodes => nodes
        .filter(node => !node.disabled && node.getAttribute('aria-disabled') !== 'true')
        .map(node => (node.innerText || node.getAttribute('aria-label') || '').trim()).filter(Boolean).slice(0, 16));
      row.controls = row.controls.map(clean);
      row.labels = forbiddenLabels(visible, [...reasonCodes]).map(clean);
      row.failure.push(...loadErrors(visible).map(clean));
      const sensitive = page.locator('input, textarea, pre, code, [data-secret], [data-token]');
      await page.screenshot({ path: join(results, entry.id + '.png'), fullPage: false, mask: [sensitive], timeout: 12_000 });
      if (firstAgentPages.has(entry.id)) {
        const action = main.getByRole('link', { name: agentAction, exact: true });
        await action.first().waitFor();
        row.enrollmentLinks = await main.locator('a[href="' + agentForm + '"]').count();
        requireResult(row.enrollmentLinks === 1 && await action.count() === 1
          && await action.getAttribute('href') === agentForm, 'expected_one_registration_link');
        await action.click();
        await page.waitForURL(target => target.pathname === '/app/agents' && target.searchParams.get('register') === '1');
        const dialog = page.getByRole('dialog', { name: agentAction });
        await dialog.waitFor();
        await dialog.locator('#agent-console-server-url').waitFor();
        await dialog.locator('#agent-console-limit').waitFor();
        row.enrollmentOpened = true;
        await page.screenshot({ path: join(results, entry.id + '-enrollment.png'), mask: [sensitive], timeout: 12_000 });
      }
    } catch (error) {
      row.failure.push(clean(String(error.message).split('\n')[0]));
    } finally {
      for (const key of ['failure', 'api', 'blocked', 'labels']) row[key] = [...new Set(row[key])];
      await page.close();
      await writeFile(join(results, 'menu.json'), JSON.stringify({ commit, home, domainList, menuPaths: [...seen], rows }, null, 2));
      console.log('BETA_README_EVIDENCE menu_row=' + JSON.stringify(row));
    }
  }
  activeRow = undefined;
  permissionChecks = {};
  if (domainList?.status === 200 && domainList.items === 0 && home?.domains === 0
    && rows.filter(row => row.enrollmentOpened).length === firstAgentPages.size) {
    try { await checkPermissions(permissionChecks); permissionChecks.passed = true; }
    catch (error) { permissionChecks.error = /^[a-z_]+$/.test(error.message) ? error.message : 'scope_probe_error'; }
  } else {
    permissionChecks.error = 'first_run_required_for_scope_probe';
  }
} finally { await browser.close(); }
await writeFile(join(results, 'menu.json'), JSON.stringify({ commit, home, domainList, menuPaths: [...seen], rows, permissionChecks }, null, 2));
const expected = new Set(allBetaEntries.map(entry => targetPath(entry.path)));
const unexpected = [...seen].filter(path => !expected.has(path));
console.log('BETA_README_EVIDENCE menu_summary=' + JSON.stringify({
  commit, visited: rows.length, clicked: rows.filter(row => row.clicked).length,
  loadErrorScreens: rows.filter(row => row.failure.length || row.api.length).length,
  technicalLabelScreens: rows.filter(row => row.labels.length).length,
  unexpected, home, domainList, permissionChecks, enrollmentFormsOpened: rows.filter(row => row.enrollmentOpened).length,
}));

const notification = rows.find(row => row.id === 'notifications');
const statuses = new Set(notification?.responses.filter(response => response.status === 200).map(response => response.path));
const passed = rows.length === candidates.size && rows.every(row =>
  row.clicked && !row.failure.length && !row.api.length && !row.blocked.length && !row.labels.length)
  && rows.filter(row => row.enrollmentOpened).length === firstAgentPages.size
  && [...readStatusPosts].every(path => statuses.has(path))
  && permissionChecks.passed === true;
if (!passed) process.exitCode = 1;
