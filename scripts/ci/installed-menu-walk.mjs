import { randomBytes } from 'node:crypto';
import { chromium } from 'playwright-core';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { redact, waitForVisibleLoadingToFinish } from './checks.mjs';

let input = '';
for await (const chunk of process.stdin) input += chunk;
const { url, token, commit } = JSON.parse(input);
const origin = new URL(url).origin;
const results = process.argv[2];
if (!/^https:/.test(origin) || !token || !results || commit !== '2323cfa48cf8c8d3e66705b1b09a7e20e140309f') {
  throw new Error('Expected the verified guest build and an owner session');
}
const agentForm = '/app/agents?register=1';
const reasonCode = value => typeof value === 'string' && /^[a-z][a-z0-9_]{0,95}$/.test(value) ? value : null;
const browser = await chromium.launch({ executablePath: '/usr/bin/chromium-headless-shell', timeout: 30_000 });
const context = await browser.newContext({ locale: 'ru-RU', timezoneId: 'UTC', viewport: { width: 1440, height: 900 },
  serviceWorkers: 'block' });
context.setDefaultTimeout(12_000);
context.setDefaultNavigationTimeout(18_000);
await context.addInitScript(() => { localStorage.setItem('sli.locale', 'ru'); localStorage.setItem('sli.theme', 'light'); });
await context.addCookies([{ name: 'adlog_session', value: token, url: origin, httpOnly: true, secure: true, sameSite: 'Strict' }]);
await context.route('**/*', route => {
  const request = route.request();
  const target = new URL(request.url());
  if (['data:', 'blob:'].includes(target.protocol)) return route.continue();
  if (target.origin === origin && ['GET', 'HEAD'].includes(request.method())) return route.continue();
  return route.abort('blockedbyclient');
});

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

async function inspectScopedPage(path, picture) {
  const page = await context.newPage();
  const reportResponses = [];
  page.on('response', response => {
    const target = new URL(response.url());
    if (target.pathname.startsWith('/api/v2/reports/')) reportResponses.push({
      path: target.pathname, status: response.status(),
    });
  });
  try {
    const requested = new URL(path, origin);
    const response = await page.goto(requested.href, { waitUntil: 'domcontentloaded' });
    const main = page.locator('main').first();
    await main.waitFor({ state: 'visible' });
    await page.waitForLoadState('networkidle', { timeout: 10_000 }).catch(() => {});
    const settled = await waitForVisibleLoadingToFinish(page);
    const actual = new URL(page.url());
    const read = (url) => url.searchParams.get('domain_id') ?? url.searchParams.get('domain');
    const sensitive = page.locator('input, textarea, pre, code, [data-secret], [data-token]');
    await page.screenshot({ path: join(results, picture + '.png'), mask: [sensitive], timeout: 12_000 });
    return {
      pageStatus: response?.status(), settled, sameReport: actual.pathname === requested.pathname,
      sameDomain: read(actual) === read(requested), noEnrollment: await main.locator('a[href="' + agentForm + '"]').count() === 0,
      deniedText: (await main.innerText()).includes('Нет доступа'),
      reportResponses, text: (await main.innerText()).split('\n').map(line => redact(line.trim(), [token])).filter(Boolean).slice(0, 20),
    };
  } finally {
    await page.close();
  }
}

async function checkPermissions(evidence) {
  const report = '/api/v2/reports/ad.users.v2/data';
  const reportPage = '/app/report/ad.users.v2';
  evidence.viewerReport = 'ad.users.v2';
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
    subject_type: 'user', subject_id: created.body.item.id, report_key: 'ad.users.v2',
    scope: { kind: 'domain', ids: [ids[0]] },
    field_categories: ['identity_basic', 'security'], allowed_actions: ['view'],
    business_reason: 'Isolated installed beta menu scope verification',
  } });
  evidence.viewerGrant = { status: grant.status, code: reasonCode(grant.body.error) };
  requireResult(grant.status === 201, 'grant_only_first_domain');
  const login = await api('/api/auth/login', { session: null, body: { username, password } });
  const viewer = login.cookie?.match(/(?:^|[, ]\s*)adlog_session=([^;]+)/)?.[1];
  evidence.viewerLogin = { status: login.status, authenticated: login.body.authenticated === true };
  requireResult(login.status === 200 && login.body.authenticated === true && viewer, 'authenticate_synthetic_viewer');

  const permitted = await api(report + '?tab=changes&domain_id=' + ids[0], { session: viewer });
  const denied = await api(report + '?tab=changes&domain_id=' + ids[1], { session: viewer });
  evidence.viewerAllowed = { status: permitted.status, code: reasonCode(permitted.body.error) };
  evidence.viewerDenied = { status: denied.status, code: reasonCode(denied.body.error) };
  requireResult(permitted.status === 200 && denied.status === 403 && denied.body.error === 'domain_scope_denied', 'viewer_api_scope');
  await context.clearCookies();
  await context.addCookies([{ name: 'adlog_session', value: viewer, url: origin, httpOnly: true, secure: true, sameSite: 'Strict' }]);
  evidence.viewerDenied.ui = await inspectScopedPage(reportPage + '?tab=changes&domain_id=' + ids[1], 'viewer-cross-domain');
  const ui = evidence.viewerDenied.ui;
  requireResult(ui.pageStatus === 200 && ui.settled && ui.sameReport && ui.sameDomain && ui.noEnrollment
    && ui.deniedText && ui.reportResponses.some(result => result.path.endsWith('/data') && result.status === 403),
  'viewer_explicit_domain_ui');
}


const evidence = { commit };
try {
  console.log('BETA_README_EVIDENCE installed_chromium=' + browser.version());
  const domains = await api('/api/v1/domains');
  evidence.cleanDomains = { status: domains.status, count: domains.body.items?.length };
  requireResult(domains.status === 200 && domains.body.items?.length === 0, 'clean_install_required');
  await checkPermissions(evidence);
  evidence.passed = true;
} catch (error) {
  evidence.error = /^[a-z_]+$/.test(error.message) ? error.message : 'scope_probe_error';
  evidence.type = /^[A-Za-z]+$/.test(error.name) ? error.name : 'Error';
} finally {
  await browser.close();
}
await writeFile(join(results, 'menu.json'), JSON.stringify(evidence, null, 2));
console.log('BETA_README_EVIDENCE menu_summary=' + JSON.stringify(evidence));
if (!evidence.passed) process.exitCode = 1;
