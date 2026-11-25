import { chromium } from 'playwright-core';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';

let input = '';
for await (const chunk of process.stdin) input += chunk;
const { url, token, commit } = JSON.parse(input);
const origin = new URL(url).origin;
const results = process.argv[2];
if (!/^https:/.test(origin) || !token || !results || commit !== '4a6f14c815e07ff2a01346700d79507689d657e9') {
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

async function api(path, { body } = {}) {
  const headers = { Accept: 'application/json', Origin: origin };
  headers.Cookie = 'adlog_session=' + token;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(new URL(path, origin), {
    method: body === undefined ? 'GET' : 'POST', headers, redirect: 'error',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

function requireResult(condition, step) {
  if (!condition) throw new Error(step);
}

const evidence = { commit, direct: [], tabs: [] };
const missing = '999999';
const reportPath = key => '/api/v2/reports/' + key + '/data';
const uiPath = (key, search) => '/app/report/' + key + '?' + search;

function scope(url) {
  const search = new URL(url).searchParams;
  return { domain: search.get('domain'), domain_id: search.get('domain_id'), tab: search.get('tab') };
}

function observe(page, key) {
  const calls = [];
  page.on('response', response => {
    if (new URL(response.url()).pathname === reportPath(key)) {
      calls.push({ ...scope(response.url()), status: response.status() });
    }
  });
  return calls;
}

async function visit(page, key, search) {
  const response = await page.goto(new URL(uiPath(key, search), origin).href, { waitUntil: 'domcontentloaded' });
  requireResult(response?.status() === 200, 'report_document');
  const main = page.locator('main').first();
  await main.waitFor({ state: 'visible' });
  return main;
}

async function deny(main) {
  await main.getByRole('link', { name: 'Мой доступ', exact: true }).waitFor({ state: 'visible' });
  return {
    denied: (await main.innerText()).includes('Нет доступа'),
    noEnrollment: await main.locator('a[href="' + agentForm + '"]').count() === 0,
  };
}

async function photograph(page, name) {
  await page.screenshot({
    path: join(results, name + '.png'),
    mask: [page.locator('input, textarea, pre, code, [data-secret], [data-token]')],
    timeout: 12_000,
  });
}

async function checkDirect(parameter) {
  const key = 'ad.infrastructure';
  const search = parameter + '=' + missing;
  const result = await api(reportPath(key) + '?' + search);
  const row = { parameter, api: result.status, reason: reasonCode(result.body.error) };
  evidence.direct.push(row);
  requireResult(row.api === 403 && row.reason === 'domain_scope_denied', 'direct_scope_api');
  const page = await context.newPage();
  const calls = observe(page, key);
  try {
    const main = await visit(page, key, search);
    Object.assign(row, await deny(main), scope(page.url()), { calls });
    requireResult(row.denied && row.noEnrollment && row[parameter] === missing
      && calls.some(call => call[parameter] === missing && call.status === 403), 'direct_scope_browser');
  } finally {
    row.current = scope(page.url());
    await photograph(page, 'owner-direct-' + parameter).catch(() => {});
    await page.close();
  }
}

async function checkTab(key, initialTab) {
  const search = new URLSearchParams({ domain: missing, domain_id: missing, tab: initialTab });
  const page = await context.newPage();
  const calls = observe(page, key);
  const row = { report: key, calls };
  evidence.tabs.push(row);
  try {
    const main = await visit(page, key, search);
    const before = await deny(main);
    row.before = { ...scope(page.url()), ...before };
    const changes = main.getByRole('tab', { name: 'Изменения', exact: true });
    await changes.click();
    await page.waitForURL(current => current.searchParams.get('tab') === 'changes');
    row.after = { ...scope(page.url()), ...await deny(main) };
    await photograph(page, key + '-tab');
    requireResult(row.before.tab === initialTab && row.after.tab === 'changes'
      && [row.before, row.after].every(value => value.denied && value.noEnrollment
        && value.domain === missing && value.domain_id === missing), 'tab_scope_browser');
  } finally {
    await page.close();
  }
}

async function checkSelection() {
  const key = 'ad.computers.v6';
  const names = ['scope-first.example.test', 'scope-second.example.test'];
  const registration = [];
  const row = { registration };
  evidence.selection = row;
  for (const fqdn of names) {
    const response = await api('/api/v1/setup/domains', { body: { fqdn } });
    registration.push({ status: response.status, reason: reasonCode(response.body.error) });
    requireResult(response.status === 201, 'register_synthetic_domain');
  }
  const list = await api('/api/v1/domains');
  const ids = names.map(name => list.body.items?.find(domain => domain.display_name === name)?.id);
  requireResult(list.status === 200 && ids.every(id => Number.isSafeInteger(id) && id > 0) && ids[0] !== ids[1],
    'verify_synthetic_domains');
  const [first, second] = ids.map(String);
  const page = await context.newPage();
  const calls = observe(page, key);
  row.calls = calls;
  try {
    const main = await visit(page, key, new URLSearchParams({ domain: first, domain_id: first, tab: 'computers' }));
    const selector = main.getByRole('combobox', { name: 'Домен', exact: true });
    await selector.waitFor({ state: 'visible' });
    await selector.locator('option[value="' + second + '"]').waitFor({ state: 'attached' });
    row.before = { ...scope(page.url()), selected: await selector.inputValue() };
    row.options = await selector.locator('option').evaluateAll(options => options.map(option => option.value));
    requireResult(row.before.domain === first && row.before.domain_id === first && row.before.selected === first
      && row.options.includes(second), 'existing_domain_filter');
    const [delivery] = await Promise.all([
      page.waitForResponse(response => {
        const url = new URL(response.url());
        return url.pathname === reportPath(key) && url.searchParams.get('domain') === second;
      }),
      selector.selectOption(second),
    ]);
    await page.waitForURL(current => current.searchParams.get('domain') === second && !current.searchParams.has('domain_id'));
    row.after = { ...scope(page.url()), selected: await selector.inputValue(), api: delivery.status() };
    row.request = scope(delivery.url());
    await photograph(page, 'computers-changed-domain');
    requireResult(row.after.domain === second && row.after.selected === second && row.after.domain_id === null
      && row.after.api === 200 && row.request.domain_id === null, 'replace_old_domain_alias');
  } finally {
    await page.close();
  }
}

try {
  console.log('BETA_README_EVIDENCE installed_chromium=' + browser.version());
  evidence.stage = 'clean_install';
  const domains = await api('/api/v1/domains');
  evidence.cleanDomains = { status: domains.status, count: domains.body.items?.length };
  requireResult(domains.status === 200 && domains.body.items?.length === 0, 'clean_install_required');

  evidence.stage = 'direct_domain';
  await checkDirect('domain');
  evidence.stage = 'direct_domain_id';
  await checkDirect('domain_id');
  evidence.stage = 'users_tab';
  await checkTab('ad.users.v2', 'all');
  evidence.stage = 'computers_tab';
  await checkTab('ad.computers.v6', 'computers');
  evidence.stage = 'select_other_domain';
  await checkSelection();
  evidence.stage = 'complete';
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
