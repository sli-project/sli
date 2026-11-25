import { chromium } from 'playwright-core';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { forbiddenLabels, loadErrors, redact } from './checks.mjs';

let input = '';
for await (const chunk of process.stdin) input += chunk;
const { url, token, commit } = JSON.parse(input);
const origin = new URL(url).origin;
const results = process.argv[2];
if (!/^https:/.test(origin) || !token || !results || commit !== 'fa8baf797ca0f0bcd62574aebf551e3aef1e6638') {
  throw new Error('Expected a verified guest HTTPS origin and an owner session');
}
const registry = JSON.parse(await readFile(new URL('./navigation_v3.json', import.meta.url), 'utf8'));
const all = registry.sections.flatMap(section => section.groups.flatMap(group =>
  group.entries.map(entry => ({ ...entry, administration: ['admin', 'operations'].includes(section.id) }))));
const selectedKeys = registry.beta_entries.filter(id => id === "file-audit");
const entries = selectedKeys.map(id => {
  const entry = all.find(item => item.id === id);
  if (!entry || !/^[a-z][a-z-]+$/.test(id)) throw new Error('Invalid beta navigation declaration');
  return { ...entry, path: entry.path === '/admin/language-time' ? '/settings' : entry.path };
});
const base = new URL('/app/', origin).href;
const targetPath = path => new URL('app' + path, origin).pathname.replace(/\/$/, '');
const nav = '.sli-ds-shell__nav';
const clean = value => redact(value, [token]).replace(/[A-Za-z0-9+_/-]{38,}(?:={1,2})?/g, '[redacted]');
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
  if (target.origin === origin && request.method() === 'POST' && !target.search) {
    if (readStatusPosts.has(target.pathname)
        && (request.postData() === null || /^\{\s*\}$/.test(request.postData().trim()))) return route.continue();
    if (allowVpnToggle && target.pathname === vpnPlugin) {
      try {
        const body = request.postDataJSON();
        if (body.enabled === true && Number.isSafeInteger(body.expected_revision) && body.expected_revision > 0
            && Object.keys(body).length === 2) return route.continue();
      } catch {}
    }
  }
  if (activeRow && target.origin === origin) activeRow.blocked.push(request.method() + ' ' + target.pathname);
  return route.abort('blockedbyclient');
});

const readStatusPosts = new Set([
  '/api/v1/notification-channels/smtp/setup/status',
  '/api/v1/notification-channels/telegram/setup/status',
]);
const vpnPlugin = '/api/v1/plugins/sli.remote-access';
const adminVpnPage = '/app/admin/plugins/sli.remote-access';
let allowVpnToggle = false;
const vpn = { defaultVisible: null, activation: 'not_examined' };
const seen = new Set();

async function menuLinks(page) {
  const result = await page.locator(nav + ' a[data-route]').evaluateAll(nodes => nodes.map(node => ({
    route: node.dataset.route, path: new URL(node.href).pathname.replace(/\/$/, ''), label: node.innerText.trim(),
  })));
  for (const link of result) {
    if (!['administration', 'back-to-work'].includes(link.route)) seen.add(link.path);
  }
  return result;
}

async function vpnPreflight() {
  const page = await context.newPage();
  const expected = '/app/report/vpn.connections';
  try {
    await page.goto(base, { waitUntil: 'domcontentloaded' });
    await page.locator(nav + ' a[data-route="workspace"]').waitFor();
    await page.waitForLoadState('networkidle', { timeout: 12_000 }).catch(() => {});
    vpn.defaultVisible = (await menuLinks(page)).some(link => link.path === expected);
    if (vpn.defaultVisible) {
      vpn.activation = 'already_in_menu';
      return;
    }
    const url = new URL('/api/v1/plugins', origin);
    const response = await context.request.get(url.href);
    vpn.catalogStatus = response.status();
    if (!response.ok()) {
      vpn.activation = 'catalog_unavailable';
      return;
    }
    const body = await response.json();
    const state = body.items?.find(item => item.plugin_id === 'sli.remote-access');
    vpn.state = state && {
      installed: state.installed === true, configured: state.configured === true,
      enabled: state.enabled === true, runtime: /^[a-z_]{1,24}$/.test(state.component_runtime)
        ? state.component_runtime : null, canManage: body.can_manage === true,
    };
    await page.goto(new URL(adminVpnPage, origin).href, { waitUntil: 'domcontentloaded' });
    const main = page.locator('main').first();
    await main.waitFor({ state: 'visible' });
    await page.waitForLoadState('networkidle', { timeout: 12_000 }).catch(() => {});
    const control = main.getByRole('switch').first();
    vpn.switchVisible = await control.count() > 0 && await control.isVisible();
    vpn.switchEnabled = vpn.switchVisible && await control.isEnabled();
    const sensitive = page.locator('input, textarea, pre, code, [data-secret], [data-token]');
    await page.screenshot({ path: join(results, 'vpn-default-control.png'), mask: [sensitive], timeout: 12_000 });
    if (!vpn.state?.installed || !vpn.state.configured || vpn.state.enabled || !vpn.switchEnabled) {
      vpn.activation = 'native_precondition_unavailable';
      return;
    }
    allowVpnToggle = true;
    const [toggle] = await Promise.all([
      page.waitForResponse(item => {
        const target = new URL(item.url());
        return target.pathname === vpnPlugin && item.request().method() === 'POST';
      }),
      control.click(),
    ]);
    vpn.toggleStatus = toggle.status();
    if (toggle.ok()) {
      const confirmed = await context.request.get(url.href);
      const activeState = confirmed.ok() ? (await confirmed.json()).items?.find(item => item.plugin_id === 'sli.remote-access') : null;
      vpn.afterToggle = { status: confirmed.status(), enabled: activeState?.enabled === true, runtime: activeState?.component_runtime ?? null };
      vpn.activation = vpn.afterToggle.enabled && vpn.afterToggle.runtime === 'running' ? 'enabled_in_guest' : 'state_not_running';
    } else {
      const error = await toggle.json().catch(() => ({}));
      vpn.toggleReason = /^[a-z_]{1,80}$/.test(error.error) ? error.error : null;
      vpn.activation = 'enable_rejected';
    }
  } catch (error) {
    vpn.activation = 'probe_failed';
    vpn.probeError = clean(String(error.message).split('\n')[0]);
  } finally {
    allowVpnToggle = false;
    await page.close();
  }
}

const targetUrl = '/app/report/file-audit.overview';
const endpoints = new Map([
  ['/api/v2/reports/file-audit.overview/data', 'data'],
  ['/api/v1/admin/agents', 'agents'],
]);
const states = new Set(['ok', 'ready', 'empty', 'not_collected', 'partial', 'processing', 'stale', 'denied', 'error']);
const pluginStates = new Set(['enabled', 'disabled', 'unknown']);
const observation = { commit, target: targetUrl, requests: { data: [], agents: [] }, snapshots: {} };
const page = await context.newPage();
const main = page.locator('main').first();
const requests = new WeakMap();
const completed = {};
let clickAt;
let finishBoth;
const both = new Promise(resolve => { finishBoth = resolve; });
const elapsed = () => Math.round(performance.now() - clickAt);

function summarize(kind, body) {
  if (kind === 'data') return {
    state: states.has(body.state) ? body.state : null,
    items: Array.isArray(body.items) ? body.items.length : null,
    access_allowed: typeof body.access?.allowed === 'boolean' ? body.access.allowed : null,
    plugin_state: pluginStates.has(body.plugin?.state) ? body.plugin.state : null,
    plugin_read_only: typeof body.plugin?.read_only === 'boolean' ? body.plugin.read_only : null,
  };
  if (!Array.isArray(body.items) || body.items.some(agent => !Array.isArray(agent.assigned_modules))) {
    return { agents: null, assigned_file_audit: null };
  }
  return {
    agents: body.items.length,
    assigned_file_audit: body.items.filter(agent => agent.assigned_modules.some(module =>
      (typeof module === 'string' ? module : module?.module_id) === 'sli.file-audit')).length,
  };
}

const selector = '[data-state="empty"] a[href="/app/admin/plugins/sli.file-audit"]';
async function snapshot() {
  const value = await main.evaluate((root, path) => {
    const links = [...root.querySelectorAll(path)].filter(link => link.getClientRects().length > 0
      && getComputedStyle(link).visibility === 'visible' && link.textContent.trim() === 'Настроить');
    return {
      cta_count: links.length, no_sources: root.innerText.includes('Источники ещё не подключены'),
      report_title: root.innerText.includes('Аудит файловых серверов MS'), denied: /^Нет доступа$/m.test(root.innerText),
    };
  }, selector);
  return { ms: elapsed(), ...value };
}

async function beforeDeadline(promise, milliseconds) {
  let timer;
  try {
    return await Promise.race([promise, new Promise(resolve => {
      timer = setTimeout(() => resolve(false), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

page.on('request', request => {
  const url = new URL(request.url());
  const kind = endpoints.get(url.pathname);
  if (clickAt === undefined || request.method() !== 'GET' || url.origin !== origin || !kind) return;
  const record = { started_ms: elapsed() };
  observation.requests[kind].push(record);
  requests.set(request, { kind, record });
});
page.on('response', async response => {
  const request = requests.get(response.request());
  if (!request) return;
  const { kind, record } = request;
  record.headers_ms = elapsed();
  record.http = response.status();
  try {
    if (await response.finished()) {
      record.body = 'failed';
      return;
    }
    record.body_ms = elapsed();
    record.fields = summarize(kind, await response.json());
    record.json_ms = elapsed();
    record.body = 'settled';
    if (record.http === 200) completed[kind] = record;
    if (completed.data && completed.agents) finishBoth(true);
  } catch { record.body = 'unreadable'; }
});
page.on('requestfailed', request => {
  const observed = requests.get(request);
  if (observed) observed.record.failed_ms = elapsed();
});

try {
  if (entries.length !== 1 || targetPath(entries[0].path) !== targetUrl) throw new Error('Unexpected entry');
  await vpnPreflight();
  observation.vpn = vpn.activation;
  if (vpn.activation !== 'enabled_in_guest') throw new Error('VPN preparation not confirmed');
  const network = { blocked: [] };
  activeRow = network;
  await page.goto(base, { waitUntil: 'domcontentloaded' });
  await page.locator(nav + ' a[data-route="workspace"]').waitFor({ timeout: 7_000 });
  await page.waitForLoadState('networkidle', { timeout: 4_000 }).catch(() => {});
  const link = (await menuLinks(page)).find(item => item.path === targetUrl);
  if (!link) throw new Error('File Audit menu entry missing');
  clickAt = performance.now();
  await page.locator(nav + ' a[data-route=' + JSON.stringify(link.route) + ']').click({ timeout: 6_000 });
  await page.waitForURL(current => current.pathname === targetUrl, { timeout: 6_000 });
  await main.waitFor({ state: 'visible', timeout: 6_000 });
  observation.snapshots.first = await snapshot();
  await page.waitForLoadState('networkidle', { timeout: 4_000 }).catch(() => {});
  observation.snapshots.after_network_idle = await snapshot();
  observation.explicit_responses_settled = await beforeDeadline(both, 6_000);
  observation.snapshots.after_bodies = await snapshot();
  try {
    await page.waitForFunction(path => {
      const main = document.querySelector('main');
      if (!main) return false;
      const links = [...main.querySelectorAll(path)].filter(link => link.getClientRects().length > 0
        && getComputedStyle(link).visibility === 'visible' && link.textContent.trim() === 'Настроить');
      return links.length === 1 && main.innerText.includes('Источники ещё не подключены');
    }, selector, { timeout: 6_000 });
    observation.render_wait = 'matched';
  } catch (error) {
    observation.render_wait = error.name === 'TimeoutError' ? 'timeout' : 'failed';
  }
  const final = await snapshot();
  observation.snapshots.final = final;
  const visible = await main.innerText();
  observation.final_load_errors = loadErrors(visible).length;
  observation.blocked_same_origin = network.blocked.length;
  observation.final_completeness_labels = forbiddenLabels(visible, []).length;
  const mask = page.locator('input, textarea, pre, code, [data-secret], [data-token]');
  await page.screenshot({ path: join(results, 'file-audit.png'), mask, timeout: 6_000 });
  observation.passed = observation.explicit_responses_settled && observation.render_wait === 'matched'
    && completed.data.fields.state === 'not_collected' && completed.data.fields.items === 0
    && completed.agents.fields.assigned_file_audit === 0 && final.cta_count === 1
    && final.no_sources && final.report_title && !final.denied
    && observation.final_load_errors === 0 && observation.blocked_same_origin === 0
    && observation.final_completeness_labels === 0;
} catch (error) {
  observation.failed = error.name === 'TimeoutError' ? 'timeout' : 'precondition_or_browser_error';
} finally { await browser.close(); }
await writeFile(join(results, 'menu.json'), JSON.stringify(observation, null, 2));
console.log('BETA_README_EVIDENCE file_audit_observation=' + JSON.stringify(observation));
if (observation.passed !== true) process.exitCode = 1;
