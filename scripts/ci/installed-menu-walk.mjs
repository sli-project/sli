import { chromium } from 'playwright-core';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { forbiddenLabels, loadErrors, redact, waitForVisibleLoadingToFinish } from './checks.mjs';

let input = '';
for await (const chunk of process.stdin) input += chunk;
const { url, token, commit } = JSON.parse(input);
const origin = new URL(url).origin;
const results = process.argv[2];
if (!/^https:/.test(origin) || !token || !results || commit !== '4bc007843aab81272eb56387de1723182bad9c13') {
  throw new Error('Expected a verified guest HTTPS origin and an owner session');
}
const registry = JSON.parse(await readFile(new URL('./navigation_v3.json', import.meta.url), 'utf8'));
const all = registry.sections.flatMap(section => section.groups.flatMap(group =>
  group.entries.map(entry => ({ ...entry, administration: ['admin', 'operations'].includes(section.id) }))));
const phase = process.env.SLI_MENU_PHASE;
if (!["clean", "full"].includes(phase)) throw new Error("Missing menu phase");
const cleanTargets = new Set(["problems", "events", "gpo-report", "file-audit"]);
const selectedKeys = phase === "clean" ? registry.beta_entries.filter(key => cleanTargets.has(key)) : registry.beta_entries;
const entries = selectedKeys.map(id => {
  const entry = all.find(item => item.id === id);
  if (!entry || !/^[a-z][a-z-]+$/.test(id)) throw new Error('Invalid beta navigation declaration');
  return { ...entry, path: entry.path === '/admin/language-time' ? '/settings' : entry.path };
});
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
const agentForm = '/app/agents?register=1';
const rows = [];
let allowVpnToggle = false;
const vpn = { defaultVisible: null, activation: 'not_examined' };
const seen = new Set();
let home = null;

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

async function inspectOutcome(main, row, visible) {
  const samples = await main.locator('tbody tr:visible').evaluateAll(trs => trs
    .map(tr => [...tr.querySelectorAll('td:not([colspan])')].map(td => td.innerText.trim()))
    .filter(cells => cells.some(cell => cell && !/^[—–-]+$/.test(cell))));
  const listItems = await main.locator('.sli-ds-review-list__item:visible').count();
  const dataEvidence = [];
  if (samples.length) dataEvidence.push({ kind: 'rendered_table_rows', count: samples.length });
  if (listItems) dataEvidence.push({ kind: 'rendered_review_items', count: listItems });
  if (row.id === 'admin-locale' && /^admin\s*·\s*\S+/im.test(visible)) {
    dataEvidence.push({ kind: 'signed_in_owner_profile', count: 1 });
  }
  if (row.id === 'plugins' && row.responses.some(response => response.path === '/api/v1/plugins' && response.status === 200)
      && /^Установлен$/m.test(visible) && /^Версия$/m.test(visible)) {
    dataEvidence.push({ kind: 'rendered_plugin_registry', count: 1 });
  }
  if (row.id.startsWith('admin-plugin-') && row.responses.some(response => response.path === '/api/v1/plugins' && response.status === 200)
      && /^(?:Работает|Остановлен|Плагин выключен)$/m.test(visible)) {
    dataEvidence.push({ kind: 'rendered_plugin_runtime_state', count: 1 });
  }
  row.dataEvidence = dataEvidence;
  const exact = await main.locator('a[href="' + agentForm + '"]:visible').count();
  const emptyActions = await main.locator('[data-state="empty"]:visible').evaluateAll(states => states.flatMap(state => {
    const eligible = text => /^(?:подключите|добавьте|настройте|выберите|укажите|откройте|запустите|перейдите|очистите|измените|проверьте|установите|включите|создайте)\s/i.test(text);
    const links = [...state.querySelectorAll('a[href], button')].filter(element =>
      element.getClientRects().length > 0 && !element.disabled && element.getAttribute('aria-disabled') !== 'true')
      .map(element => element.innerText.trim()).filter(Boolean);
    // A linked button and its explanatory copy are evidence of the same action.
    if (links.length) return links;
    return [...state.querySelectorAll('.sli-ds-state__detail, .sli-ds-state__text')]
      .map(element => element.innerText.trim()).filter(eligible);
  }));
  const actions = exact ? ['Добавить агента'] : emptyActions;
  row.enrollmentLinks = exact;
  if (row.id === 'agents' && /Агентов нет\.\s*Добавьте агента/.test(visible)
      && row.controls.includes('Добавить агента')) actions.push('Добавить агента');
  row.actions = [...new Set(actions.map(clean))];
}

try {
  console.log('BETA_README_EVIDENCE installed_chromium=' + browser.version());
  if (phase === 'full') await vpnPreflight();
  for (const entry of entries) {
    const expected = targetPath(entry.path);
    const row = { id: entry.id, path: expected, commit, clicked: false, failure: [], labels: [], api: [], blocked: [], text: [], responses: [], actions: [], dataEvidence: [] };
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
      if (path.startsWith('/api/')) row.responses.push({ path, method: response.request().method(), status });
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
      if (checkDestination && message.type() === 'error' && !message.text().includes('ERR_BLOCKED_BY_CLIENT')) row.failure.push(clean(message.text()));
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
        row.navigation = 'hidden';
        row.failure.push('Пункт отсутствует в меню владельца');
        continue;
      }
      await page.waitForURL(current => current.pathname.replace(/\/$/, '') === expected, { timeout: 8_000 })
        .catch(() => row.failure.push('Перенаправление вместо страницы: ' + new URL(page.url()).pathname));
      const main = page.locator('main').first();
      await main.waitFor({ state: 'visible' });
      await page.waitForLoadState('networkidle', { timeout: 12_000 }).catch(() => {});
      await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      if (!await waitForVisibleLoadingToFinish(page)) row.failure.push('Загрузка не завершилась после ответов API');
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
      await inspectOutcome(main, row, visible);
      row.navigation = 'clicked';
      row.labels = forbiddenLabels(visible, [...reasonCodes]).map(clean);
      row.failure.push(...loadErrors(visible).map(clean));
      if (/^Нет доступа$/m.test(visible)) row.failure.push('Нет доступа');
      const sensitive = page.locator('input, textarea, pre, code, [data-secret], [data-token]');
      await page.screenshot({ path: join(results, entry.id + '.png'), fullPage: false, mask: [sensitive], timeout: 12_000 });
    } catch (error) {
      row.failure.push(clean(String(error.message).split('\n')[0]));
    } finally {
      for (const key of ['failure', 'api', 'blocked', 'labels']) row[key] = [...new Set(row[key])];
      row.load_errors = row.failure.length + row.api.length + row.blocked.length;
      row.completeness_labels = row.labels.length;
      row.data = row.dataEvidence.length > 0;
      row.action_phrases = row.actions.length;
      row.passed = row.clicked && row.load_errors === 0 && row.completeness_labels === 0
        && (row.data || row.action_phrases === 1);
      await page.close();
      await writeFile(join(results, 'menu.json'), JSON.stringify({ commit, home, menuPaths: [...seen], rows }, null, 2));
      const details = { phase, id: row.id, path: row.path, commit: row.commit, clicked: row.clicked,
        data: row.data, dataEvidence: row.dataEvidence, action_phrases: row.action_phrases, actions: row.actions,
        load_errors: row.load_errors, completeness_labels: row.completeness_labels, failure: row.failure,
        api: row.api, blocked: row.blocked, labels: row.labels, passed: row.passed };
      console.log('BETA_README_EVIDENCE menu_row=' + JSON.stringify(details));
    }
  }
} finally { await browser.close(); }
const expected = new Set(entries.map(entry => targetPath(entry.path)));
const unexpected = phase === 'full' ? [...seen].filter(path => !expected.has(path)) : [];
const pages = Object.fromEntries(rows.map(row => [row.id, {
  load_errors: row.load_errors, completeness_labels: row.completeness_labels,
  data: row.data, action_phrases: row.action_phrases,
}]));
const failed = rows.filter(row => !row.passed).map(row => row.id);
const summary = { commit, visited: rows.length, clicked: rows.filter(row => row.clicked).length,
  phase, expectedKeys: selectedKeys, failed, unexpected, vpn, home };
await writeFile(join(results, 'menu.json'), JSON.stringify({ commit, pages, summary, rows }, null, 2));
console.log('BETA_README_EVIDENCE menu_summary=' + JSON.stringify(summary));
if (rows.length !== selectedKeys.length || failed.length || unexpected.length || (phase === 'full' && vpn.activation !== 'enabled_in_guest')) process.exitCode = 1;
