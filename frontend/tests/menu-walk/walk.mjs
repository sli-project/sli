import { chromium } from '@playwright/test';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { forbiddenLabels, loadErrors, markdown, redact, waitForVisibleLoadingToFinish } from './checks.mjs';
import { walkFileServers } from './file-servers.mjs';
import { walkWorkstations } from './workstations.mjs';

let input = '';
for await (const chunk of process.stdin) input += chunk;
const { url: betaUrl, preview_url: previewUrl, token, results, file_servers: fileServers, workstations } = JSON.parse(input);
for (const url of [betaUrl, previewUrl]) {
  if (!new URL(url).hostname.match(/^(127\.0\.0\.1|localhost|\[::1\])$/)) throw new Error('Owned loopback host required');
}
const registry = JSON.parse(await readFile(new URL('../../../config/navigation_v3.json', import.meta.url), 'utf8'));
const all = registry.sections.flatMap(section => section.groups.flatMap(group => group.entries));
function destination(id, url) {
  const entry = all.find(item => item.id === id);
  if (!entry) throw new Error(`Missing navigation declaration: ${id}`);
  return { ...entry, url, path: entry.path === '/admin/language-time' ? '/settings' : entry.path };
}
const previewEntries = registry.preview_entries.map(id => destination(id, previewUrl));
const betaEntries = registry.beta_entries.map(id => destination(id, betaUrl));
for (const id of ['file-audit', 'workstations-overview']) {
  if (!betaEntries.some(entry => entry.id === id)) throw new Error(`Missing default destination for fixture: ${id}`);
}
const allEntries = [...betaEntries, ...previewEntries];
const focus = process.env.SLI_MENU_WALK_ONLY;
const entries = focus ? allEntries.filter(entry => entry.id === focus) : allEntries;
if (!entries.length) throw new Error('Unknown menu destination');
await mkdir(results, { recursive: true });
const browser = await chromium.launch({ executablePath: process.env.SLI_TEST_CHROMIUM_EXECUTABLE_PATH, timeout: 0 });
const rows = [];
const clean = value => redact(value, [token]);
try {
  for (const entry of entries) {
    const { url } = entry;
    const row = { id: entry.id, label: entry.id, path: entry.path, failures: [], api: [], console: [], labels: [], appearance: [] };
    rows.push(row);
    console.log(`menu-walk: ${entry.id} ${entry.path}`);
    const heartbeat = setInterval(() => console.log(`menu-walk: waiting ${entry.id}`), 10_000);
    const context = await browser.newContext({ locale: 'ru-RU', timezoneId: 'UTC', viewport: entry.id === "file-audit" ? { width: 1920, height: 1080 } : { width: 1440, height: 900 }, serviceWorkers: 'block' });
    context.setDefaultTimeout(0);
    context.setDefaultNavigationTimeout(0);
    await context.addCookies([{ name: 'adlog_session', value: token, url, httpOnly: true, sameSite: 'Strict' }]);
    await context.addInitScript(theme => { localStorage.setItem('sli.locale', 'ru'); localStorage.setItem('sli.theme', theme); },
      entry.id === 'file-audit' ? 'dark' : 'light');
    // Fixture navigation is read-only; never permit accidental external access.
    await context.route('**/*', route => {
      const target = new URL(route.request().url());
      return target.origin === new URL(url).origin || ['data:', 'blob:'].includes(target.protocol)
        ? route.continue() : route.abort('blockedbyclient');
    });
    const page = await context.newPage();
    const reasons = new Set();
    const pending = new Set();
    page.on('response', response => {
      const request = response.request();
      const path = new URL(response.url()).pathname;
      if (path.startsWith('/api/') && response.status() >= 400) row.api.push(`${request.method()} ${path} → ${response.status()}`);
      if (!path.startsWith('/api/') && response.status() >= 400) row.failures.push(`${path} → ${response.status()}`);
      if (path.startsWith('/api/') && response.headers()['content-type']?.includes('json')) {
        const task = response.json().then(body => {
          const visit = node => {
            if (!node || typeof node !== 'object') return;
            for (const [key, value] of Object.entries(node)) {
              if (['reason', 'reason_code'].includes(key) && typeof value === 'string') reasons.add(value);
              else if (typeof value === 'object') visit(value);
            }
          };
          visit(body);
        }).catch(() => {}).finally(() => pending.delete(task));
        pending.add(task);
      }
    });
    page.on('requestfailed', request => row.failures.push(`${request.method()} ${new URL(request.url()).pathname} → ${clean(request.failure()?.errorText)}`));
    page.on('console', message => { if (message.type() === 'error') row.console.push(clean(message.text())); });
    page.on('pageerror', error => row.console.push(clean(error.message)));
    try {
      const target = new URL(`app${entry.path}`, url).href;
      await page.goto(target);
      await page.waitForLoadState('networkidle');
      await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      if (!await waitForVisibleLoadingToFinish(page)) row.failures.push('Загрузка не завершилась после ответов API');
      await Promise.all([...pending]);
      const link = page.locator('.sli-ds-shell__nav a').filter({ hasText: /./ });
      const links = await link.evaluateAll(nodes => nodes.map(node => ({ path: new URL(node.href).pathname, label: node.innerText })));
      const match = links.find(item => item.path.replace(/\/$/, '') === new URL(target).pathname.replace(/\/$/, ''));
      if (!match) row.failures.push('Пункт отсутствует в меню владельца');
      else row.label = match.label;
      if (url === betaUrl) {
        for (const preview of previewEntries) {
          if (links.some(item => item.path.replace(/\/$/, '') === `/app${preview.path}`))
            row.failures.push(`Preview destination in the default beta menu: ${preview.id}`);
        }
      }
      if (new URL(page.url()).pathname.replace(/\/$/, '') !== new URL(target).pathname.replace(/\/$/, '')) row.failures.push('Перенаправление вместо страницы');
      const main = page.locator('main');
      if (!await main.count()) throw new Error('На странице нет рабочего экрана (main)');
      const text = await main.innerText();
      if (!text.trim()) row.failures.push('Пустой экран');
      if (await main.locator('table:visible, .sli-ds-review-list:visible').count()
        && !await main.locator('tbody td:not([colspan]):visible, .sli-ds-review-list__item:visible').count()
        && !/(?:нет|добав|подключ|запуст|спокойно|не найден)/i.test(text)) row.appearance.push('Пустая таблица без следующего шага');
      const visibleText = await page.locator('body').innerText();
      row.failures.push(...loadErrors(visibleText).map(clean));
      const leaves = await page.locator('body *').evaluateAll(nodes => nodes
        .filter(node => node.getClientRects().length && !['SCRIPT', 'STYLE'].includes(node.tagName))
        .filter(node => ![...node.children].some(child => child.getClientRects().length && child.textContent?.trim()))
        .map(node => ({ text: node.innerText || '', where: `${node.tagName.toLowerCase()}${node.className && typeof node.className === 'string' ? '.' + node.className.trim().split(/\s+/).join('.') : ''}` })));
      row.labels = leaves.flatMap(leaf => forbiddenLabels(leaf.text, [...reasons]).map(label => ({ label: clean(label), where: leaf.where })));
      // A phrase may be split across child nodes. Keep those matches visible too.
      for (const label of forbiddenLabels(visibleText, [...reasons])) if (!row.labels.some(item => item.label === clean(label))) row.labels.push({ label: clean(label), where: 'body' });
      if (!focus) await page.screenshot({ path: join(results, `${entry.id}.png`), fullPage: true });
      if (entry.id === 'file-audit') await walkFileServers(page, { url, results, fixture: fileServers });
      if (entry.id === 'workstations-overview') await walkWorkstations(page, { url, results, fixture: workstations });
    } catch (error) { row.failures.push(clean(error.message)); }
    finally {
      clearInterval(heartbeat);
      await context.close();
      row.api = [...new Set(row.api)]; row.console = [...new Set(row.console)];
      row.failures = [...new Set([...row.failures, ...row.api, ...row.console])];
      if (!focus) {
        await writeFile(join(results, 'menu-walk.json'), JSON.stringify(rows, null, 2));
        await writeFile(join(results, 'menu-walk.md'), markdown(rows));
      }
    }
  }
} finally { await browser.close(); }
console.log(markdown(rows));
// Appearance is reported separately, as screen changes are outside this task.
process.exitCode = rows.some(row => row.failures.length) ? 1 : 0;
