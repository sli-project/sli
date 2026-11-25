import { chromium } from 'playwright-core';
import { X509Certificate, createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const results = process.argv[2];
const candidate = '6a454ca4abc8c6960eb5823748afd4848f3faddf';
const expectedMsi = 'f85c9b0df4faf37bd979b357925f780113ee0283dbc8690499c7039951fe2791';
const packageRoute = '/api/v1/agent/installer/SliAgent.msi';
const tokenRoute = '/api/v1/admin/agent-console-tokens';
const evidence = { commit: candidate, passed: false };
let browser;
try {
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  const { url, token, commit } = JSON.parse(input);
  const origin = new URL(url).origin;
  if (!origin.startsWith('https:') || commit !== candidate || !token) throw new Error('fixture');
  const root = new X509Certificate(await readFile('/var/lib/sli/tls-ca.crt'));
  const rootPin = createHash('sha256').update(root.raw).digest('hex');
  browser = await chromium.launch({ executablePath: '/usr/bin/chromium-headless-shell', timeout: 18_000 });
  const context = await browser.newContext({ locale: 'ru-RU', serviceWorkers: 'block' });
  await context.addInitScript(() => { localStorage.setItem('sli.locale', 'ru'); });
  await context.addCookies([{ name: 'adlog_session', value: token, url: origin, httpOnly: true, secure: true, sameSite: 'Strict' }]);
  let issues = 0;
  await context.route('**/*', route => {
    const request = route.request();
    const target = new URL(request.url());
    if (['data:', 'blob:'].includes(target.protocol)) return route.continue();
    if (target.origin !== origin) return route.abort('blockedbyclient');
    if (['GET', 'HEAD'].includes(request.method())) return route.continue();
    if (request.method() === 'POST' && target.pathname === tokenRoute && !target.search && issues === 0) {
      try {
        const body = request.postDataJSON();
        if (Object.keys(body).length === 3 && body.host_limit === 1 && body.manage_windows_audit === true
            && new URL(body.server_url).href === origin + '/') {
          issues += 1;
          return route.continue();
        }
      } catch {}
    }
    return route.abort('blockedbyclient');
  });
  const page = await context.newPage();
  const settings = page.waitForResponse(res => new URL(res.url()).pathname === tokenRoute + '/settings', { timeout: 9_000 });
  const [loaded] = await Promise.all([settings, page.goto(origin + '/app/agents?register=1', { waitUntil: 'domcontentloaded', timeout: 10_000 })]);
  const address = page.locator('#agent-console-server-url');
  const hostLimit = page.locator('#agent-console-limit');
  await address.waitFor({ state: 'visible', timeout: 7_000 });
  evidence.settings_http = loaded.status();
  evidence.origin_default = new URL(await address.inputValue()).href === origin + '/';
  evidence.one_host = (await hostLimit.inputValue()) === '1';
  if (!evidence.origin_default || !evidence.one_host || loaded.status() !== 200) throw new Error('settings');
  const issue = page.waitForResponse(res => new URL(res.url()).pathname === tokenRoute
      && res.request().method() === 'POST', { timeout: 10_000 });
  const [issued] = await Promise.all([issue, page.getByRole('button', { name: 'Создать команду', exact: true }).click({ timeout: 8_000 })]);
  evidence.issue_http = issued.status();
  if (evidence.issue_http < 200 || evidence.issue_http >= 300) throw new Error('issue');
  const commandField = page.locator('#agent-console-command');
  await commandField.waitFor({ state: 'visible', timeout: 7_000 });
  const command = await commandField.inputValue();
  const last = command.trimEnd().split('\n').at(-1);
  const args = [...last.matchAll(/'([^']*)'/g)].map(match => match[1]);
  const download = page.locator('a[href="' + packageRoute + '"]');
  evidence.command_fields = await commandField.count();
  evidence.issuances = issues;
  evidence.shape = command.startsWith('& {\n') && last.startsWith("} '") && args.length === 6;
  evidence.https_origin_match = evidence.shape && args[0] === origin + '/';
  evidence.ca_pin_match = evidence.shape && args[3] === rootPin
      && createHash('sha256').update(Buffer.from(args[2], 'base64')).digest('hex') === rootPin;
  evidence.msi_hash_match = evidence.shape && args[4] === expectedMsi;
  evidence.msi_version_match = evidence.shape && args[5] === '26.0.166';
  evidence.download_route_present = await download.count() >= 1;
  evidence.passed = evidence.command_fields === 1 && evidence.issuances === 1 && evidence.https_origin_match
      && evidence.ca_pin_match && evidence.msi_hash_match && evidence.msi_version_match && evidence.download_route_present;
} catch (error) {
  evidence.error = error.name === 'TimeoutError' ? 'timeout' : 'ui_or_fixture_error';
} finally {
  if (browser) await browser.close();
}
await writeFile(join(results, 'agent-ui.json'), JSON.stringify(evidence, null, 2));
console.log('BETA_README_EVIDENCE agent_command_ui=' + JSON.stringify(evidence));
if (!evidence.passed) process.exitCode = 1;
