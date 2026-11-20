// Standalone local dashboard; messages are exported from the product dictionaries.
export const REFRESH_MS = 30_000;
export const STALE_SECONDS = 20 * 60;
export function isStale(lastPass, now = Date.now()) {
  return !Number.isFinite(lastPass) || now / 1000 - lastPass > STALE_SECONDS;
}
export function selectRows(rows, filter, key, descending = false) {
  const query = filter.trim().toLocaleLowerCase('ru');
  return rows.filter(row => Object.values(row).some(value => String(value ?? '').toLocaleLowerCase('ru').includes(query)))
    .slice().sort((a, b) => {
      const first = a[key] ?? ''; const second = b[key] ?? '';
      const order = typeof first === 'number' && typeof second === 'number'
        ? first - second : String(first).localeCompare(String(second), 'ru', { numeric: true });
      return descending ? -order : order;
    });
}
export function safeLink(value) {
  return typeof value === 'string' && /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/pull\/\d+$/.test(value) ? value : null;
}
export function taskLabel(row, messages) {
  const title = row.title || '';
  const key = /agent_projection_failed|post-collection|projection failed/i.test(title) ? 'task.import'
    : /semantic heartbeat/i.test(title) ? 'task.securityQueue'
    : /отч[её]ты AD/i.test(title) ? 'task.directoryReports'
    : /[а-яё]/i.test(title) ? null : `kind.${row.kind ?? 'queue'}`;
  return key ? messages[key] ?? messages.unknown : title;
}
export function mount(root, messages, fetchData = () => fetch('data.json', { cache: 'no-store' }).then(response => {
  if (!response.ok) throw new Error('Snapshot unavailable');
  return response.json();
})) {
  let data; let error = false; let filter = ''; let pending = false;
  const sorts = {}; const expanded = new Set();
  const t = (key, params = {}) => (messages[key] ?? messages.unknown).replace(/\{(\w+)\}/g, (match, name) => String(params[name] ?? match));
  const el = (tag, text, className) => { const node = document.createElement(tag); if (text != null) node.textContent = text; if (className) node.className = className; return node; };
  const date = value => Number.isFinite(value) ? new Date(value * 1000).toLocaleString('ru-RU') : t('unknown');
  const duration = value => {
    if (!Number.isFinite(value)) return t('unknown');
    const minutes = Math.max(0, Math.floor((Date.now() / 1000 - value) / 60));
    return minutes < 60 ? t('minutes', { value: minutes }) : t('hours', { value: Math.floor(minutes / 60), minutes: minutes % 60 });
  };
  const prLink = (number, url) => { const target = safeLink(url); const node = el(target ? 'a' : 'span', number ? `#${number}` : t('unknown')); if (target) { node.href = target; node.target = '_blank'; node.rel = 'noopener noreferrer'; } return node; };
  const heading = el('header'); heading.append(el('h1', t('title')), el('p', t('subtitle'), 'muted'));
  const alert = el('div'); alert.setAttribute('role', 'status');
  const stats = el('div', null, 'stats');
  const label = el('label', t('filter')); label.htmlFor = 'filter';
  const input = el('input'); input.id = 'filter'; input.type = 'search';
  const content = el('div'); root.replaceChildren(heading, alert, stats, label, input, content);
  document.title = t('title');
  function table(id, rows, columns, unavailable = false) {
    const section = el('section'); section.append(el('h2', t(id)));
    if (unavailable) { section.append(el('p', t(id === 'reports' ? 'noReports' : 'unavailable'), 'muted')); content.append(section); return; }
    const [key, descending] = sorts[id] ?? [columns[0][0], id === 'history'];
    const translated = rows.map(row => ({ ...row, ...Object.fromEntries(columns.filter(column => column[2] === 'translate').map(([field]) => [field, t(row[field] ?? 'unknown')])) }));
    const selected = selectRows(translated, filter, key, descending);
    const element = el('table'); const head = el('thead'); const headRow = el('tr');
    for (const [field, title] of columns) {
      const cell = el('th'); cell.scope = 'col'; cell.setAttribute('aria-sort', field === key ? descending ? 'descending' : 'ascending' : 'none');
      const button = el('button', `${t(title)}${field === key ? descending ? ' ↓' : ' ↑' : ''}`); button.type = 'button'; button.setAttribute('aria-label', t('sort', { name: t(title) }));
      button.onclick = () => { sorts[id] = [field, field === key ? !descending : false]; render(); }; cell.append(button); headRow.append(cell);
    }
    head.append(headRow); element.append(head); const body = el('tbody');
    for (const row of selected) {
      const tr = el('tr');
      for (const [field, title, format] of columns) {
        const td = el('td'); td.dataset.label = t(title);
        if (field === 'number' || field === 'pr') td.append(prLink(row[field], row.url));
        else td.append(el('span', format === 'date' ? date(row[field]) : format === 'duration' ? duration(row[field]) : row[field] || (row[field] === 0 ? '0' : t('unknown'))));
        if (id === 'jobs' && field === 'title') {
          const detail = el('details'); const identity = `${row.started_at}:${row.pr}:${row.title}`; detail.open = expanded.has(identity);
          detail.addEventListener('toggle', () => { if (detail.open) expanded.add(identity); else expanded.delete(identity); });
          detail.append(el('summary', t('journal')), el('p', t('journalNote'), 'log-note')); const list = el('ol');
          for (const line of row.logs ?? []) list.append(el('li', t(line))); detail.append(list); if (!row.logs?.length) detail.append(el('p', t('unavailable'))); td.append(detail);
        }
        tr.append(td);
      }
      body.append(tr);
    }
    element.append(body); section.append(element); if (!selected.length) section.append(el('p', t(id === 'reports' && !rows.length ? 'reportsEmpty' : 'empty'), 'muted')); content.append(section);
  }
  function render() {
    alert.replaceChildren(); if (error) alert.append(el('p', t('loadError'), 'banner error'));
    if (!data) { content.replaceChildren(el('p', t('loading'))); return; }
    root.setAttribute('aria-busy', 'false');
    if (isStale(data.last_pass)) alert.append(el('p', t('stale'), 'banner error'));
    if (data.dry_run) alert.append(el('p', t('dry'), 'banner'));
    if (data.network === 'offline') alert.append(el('p', t('networkOffline'), 'banner error'));
    stats.replaceChildren();
    const items = [['lastPass', date(data.last_pass), isStale(data.last_pass) ? 'stale' : 'fresh'], ['sli', t(data.sli?.health ?? 'unknown')], ['version', data.sli?.commit?.slice(0, 12) || t('unknown')], ['update', t(data.update ?? 'unknown')]];
    for (const [name, value, note] of items) { const box = el('div', null, 'stat'); box.append(el('span', t(name), 'muted'), el('strong', value)); if (note) box.append(el('span', t(note), isStale(data.last_pass) ? 'error' : 'good')); if (name === 'version') box.append(prLink(data.sli?.pr, data.sli?.url)); stats.append(box); }
    content.replaceChildren();
    table('jobs', (data.jobs ?? []).map(row => ({ ...row, title: taskLabel(row, messages), duration: row.started_at })), [['title', 'task'], ['started_at', 'started', 'date'], ['duration', 'duration', 'duration'], ['pr', 'prs']]);
    table('queue', (data.queue ?? []).map(row => ({ ...row, title: taskLabel(row, messages) })), [['title', 'task']]);
    table('prs', data.prs ?? [], [['number', 'number'], ['title', 'name'], ['ci', 'ci', 'translate'], ['conflict', 'conflict', 'translate'], ['attempts', 'attempts'], ['action', 'action', 'translate']], !data.prs_available);
    table('reports', data.reports ?? [], [['title', 'name'], ['rows', 'rows'], ['freshness', 'freshness']], !data.reports_available);
    table('history', data.history ?? [], [['time', 'time', 'date'], ['code', 'event', 'translate']]);
  }
  input.addEventListener('input', () => { filter = input.value; render(); });
  async function refresh() {
    if (pending) return; pending = true;
    try { const next = await fetchData(); if (next.schema_version !== 1 || !Number.isFinite(next.last_pass)) throw new Error('Invalid snapshot'); data = next; error = false; }
    catch { error = true; }
    finally { pending = false; render(); }
  }
  render(); void refresh(); const timer = setInterval(refresh, REFRESH_MS);
  return { refresh, destroy: () => clearInterval(timer) };
}
if (typeof document !== 'undefined' && document.getElementById('dashboard')) {
  fetch('ru.json', { cache: 'no-store' }).then(response => { if (!response.ok) throw new Error('Messages unavailable'); return response.json(); })
    .then(messages => mount(document.getElementById('dashboard'), messages)).catch(() => { document.getElementById('dashboard').textContent = 'SLI — ⚠'; });
}
