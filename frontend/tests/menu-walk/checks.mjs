// Keep diagnostic output small and credential-free; never save response bodies.
export function redact(text, secrets = []) {
  let value = String(text);
  for (const secret of secrets.filter(Boolean)) value = value.split(secret).join('[redacted]');
  return value.replace(/(?:https?:\/\/)[^\s)]+/gi, '[url]')
    .replace(/\b(?:bearer\s+)?[a-f0-9]{48,}\b/gi, '[redacted]')
    .replace(/\b(password|token|code|cookie|authorization)\s*[:=]\s*\S+/gi, '$1=[redacted]')
    .slice(0, 300);
}

export function forbiddenLabels(text, reasons = []) {
  const patterns = [
    /\b(?:partial|stale|processing|not_collected|evidence|policy|snapshot|cohort|projection|baseline|API|JSON)\b/giu,
    /неполн[а-яё]*|полн[а-яё]*\s*[:—-]|покрыти[а-яё]*|не\s+оценено|нет\s+данных|неизвестно|название\s+недоступно|≥\s*0|когорт[а-яё]*|не\s+подтвержд[а-яё]*/giu,
    /\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b/gu,
  ];
  const found = patterns.flatMap(pattern => [...text.matchAll(pattern)].map(match => match[0]));
  for (const reason of reasons) if (reason && text.includes(reason)) found.push(reason);
  return [...new Set(found)];
}

export function loadErrors(text) {
  return [...new Set(text.split('\n').map(line => line.trim()).filter(line =>
    /не удалось (?:загрузить|получить|открыть)|ошибка (?:загрузки|получения)|failed to (?:load|fetch)|unable to load|something went wrong|доступ запрещ[её]н|access denied/i.test(line)))];
}

export async function waitForVisibleLoadingToFinish(page, timeout = 15_000) {
  const busy = page.locator('[aria-busy="true"]:visible').first();
  try {
    await busy.waitFor({ state: 'hidden', timeout });
    return true;
  } catch (error) {
    if (error.name !== 'TimeoutError') throw error;
    return false;
  }
}

export function markdown(rows) {
  const cell = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('[', '\\[').replaceAll(']', '\\]').replaceAll('|', '\\|').replaceAll('\n', ' ');
  return '| Пункт меню | Путь | Загрузился / что упало | Замечания по виду экрана |\n|---|---|---|---|\n'
    + rows.map(row => `| ${cell(row.label)} | ${cell(row.path)} | ${cell(row.failures.length ? row.failures.join('; ') : 'загрузился')} | ${cell([...row.labels.map(item => `${item.label} (${item.where})`), ...(row.appearance ?? [])].join('; ') || '—')} |`).join('\n') + '\n';
}
