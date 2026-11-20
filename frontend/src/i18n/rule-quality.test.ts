// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { localeRuntime, setLocale, t } from './index';
import { localizeReportResult } from './report-metadata';
import type { ReportResultDto } from '../api/report-v2-types';

beforeEach(() => { vi.spyOn(localeRuntime, 'reload').mockImplementation(() => undefined); });
afterEach(() => { setLocale('ru'); vi.restoreAllMocks(); });
it.each(['ru', 'en'] as const)('resolves rule labels without rewriting identity or unknown metrics in %s', (locale) => {
  setLocale(locale);
  const rules = [
    ['semantic.qw.file-ransom', 'file_ransom'],
    ['semantic.security.audit_controls_changed', 'audit_controls_changed'],
    ['semantic.security.privileged_group_member_added', 'privileged_group_member_added'],
    ['semantic.security.scheduled_task_created', 'scheduled_task_created'],
    ['semantic.synthetic-one', 'unknown'],
    ['semantic.synthetic-two', 'unknown'],
  ] as const;
  const rows = rules.map(([rule_code, suffix]) => ({
    rule_code, rule_name: 'server fallback', false_positive_rate: null, findings_produced: 3,
    presentation_messages: { rule_name: { code: `reports.v2.security.rule-quality.names.${suffix}`, params: {}, text: 'server fallback' } },
    technical_details: [{ rule_code, policies: ['synthetic:7'] }],
  }));
  const raw: ReportResultDto = { contract_id: 'sli.report-result.v2', report_key: 'security.rule-quality', state: 'partial', items: rows,
    has_more: false, next_cursor: null, filtered_count: rows.length, metrics: [], series: {}, coverage: {}, filter_options: {}, limitations: [], window: {} };
  const result = localizeReportResult(raw);
  expect(result.items.map(row => row.rule_name)).toEqual(rules.map(([, suffix]) => t(`reports.v2.security.rule-quality.names.${suffix}`)));
  expect(result.items.slice(1, 4).map(row => row.rule_name)).toEqual(locale === 'ru'
    ? ['Изменения контроля аудита', 'Добавление участника в привилегированную группу', 'Создание задачи планировщика']
    : ['Audit control changes', 'Member added to a privileged group', 'Scheduled task creation']);
  result.items.forEach((row, i) => {
    expect(row.rule_code).toBe(rows[i].rule_code);
    expect(row.false_positive_rate).toBeNull();
    expect(row.findings_produced).toBe(3);
    expect(row.technical_details).toEqual(rows[i].technical_details);
  });
  expect(rows.every(row => row.rule_name === 'server fallback')).toBe(true);
});
