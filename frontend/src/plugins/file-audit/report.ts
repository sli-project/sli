import type { ReportDefinitionDto, ReportOption } from "../../api/report-v2-types";
import { periodBounds, type FilterField, type FilterValues, type PeriodValue } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { apiParams, paramOptions, valuesReady } from "../../app/report-v2/state";
import { localDateTimeToUtc } from "../../shared/date-time";

export const FILE_AUDIT_TABS = ["overview", "actions", "mass-operations", "permission-changes",
  "access-denials", "out-of-hours", "permissions", "audit-state"] as const;
export type FileAuditTab = typeof FILE_AUDIT_TABS[number];
export const isFileAuditReport = (key: string) => FILE_AUDIT_TABS.some((tab) => key === `file-audit.${tab}`);
export const tabTitle = (tab: FileAuditTab) => t(`file-audit.tabs.${tab}` as MessageKey);

export function fileAuditFields(definition: ReportDefinitionDto, options?: Record<string, ReportOption[]>): FilterField[] {
  return [
    { key: "period", label: t("period.label"), kind: "period", presets: ["24h", "7d", "30d", "custom"], precision: "datetime-local" },
    { key: "source_kind", label: t("file-audit.source"), kind: "select", options: [
      { value: "server", label: t("file-audit.source.server") },
      { value: "workstation", label: t("file-audit.source.workstation") },
    ] },
    { key: "path", label: t("file-audit.object"), kind: "text", wide: true, nested: { key: "include_nested", label: t("file-audit.include_nested") } },
    { key: "employee", label: t("file-audit.employee"), kind: "text" },
    { key: "share", label: t("file-audit.share"), kind: "search-multiselect", options: paramOptions(definition, "share", options) },
    { key: "operation", label: t("file-audit.operation"), kind: "select", options: paramOptions(definition, "operation", options) },
  ];
}

export function fileAuditParams(definition: ReportDefinitionDto, values: FilterValues, timeZone: string, cursor?: string | null, anchor = new Date()) {
  if (!valuesReady(definition, values)) return null;
  const params = apiParams(definition, values, { timeZone, cursor, limit: 50 });
  const period = values.period as PeriodValue | undefined;
  if (!period || !["24h", "7d", "30d", "custom"].includes(period.preset)) return null;
  if (period?.preset === "custom") {
    if (!period.from || !period.to) return null;
    try {
      const from = localDateTimeToUtc(period.from, timeZone), to = localDateTimeToUtc(period.to, timeZone);
      if (!from || !to || from >= to) return null;
      params.set("from", from); params.set("to", to);
    } catch { return null; }
  } else {
    const bounds = periodBounds(period, anchor);
    if (!bounds) return null;
    params.set("period", "custom"); params.set("from", bounds.from); params.set("to", bounds.to);
  }
  return params;
}
