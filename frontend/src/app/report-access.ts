import type { V4Access } from "../api/client";

/** Разрешён ли пользователю хотя бы один из отчётов (ключи и их псевдонимы). */
export function hasAllowedReport(access: V4Access | undefined, reportKeys: readonly string[]): boolean {
  return access?.reports.some((report) => report.allowed && reportKeys.includes(report.report_key)) ?? false;
}
