import { getLocale, t } from "../i18n";

/** Localize only the unit suffix of a server-formatted size, keeping its value. */
export function localizeByteSize(value: string): string;
export function localizeByteSize(value: string | null | undefined): string | null | undefined;
export function localizeByteSize(value: string | null | undefined): string | null | undefined {
  if (value == null || getLocale() !== "en") return value;
  const units: Record<string, string> = { "Б": t("operations.source.unit_b"), "КБ": t("operations.source.unit_kb"), "МБ": t("operations.source.unit_mb"), "ГБ": t("operations.source.unit_gb"), "ТБ": t("operations.source.unit_tb") };
  return value.replace(/^(\d+(?:[.,]\d+)?\s+)(Б|КБ|МБ|ГБ|ТБ)$/, (_, amount: string, unit: string) => amount + units[unit]);
}
