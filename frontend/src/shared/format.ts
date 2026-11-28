import { getLocale } from "../i18n";

/** The one placeholder for an empty cell or field. */
export const EMPTY_VALUE = "—";

/** Number grouped by the interface language; null/undefined/NaN become the empty value. */
export function formatNumber(value: number | null | undefined, options?: Intl.NumberFormatOptions): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return EMPTY_VALUE;
  return new Intl.NumberFormat(getLocale() === "en" ? "en-US" : "ru-RU", options).format(value);
}
