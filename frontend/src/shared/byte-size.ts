import { getLocale, t } from "../i18n";
import { formatNumber } from "./format";

const units = ["b", "kb", "mb", "gb", "tb"] as const;
const sizeSuffixes = ["B", "KB", "MB", "GB", "TB"];
const russianSuffixes = ["Б", "КБ", "МБ", "ГБ", "ТБ"];

export function formatByteSize(bytes: number | null | undefined): string | undefined {
  if (typeof bytes !== "number" || !Number.isFinite(bytes) || bytes < 0) return undefined;
  const unit = bytes === 0 ? 0 : Math.max(0, Math.min(units.length - 1, Math.floor(Math.log2(bytes) / 10)));
  return `${formatNumber(bytes / 1024 ** unit, { maximumFractionDigits: 1 })} ${t(`operations.source.unit_${units[unit]}`)}`;
}

/** Localize a size from older responses that carry a formatted value. */
export function localizeByteSize(value: string): string;
export function localizeByteSize(value: string | null | undefined): string | null | undefined;
export function localizeByteSize(value: string | null | undefined): string | null | undefined {
  const match = value?.match(/^(\d+(?:[.,]\d+)?)\s+(B|KB|MB|GB|TB|Б|КБ|МБ|ГБ|ТБ)$/);
  if (!match) return value;
  const [, amount, suffix] = match;
  const unit = units[Math.max(sizeSuffixes.indexOf(suffix), russianSuffixes.indexOf(suffix))];
  const decimal = getLocale() === "ru" ? amount.replace(".", ",") : amount.replace(",", ".");
  return `${decimal} ${t(`operations.source.unit_${unit}`)}`;
}
