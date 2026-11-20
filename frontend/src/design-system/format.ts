import { t } from "../i18n";
import { formatDateTime as sharedFormatDateTime } from "../shared/date-time";
import { formatNumber } from "../shared/format";

export type CellKind = "text" | "number" | "datetime" | "date" | "boolean" | "code" | "list";

let displayTimeZone: string | undefined;

/** Compatibility fallback for non-React callers; UI renders pass their zone explicitly. */
export function setDisplayTimeZone(timeZone: string | undefined) {
  displayTimeZone = timeZone;
}

export function formatDateTime(value: string | Date | null | undefined, withTime = true, timeZone: string | undefined = displayTimeZone): string {
  return sharedFormatDateTime(value, timeZone ?? "browser", { withTime });
}

/** Formats a raw value for a table cell; null/undefined/"" become an explicit dash. */
export function formatCell(value: unknown, kind: CellKind = "text", timeZone?: string): string {
  if (value === null || value === undefined || value === "") return t("table.noValue");
  if (typeof value === "boolean") return t(value ? "reports.boolean.yes" : "reports.boolean.no");
  switch (kind) {
    case "number": return typeof value === "number" ? formatNumber(value) : String(value);
    case "datetime": return formatDateTime(String(value), true, timeZone);
    case "date": return formatDateTime(String(value), false, timeZone);
    case "boolean": return t(value ? "reports.boolean.yes" : "reports.boolean.no");
    case "list": return Array.isArray(value) ? (value.length ? value.join(", ") : t("table.noValue")) : String(value);
    default: return String(value);
  }
}
