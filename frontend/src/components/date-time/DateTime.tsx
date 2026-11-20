import { t } from "../../i18n";
import { EMPTY_VALUE } from "../../shared/format";
import { browserTimeZone, formatDateTime } from "../../shared/date-time";

export function DateTime({ value, timeZone, showZone = false }: { value: string | null | undefined; timeZone: string; showZone?: boolean }) {
  const label = formatDateTime(value, timeZone);
  const zoneLabel = timeZone.startsWith("invalid:") ? timeZone.slice("invalid:".length) : timeZone === "browser" ? browserTimeZone() || EMPTY_VALUE : timeZone;
  return <time dateTime={value || undefined} title={value || t("operations.dateTime.notProvided")}>{label}{showZone ? ` (${zoneLabel})` : ""}</time>;
}

