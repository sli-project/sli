import { EMPTY_VALUE } from "../shared/format";
import { t } from "../i18n";
import { resolveMessage } from "../i18n/messages";
import catalog from "../../../config/i18n/server.ru.json";

type CaseStatusCode = Extract<keyof typeof catalog, `investigations.caseStatus.${string}`>;

/** Подписи статусов дел и проблем безопасности. */
const text = (value: unknown, fallback = EMPTY_VALUE) => value === null || value === undefined || value === "" ? fallback : String(value);

export function caseStatusLabel(value: unknown, message?: unknown): string {
  const raw = text(value);
  const code = `investigations.caseStatus.${raw.toLowerCase()}`;
  return resolveMessage(message, Object.hasOwn(catalog, code) ? t(code as CaseStatusCode) : raw);
}
