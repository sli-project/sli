import { t, type MessageKey } from "./index";
import { ru } from "./ru";
import dateParams from "../../../config/i18n/date-params.json";
import { formatDateTime } from "../shared/date-time";

export type ApiMessage = {
  code: string;
  params: Record<string, string | number>;
  text?: string;
  rendered?: boolean;
};

/** Prefer the current UI language, keeping server text for codes from newer servers. */
export function resolveMessage(value: unknown, fallback = "", timeZone?: string): string {
  if (!value || typeof value !== "object") return fallback;
  const message = value as Partial<ApiMessage>;
  if (typeof message.code !== "string") return fallback;
  if (message.rendered === true && typeof message.text === "string") return message.text;
  if (!Object.hasOwn(ru, message.code)) return typeof message.text === "string" ? message.text : fallback;
  const params = message.params && typeof message.params === "object"
    ? Object.fromEntries(Object.entries(message.params).filter(([, value]) => typeof value === "string" || typeof value === "number")) : {};
  const formats = (dateParams as Record<string, Record<string, string>>)[message.code];
  for (const [name, kind] of Object.entries(formats ?? {})) {
    if (message.params && Object.hasOwn(message.params, name)) {
      const raw = message.params[name];
      const value = typeof raw === "string" && (kind === "date" || /(?:Z|[+-]\d{2}:\d{2})$/i.test(raw)) ? raw : null;
      // A working-hours explanation names the policy zone beside the date;
      // translating it into the viewer's zone would change the explanation.
      const zone = kind === "local_datetime" ? String(message.params.timezone ?? "invalid:—") : timeZone;
      params[name] = formatDateTime(value, zone, { withTime: kind !== "date" });
    }
  }
  return t(message.code as MessageKey, params);
}

/** Apply explicit report presentation envelopes, leaving source fields intact. */
export function resolvePresentation<T>(value: T, timeZone?: string): T {
  if (Array.isArray(value)) {
    const result = value.map((item) => resolvePresentation(item, timeZone));
    return (result.some((item, index) => item !== value[index]) ? result : value) as T;
  }
  if (!value || typeof value !== "object") return value;
  const record = value as Record<string, unknown>;
  const result = Object.fromEntries(Object.entries(record).map(([key, item]) => [key, resolvePresentation(item, timeZone)]));
  if (record.presentation_messages && typeof record.presentation_messages === "object") {
    for (const [field, envelope] of Object.entries(record.presentation_messages)) {
      result[field] = resolveMessage(envelope, typeof record[field] === "string" ? record[field] : "", timeZone);
    }
  }
  if (record.labels_messages && typeof record.labels_messages === "object") {
    const labels = record.labels as Record<string, string> | undefined;
    result.labels = Object.fromEntries(Object.entries(record.labels_messages).map(([key, envelope]) => [key, resolveMessage(envelope, labels?.[key] ?? key)]));
  }
  if (Array.isArray(record.entity_messages)) {
    result.entity_text = record.entity_messages.map((item) => typeof item === "string" ? item : resolveMessage(item)).join(", ") || null;
  }
  return (Object.entries(result).some(([key, item]) => item !== record[key]) ? result : value) as T;
}
