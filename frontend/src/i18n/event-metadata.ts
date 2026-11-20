import { en } from "./en";
import { getLocale, t, type MessageKey } from "./index";

/** Unknown source-pack codes retain their server text. Never apply to raw messages or case titles. */
export function codedText(key: string, fallback: string, params?: Record<string, string | number>): string {
  return getLocale() === "en" && Object.hasOwn(en, key) ? t(key as MessageKey, params) : fallback;
}

export function eventSemanticText(code: string | null | undefined, fallback: string): string {
  const key = `events.semantic.${code}`;
  return code && /:\d+\.title$/.test(code) && Object.hasOwn(en, key)
    ? t(key as MessageKey) : code ? codedText(key, fallback) : fallback;
}

export function relationReasonText(relation: {
  reason_code?: string;
  reason_params?: Record<string, string | number>;
  reason?: string;
  explanation?: string;
}, fallback: string): string {
  const text = relation.reason ?? relation.explanation ?? fallback;
  const delta = relation.reason_params?.time_delta_seconds;
  return relation.reason_code && (typeof delta === "number" || typeof delta === "string")
    ? codedText(`investigations.relations.reason.${relation.reason_code}`, text, relation.reason_params) : text;
}

export function relationConfidenceText(kind: string, fallback: string): string {
  return codedText(`investigations.relations.confidence.${kind}`, fallback);
}

export function eventFacts(semantics: {
  facts: Array<[string, string]>;
  fact_label_codes?: string[];
  title_code?: string;
}): Array<[string, string]> {
  return semantics.facts.map(([label, value], index) => [
    eventSemanticText(semantics.fact_label_codes?.[index], label),
    semantics.fact_label_codes?.[index] === "facts.event" ? eventSemanticText(semantics.title_code, value) : value,
  ]);
}
