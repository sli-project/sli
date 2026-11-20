import { getLocale, t, type MessageKey } from "./index";
import { ru } from "./ru";

/** Exact matches for known product explanations; never use on object fields. */
export function fixedText(value: string, prefix: string): string {
  if (getLocale() !== "en") return value;
  const key = (Object.keys(ru) as MessageKey[]).find((key) => key.startsWith(prefix) && ru[key] === value);
  return key ? t(key) : value;
}
