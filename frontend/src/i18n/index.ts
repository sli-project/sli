import { en } from "./en";
import { ru } from "./ru";

/** ADR 0015: every new user-facing string goes through this dictionary. */
export type MessageKey = keyof typeof ru;
export type Locale = "ru" | "en";

export const LOCALE_STORAGE_KEY = "sli.locale";
export const LOCALES: readonly Locale[] = ["ru", "en"];

function storedLocale(): Locale {
  try {
    const value = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    if (value === "ru" || value === "en") return value;
  } catch { /* storage may be blocked; fall back to the default */ }
  return "ru";
}

let currentLocale: Locale = storedLocale();
if (typeof document !== "undefined") document.documentElement.lang = currentLocale;

export const getLocale = (): Locale => currentLocale;

/** Replaceable in tests: the locale is applied by a page reload so every screen re-reads the dictionary. */
export const localeRuntime = { reload: () => window.location.reload() };

export function setLocale(locale: Locale): void {
  try { window.localStorage.setItem(LOCALE_STORAGE_KEY, locale); } catch { /* the choice then lasts only until reload */ }
  currentLocale = locale;
  document.documentElement.lang = locale;
  localeRuntime.reload();
}

export function t(key: MessageKey, params?: Record<string, string | number>): string {
  const dictionary: Record<MessageKey, string> = currentLocale === "en" ? en : ru;
  const template = dictionary[key] ?? key;
  if (!params) return template;
  const values = key === "events.catalog_title" && currentLocale in params
    ? { ...params, label: params[currentLocale] } : params;
  return template.replace(/\{(\w+)\}/g, (match, name: string) => (name in values ? String(values[name]) : match));
}

const pluralRules = { ru: new Intl.PluralRules("ru-RU"), en: new Intl.PluralRules("en-US") };

type PluralForms = { one: string; few: string; many: string; other?: string }
  | { one: string; other: string; few?: string; many?: string };

/** Selects a translated form using the current locale; legacy Russian forms remain supported. */
export function plural(count: number, forms: PluralForms): string {
  const rule = pluralRules[currentLocale].select(count);
  if (rule === "one") return forms.one;
  if (rule === "few" && forms.few !== undefined) return forms.few;
  if (rule === "many" && forms.many !== undefined) return forms.many;
  return forms.other ?? forms.many ?? forms.one;
}

/** A translated count using the existing Intl plural rules; null stays unknown. */
export function counted(count: number | null, noun: "groups" | "problems" | "channels" | "assignments" | "deliveries"): string {
  const form = count === null ? "many" : plural(count, { one: "one", few: "few", many: "many", other: "other" });
  return t(`counts.${noun}.${form}` as MessageKey, { count: count ?? "—" });
}
