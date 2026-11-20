// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { en } from "./en";
import enSource from "./en.ts?raw";
import { counted, getLocale, localeRuntime, plural, setLocale, t } from "./index";
import { ru } from "./ru";
import ruSource from "./ru.ts?raw";

afterEach(() => { vi.restoreAllMocks(); localStorage.clear(); });

describe("i18n dictionaries", () => {
  it("have identical key sets", () => {
    expect(Object.keys(en).sort()).toEqual(Object.keys(ru).sort());
  });

  it.each([["en", en], ["ru", ru]] as const)("has no empty or whitespace-only values in %s", (_locale, dictionary) => {
    for (const [key, value] of Object.entries(dictionary)) expect(value.trim(), key).not.toBe("");
  });

  it.each([["en", enSource, en], ["ru", ruSource, ru]] as const)("has no duplicate keys in %s", (_locale, source, dictionary) => {
    const keys = Array.from(source.matchAll(/^\s*("(?:\\.|[^"\\])*")\s*:/gm), (match) => JSON.parse(match[1]) as string);
    expect(keys.length).toBe(new Set(keys).size);
    expect(keys.sort()).toEqual(Object.keys(dictionary).sort());
  });

  it.each([
    "evsearch.invalid_cursor",
    "reports.freshness.event", "reports.freshness.snapshot", "reports.freshness.published",
    "reports.passport.more",
    "operations.actions.sourceFailure",
    "semanticControls.title", "semanticControls.suppressions", "plugins.title",
    "reports.v2.security.problems.params.show_suppressed.label",
    "reports.v2.security.problems.params.population.label",
    "reports.v2.security.problems.params.population.options.attention",
    "reports.v2.security.problems.presets.{\"population\":\"attention\"}",
    "reports.v2.security.problems.columns.review_hint.label",
    "reports.renderer.plugin_disabled", "reports.access.hidden_columns", "reports.access.denied_part",
    "reports.filters.more", "reports.empty.latest_at", "reports.empty.original_period",
    "reports.empty.original_selection", "reports.empty.show_latest", "reports.empty.source_diagnostics",
  ] as const)("keeps %s in both dictionaries", (key) => {
    expect(en[key]).toBeTruthy();
    expect(ru[key]).toBeTruthy();
  });

  it.each([
    ["operations.workerName.collection", "Event collection", "Сбор событий"],
    ["operations.semanticMetrics.title", "Semantic queue by stage", "Семантическая очередь по стадиям"],
    ["security.scenarios.technical.title", "Technical details", "Технические сведения"],
    ["reports.summaryAria", "Summary", "Сводка"],
    ["reports.v2.ad.infrastructure.params.period.label", "Period", "Период"],
    ["reports.empty.show_latest", "Show latest data", "Показать последние данные"],
    ["reports.access.category_security", "security information", "сведения безопасности"],
    ["reports.v2.ad.users.v2.columns.password_age_policy.label", "Password age policy", "Возраст пароля по политике"],
    ["reports.v2.ad.users.v2.columns.inactivity_policy.label", "Inactivity policy", "Неактивность по политике"],
    ["setup.steps.sources.unavailable", "Source status unavailable.", "Состояние источников недоступно."],
    ["setup.steps.collection.unavailable", "Data arrival status unavailable.", "Состояние поступления данных недоступно."],
  ] as const)("keeps merged translations for %s", (key, english, russian) => {
    expect(en[key]).toBe(english);
    expect(ru[key]).toBe(russian);
  });

  it("keep the same {placeholders} in both languages", () => {
    const placeholders = (text: string) => (text.match(/\{\w+\}/g) ?? []).sort();
    for (const key of Object.keys(ru) as Array<keyof typeof ru>) {
      expect(placeholders(en[key]), key).toEqual(placeholders(ru[key]));
    }
  });

  it("selects the source catalogue label using the actual locale", () => {
    vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
    const labels = { ru: "Изменение состояния службы", en: "Service state changed" };
    setLocale("ru");
    expect(t("events.catalog_title", labels)).toBe("Изменение состояния службы");
    setLocale("en");
    expect(t("events.catalog_title", labels)).toBe("Service state changed");
    setLocale("ru");
  });

  it("keeps selected catalogue text literal and React-escaped", () => {
    vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
    const labels = { ru: "<img src=x onerror=alert(1)> {en}", en: "<script>alert(1)</script> {ru}" };
    for (const locale of ["ru", "en"] as const) {
      setLocale(locale);
      const selected = t("events.catalog_title", labels);
      expect(selected).toBe(labels[locale]);
      const html = renderToStaticMarkup(createElement("span", null, selected));
      expect(html).not.toMatch(/<img|<script/);
      expect(html).toContain("&lt;");
    }
    setLocale("ru");
  });

  it("switches the dictionary, stores the choice and sets the document language", () => {
    const reload = vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
    expect(getLocale()).toBe("ru");
    expect(t("state.retry")).toBe("Повторить");
    setLocale("en");
    expect(localStorage.getItem("sli.locale")).toBe("en");
    expect(document.documentElement.lang).toBe("en");
    expect(t("state.retry")).toBe("Retry");
    expect(t("table.shown", { count: 3 })).toBe("Shown: 3");
    expect(reload).toHaveBeenCalledOnce();
    setLocale("ru");
    expect(t("state.retry")).toBe("Повторить");
  });
});

describe("plural forms", () => {
  const forms = { one: "one", few: "few", many: "many", other: "other" };

  it.each([
    [0, "many"], [1, "one"], [2, "few"], [5, "many"], [11, "many"],
    [14, "many"], [21, "one"], [22, "few"], [25, "many"], [1.5, "other"],
  ])("uses Russian rules for %s", (count, expected) => {
    vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
    setLocale("ru");
    expect(plural(count as number, forms)).toBe(expected);
  });

  it.each([0, 1, 2, 5, 11, 21, 22, 1.5])("uses English rules for %s", (count) => {
    vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
    setLocale("en");
    expect(plural(count, forms)).toBe(count === 1 ? "one" : "other");
    setLocale("ru");
  });
});

 it("contains no Cyrillic in English UI templates except language autonyms", () => {
   const locale = "ru";
   const autonyms = ["shell.profile.language", "login.language"].map((prefix) => `${prefix}.${locale}`);
   expect(Object.entries(en).filter(([key, value]) => !autonyms.includes(key) && /[\u0400-\u04ff]/.test(value))).toEqual([]);
 });
 it.each([[1, "1 назначение", "1 группа", "1 проблема"], [2, "2 назначения", "2 группы", "2 проблемы"], [5, "5 назначений", "5 групп", "5 проблем"], [21, "21 назначение", "21 группа", "21 проблема"], [204, "204 назначения", "204 группы", "204 проблемы"]] as const)("declines real UI counts: %s", (count, assignments, groups, problems) => {
   vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
   setLocale("ru");
   expect(counted(count, "assignments")).toBe(assignments);
   expect(counted(count, "groups")).toBe(groups);
   expect(counted(count, "problems")).toBe(problems);
   setLocale("en");
   expect(counted(count, "assignments")).toBe(`${count} assignment${count === 1 ? "" : "s"}`);
   expect(counted(null, "deliveries")).toBe("— deliveries");
   setLocale("ru");
 });
