// @vitest-environment jsdom
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { en } from "./en";
import { ru } from "./ru";
import { eventSemanticText, relationConfidenceText, relationReasonText } from "./event-metadata";
import { localeRuntime, setLocale } from "./index";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("en"); });
afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });

it("translates DC catalog title/summary codes, including contextual assessments", () => {
  const catalog = JSON.parse(readFileSync(resolve(import.meta.dirname, "../../../config/event_catalog.json"), "utf8")) as {
    entries: Array<{ channel?: string; provider_name?: string; event_id: number; why?: string;
      card?: { assessment?: string; purpose?: string; risk_rules?: Array<{ assessment?: string }> } }>;
  };
  for (const entry of catalog.entries) {
    const code = `${entry.channel ?? ""}:${entry.provider_name ?? ""}:${entry.event_id}`;
    const fields = { title: undefined,
      summary: entry.card?.assessment || entry.card?.purpose || entry.why || "Событие расшифровано локальным каталогом.",
      ...Object.fromEntries((entry.card?.risk_rules ?? []).flatMap((rule, index) => rule.assessment ? [[`summary.rule.${index}`, rule.assessment]] : [])) };
    for (const [field, text] of Object.entries(fields)) {
      const key = `events.semantic.${code}.${field}` as keyof typeof ru;
      expect(ru[key], key).toBeTypeOf("string");
      if (text !== undefined) expect(ru[key], key).toBe(text);
      expect(en[key], key).toBeTypeOf("string");
      expect(eventSemanticText(`${code}.${field}`, "Changed server wording"), key).toBe(en[key]);
      expect(en[key], key).not.toMatch(/[А-Яа-яЁё]/);
    }
  }
  expect(eventSemanticText("uncatalogued.title", "fallback")).toBe("Event not yet interpreted by the catalog");
  expect(eventSemanticText("uncatalogued.summary", "fallback")).toContain("Neither action nor result");
});

it.each([
  [4688, "Process created", "Запущен процесс"],
  [6416, "External device observed", "Подключено внешнее устройство"],
])("shows event %i with a localized journal title", (eventId, english, russian) => {
  const code = `Security:Microsoft-Windows-Security-Auditing:${eventId}.title`;
  expect(eventSemanticText(code, "Server title")).toBe(english);
  setLocale("ru");
  expect(eventSemanticText(code, "Server title")).toBe(russian);
});

it.each([
  ["title", "Directory object attribute changed"],
  ["summary", "The source records a single fragment of an AD attribute change, including GPO objects."],
])("translates directory attribute change %s and preserves Russian server text", (field, expected) => {
  const code = `Security:Microsoft-Windows-Security-Auditing:5136.${field}`;
  const serverText = ru[`events.semantic.${code}` as keyof typeof ru];
  expect(eventSemanticText(code, serverText)).toBe(expected);
  setLocale("ru");
  expect(eventSemanticText(code, serverText)).toBe(serverText);
});

it("translates parameterized reasons and preserves unsupported or legacy server text", () => {
  const relation = { reason_code: "same_logon_id_same_server", reason_params: { time_delta_seconds: 0 }, reason: "Серверное пояснение" };
  expect(relationReasonText(relation, "fallback")).toBe("Matching LogonId and server; time difference 0 s.");
  expect(relationReasonText({ ...relation, reason_code: "same_task_same_server_time_window", reason_params: { time_delta_seconds: 42 } }, "fallback"))
    .toBe("Matching task name and server; time difference 42 s.");
  expect(relationReasonText({ ...relation, reason_code: "future-rule" }, "fallback")).toBe(relation.reason);
  expect(relationReasonText({ reason: relation.reason }, "fallback")).toBe(relation.reason);
  expect(relationReasonText({ reason_code: relation.reason_code, reason: relation.reason }, "fallback")).toBe(relation.reason);
  expect(relationReasonText({ explanation: "Сохранённое пояснение" }, "fallback")).toBe("Сохранённое пояснение");
  expect(eventSemanticText("future-pack.title", "Исходный текст")).toBe("Исходный текст");
  expect(eventSemanticText(undefined, "Исходный текст")).toBe("Исходный текст");
  expect(relationConfidenceText("rule_policy_score", "fallback")).toContain("neither a probability nor proof of causation");
  setLocale("ru");
  expect(relationReasonText(relation, "fallback")).toBe(relation.reason);
  expect(eventSemanticText("uncatalogued.title", "Серверный текст")).toBe("Серверный текст");
});

it.each(["ru", "en"] as const)("uses file audit words in both locales, retaining unknown source text (%s)", (locale) => {
  setLocale(locale);
  expect(eventSemanticText("Security:Microsoft-Windows-Security-Auditing:4656.title", "File audit evidence 4656"))
    .toBe(locale === "ru" ? "Запрошен доступ к объекту" : "Access to an object requested");
  expect(eventSemanticText("synthetic.unknown.title", "Синтетический источник")).toBe("Синтетический источник");
});
