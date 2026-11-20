// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  problemMetrics,
  problemPresentation,
  statusLabel,
} from "./security-problems-report";
import type { SecurityProblemFinding } from "../api/client";
import { localeRuntime, setLocale, t } from "../i18n";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });

const finding: SecurityProblemFinding = {
  id: 558,
  title: "Audit policy was changed",
  severity: "high",
  status: "new",
  actor: "sid:dc1:S-1-5-18",
  source: "6840",
  summary: "Exact named EventData from Event 4719 was observed",
  why_it_matters: "Exact named EventData from Event 4719 was observed",
  recommended_action: "Review the linked evidence and validate the security impact.",
  evidence_count: 70,
  first_seen_utc: "2026-08-26T18:21:01+07:00",
  last_seen_utc: "2026-08-26T18:21:01+07:00",
  evidence: [],
  entities: [],
  status_history: [],
};

describe("представление production finding", () => {
  it.each(["ru", "en"] as const)("shows coded WATCH priority and confidence limits in %s", (locale) => {
    setLocale(locale);
    const view = problemPresentation({ ...finding, title: "Activity of an account under watch",
      presentation_code: "account_watch_activity", presentation_messages: {
        title_text: { code: "security.problems.presentation.watch_title", params: {}, text: "fallback" },
        what_happened: { code: "security.problems.presentation.watch_what", params: {}, text: "fallback" },
        why_text: { code: "security.problems.presentation.watch_why", params: {}, text: "fallback" },
        next_text: { code: "security.problems.presentation.watch_next", params: {}, text: "fallback" },
        wording_limitation: { code: "security.problems.presentation.watch_limitation", params: {}, text: "fallback" },
      } });
    expect(view.title).toBe(t("security.problems.presentation.watch_title"));
    expect(view.whyItMatters).toBe(t("security.problems.presentation.watch_why"));
    expect(view.limitations).toEqual([t("security.problems.presentation.watch_limitation")]);
  });
  it.each(["ru", "en"] as const)("shows coded account decoy evidence and coverage limits in %s", (locale) => {
    vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
    setLocale(locale);
    const coded = { ...finding, title: "Registered decoy account used", presentation_code: "account_decoy_used",
      presentation_messages: {
        title_text: { code: "security.problems.presentation.decoy_title", params: {}, text: "fallback" },
        what_happened: { code: "security.problems.presentation.decoy_what", params: {}, text: "fallback" },
        why_text: { code: "security.problems.presentation.decoy_why", params: {}, text: "fallback" },
        next_text: { code: "security.problems.presentation.decoy_next", params: {}, text: "fallback" },
        wording_limitation: { code: "security.problems.presentation.decoy_limitation", params: {}, text: "fallback" },
      } };
    const view = problemPresentation(coded);
    expect(view.title).toBe(t("security.problems.presentation.decoy_title"));
    expect(view.whatHappened).toBe(t("security.problems.presentation.decoy_what"));
    expect(view.whyItMatters).toBe(t("security.problems.presentation.decoy_why"));
    expect(view.nextAction).toBe(t("security.problems.presentation.decoy_next"));
    expect(view.limitations).toEqual([t("security.problems.presentation.decoy_limitation")]);
  });

  it.each(["ru", "en"] as const)("prefers coded presentation in %s and preserves source observations", (locale) => {
    vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
    setLocale(locale);
    const coded = { ...finding, title: "Future rule", summary: "Source observation", presentation_messages: {
      title_text: { code: "security.problems.presentation.default_title", params: { id: finding.id }, text: "other language" },
      wording_limitation: { code: "security.problems.presentation.wording_limitation", params: {}, text: "other language" },
    } };
    const view = problemPresentation(coded);
    expect(view.title).toBe(t("security.problems.presentation.default_title", { id: finding.id }));
    expect(problemPresentation({ ...coded, actor: undefined }).actor).toBe("—");
    expect(view.whatHappened).toBe("Source observation");
    expect(view.limitations).toEqual([t("security.problems.presentation.wording_limitation")]);
    expect(coded.title).toBe("Future rule");
  });

  it("keeps a server-rendered clause with an absent optional host", () => {
    const message = { code: "security.problems.presentation.t109.agent-tamper.what", params: {},
      text: "An SLI agent service was stopped.", rendered: true };
    expect(problemPresentation({ ...finding, presentation_messages: { what_happened: message } }).whatHappened)
      .toBe("An SLI agent service was stopped.");
  });
  it("переводит принятую audit-policy policy в пользовательский вывод", () => {
    const view = problemPresentation(finding);

    expect(view.title).toBe("Изменена политика аудита Windows");
    expect(view.whatHappened).toContain("4719");
    expect(view.whyItMatters).toContain("регистрац");
    expect(view.nextAction.toLowerCase()).toContain("провер");
    expect(view.title).not.toContain("Audit policy");
    expect(view.actor).toBe("Системная учётная запись DC1");
  });

  it("не придумывает перевод для неизвестной будущей policy", () => {
    const view = problemPresentation({ ...finding, title: "Unknown future rule", summary: "raw observation" });

    expect(view.title).toBe("Unknown future rule");
    expect(view.whatHappened).toBe("raw observation");
    expect(view.limitations).toContain("Пользовательское описание для этой policy не зарегистрировано.");
  });
});

describe("сводка очереди", () => {
  it("разделяет новые, в работе и закрытые проблемы", () => {
    expect(problemMetrics([
      { severity: "high", status: "new", count: 4 },
      { severity: "high", status: "active", count: 2 },
      { severity: "medium", status: "closed", count: 3 },
      { severity: "low", status: "false_positive", count: 1 },
    ])).toEqual({ open: 6, attention: 4, inProgress: 2, closed: 4, total: 10 });
  });

  it("даёт русские lifecycle-подписи", () => {
    expect(statusLabel("new")).toBe("Новая");
    expect(statusLabel("active")).toBe("В работе");
    expect(statusLabel("confirmed")).toBe("Подтверждена");
    expect(statusLabel("false_positive")).toBe("Ложное срабатывание");
  });
});
