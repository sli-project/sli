// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { existsSync, readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, ApiResponseError } from "../api/client";
import { StateView } from "../design-system/StateView";
import { ReportLayout } from "../design-system/ReportLayout";
import { localeRuntime, setLocale, t, type MessageKey } from "./index";
import { resolveMessage, resolvePresentation } from "./messages";
import { ru } from "./ru";
import { en } from "./en";

const catalogRoot = existsSync("config/i18n") ? "config/i18n" : "../config/i18n";
const legacyProblemMessages = new Set([
  "security.problems.presentation.watch_limitation",
  "security.problems.presentation.decoy_limitation",
  "security.problems.presentation.default_next",
  "security.problems.presentation.audit_limitations",
  "security.problems.presentation.wording_limitation",
]);

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => { cleanup(); setLocale("ru"); localStorage.clear(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe("API message resolution", () => {
  it.each(["ru", "en"] as const)("resolves coded queue fields and entity fallbacks in %s without changing observations", (locale) => {
    setLocale(locale);
    const row = {
      title: "Source title", title_text: "other language", entity_text: "other language", summary: "Source summary",
      presentation_messages: { title_text: { code: "security.problems.presentation.default_title", params: { id: 7 }, text: "other language" } },
      entity_messages: [{ code: "security.problems.entity.source_host", params: {}, text: "other language" }, "source-observation"],
      labels: { new: "other language" }, labels_messages: { new: { code: "security.problems.status.new", params: {}, text: "other language" } },
    };
    const actual = resolvePresentation(row);
    expect(actual.title_text).toBe(t("security.problems.presentation.default_title", { id: 7 }));
    expect(actual.entity_text).toBe(`${t("security.problems.entity.source_host")}, source-observation`);
    expect(actual.labels.new).toBe(t("security.problems.status.new"));
    expect(actual.title).toBe(row.title);
    expect(actual.summary).toBe(row.summary);
    expect(row.title_text).toBe("other language");
    expect(resolvePresentation({ presentation_messages: { title: { code: "future.code", params: {}, text: "future wording" } }, title: "legacy" }).title).toBe("future wording");
  });
  it.each(["ru", "en"] as const)("localizes shared API messages and accepts legacy problem messages in %s", (locale) => {
    setLocale(locale);
    const server: Record<string, string> = JSON.parse(readFileSync(`${catalogRoot}/server.${locale}.json`, "utf8"));
    for (const [code, text] of Object.entries(server)) {
      if (code.startsWith("notifications.message.") || code.startsWith("notifications.bot.")) {
        expect(Object.hasOwn(ru, code) || Object.hasOwn(en, code), code).toBe(false);
        continue;
      }
      if (legacyProblemMessages.has(code)) {
        expect(resolveMessage({ code, params: {}, text: "Legacy server wording" }), code).toBe("Legacy server wording");
        continue;
      }
      expect(Object.hasOwn(ru, code), `Missing ru translation: ${code}`).toBe(true);
      expect(Object.hasOwn(en, code), `Missing en translation: ${code}`).toBe(true);
      expect(resolveMessage({ code, params: { seconds: 3 }, text: "other locale" }), code).toBe(text.replace("{seconds}", "3"));
    }
  });

  it.each(["ru", "en"] as const)("localizes event search errors and legacy notices in %s regardless of server language", (locale) => {
    setLocale(locale);
    const server: Record<string, string> = JSON.parse(readFileSync(`${catalogRoot}/server.${locale}.json`, "utf8"));
    const otherLocale = locale === "ru" ? "en" : "ru";
    const otherServer: Record<string, string> = JSON.parse(readFileSync(`${catalogRoot}/server.${otherLocale}.json`, "utf8"));
    const messages = Object.entries(server).filter(([code]) => code.startsWith("evsearch."));
    expect(messages.length).toBeGreaterThan(0);
    for (const [code, text] of messages) {
      expect(resolveMessage({ code, params: {} }), code).toBe(text);
      expect(resolveMessage({ code, params: {}, text: otherServer[code] }), code).toBe(text);
    }
  });

  it("handles absent, unknown and malformed envelopes without translating source observations", () => {
    expect(resolveMessage(null, "fallback")).toBe("fallback");
    expect(resolveMessage("legacy text", "fallback")).toBe("fallback");
    expect(resolveMessage({ code: "future.code", text: "server fallback" })).toBe("server fallback");
    expect(resolveMessage({ code: "future.code" }, "fallback")).toBe("fallback");
    expect(resolveMessage({ code: "toString" }, "fallback")).toBe("fallback");
    expect(resolveMessage({ code: "login.error.retryAfter", params: { seconds: {} } })).toContain("{seconds}");
  });

  it.each(["ru", "en"] as const)("renders a coded report state through ReportLayout in %s", (locale) => {
    setLocale(locale);
    render(<ReportLayout title="Synthetic report" state="partial" stateMessage={{ code: "reports.state.partial", params: {}, text: "other locale" }}/>);
    expect(screen.getByText(t("reports.state.partial"))).toBeTruthy();
    expect(screen.queryByText("other locale")).toBeNull();
    cleanup();
    render(<StateView state="empty" message={{ code: "reports.state.empty", params: {} }} detail="source detail"/>);
    expect(screen.getByText(t("reports.state.empty"))).toBeTruthy();
    expect(screen.getByText("source detail")).toBeTruthy();
  });

  it("retains legacy state copy when an older server omits the envelope", () => {
    render(<StateView state="empty"/>);
    expect(screen.getByText(t("state.empty.title"))).toBeTruthy();
  });

  it.each(["ru", "en"] as const)("keeps a coded title and contextual recovery message together in %s", (locale) => {
    setLocale(locale);
    render(<StateView state="processing" titleMessage={{ code: "reports.state.processing", params: {}, text: "other locale" }}
      message={<span>Contextual recovery</span>} detail="source detail"/>);
    expect(screen.getByText(t("reports.state.processing"))).toBeTruthy();
    expect(screen.getByText("Contextual recovery")).toBeTruthy();
    expect(screen.getByText("source detail")).toBeTruthy();
    expect(screen.queryByText("other locale")).toBeNull();
  });

  it("passes an unknown state envelope through ReportLayout for forward compatibility", () => {
    render(<ReportLayout title="Synthetic report" state="partial" stateMessage={{ code: "future.state", params: {}, text: "Server state title" }}/>);
    expect(screen.getByText("Server state title")).toBeTruthy();
  });

  it.each([
    ["login.error.credentials", "invalid_credentials"],
    ["reports.renderer.error_gpo_snapshot", "gpo_snapshot_unavailable"],
    ["evsearch.invalid_request", "evsearch.invalid_request"],
    ["evsearch.unsupported_version", "evsearch.unsupported_version"],
    ["evsearch.invalid_period", "evsearch.invalid_period"],
    ["evsearch.invalid_condition", "evsearch.invalid_condition"],
    ["evsearch.unsupported_field", "evsearch.unsupported_field"],
    ["evsearch.unsupported_operator", "evsearch.unsupported_operator"],
    ["evsearch.event_context_required", "evsearch.event_context_required"],
    ["evsearch.unsupported_action", "evsearch.unsupported_action"],
    ["evsearch.policy_denied", "evsearch.policy_denied"],
    ["evsearch.unsupported_question", "evsearch.unsupported_question"],
    ["evsearch.period_too_wide", "evsearch.period_too_wide"],
    ["evsearch.period_outside_scope", "evsearch.period_outside_scope"],
    ["evsearch.snapshot_expired", "evsearch.snapshot_expired"],
    ["evsearch.snapshot_invalidated", "evsearch.snapshot_invalidated"],
    ["evsearch.snapshot_limit_exceeded", "evsearch.snapshot_limit_exceeded"],
    ["evsearch.snapshot_timeout", "evsearch.snapshot_timeout"],
    ["evsearch.storage_integrity_error", "evsearch.storage_integrity_error"],
    ["evsearch.storage_limit_exceeded", "evsearch.storage_limit_exceeded"],
    ["evsearch.storage_timeout", "evsearch.storage_timeout"],
    ["evsearch.history_unavailable", "evsearch.history_unavailable"],
    ["evsearch.history_predicate_unavailable", "evsearch.history_predicate_unavailable"],
    ["evsearch.history_timeout", "evsearch.history_timeout"],
    ["evsearch.history_integrity_error", "evsearch.history_integrity_error"],
    ["evsearch.history_limit_exceeded", "evsearch.history_limit_exceeded"],
  ] as const)("localizes %s on HTTP failures while keeping the legacy error code", async (code: MessageKey, error) => {
    setLocale("en");
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ error, message: { code, params: {}, text: "other locale" } }), { status: 401 })));
    const caught = await api.bootstrap().catch((value: unknown) => value);
    expect(caught).toBeInstanceOf(ApiResponseError);
    expect(caught).toMatchObject({ code: error, detail: t(code), message: t(code) });
  });
});

it.each(["ru", "en"] as const)("formats declared presentation dates in %s without changing source params", (locale) => {
  setLocale(locale);
  const params = { expiration_utc: "2026-01-01T00:30:00Z" };
  const envelope = { code: "reports.v2.ad.computers.v6.security.laps_expired.observed", params, text: "other locale" };
  const row = { expiration_utc: params.expiration_utc, observed: "raw", presentation_messages: { observed: envelope } };
  const actual = resolvePresentation(row, "America/Los_Angeles");
  expect(actual.observed).toContain(locale === "ru" ? "31.12.2025, 16:30" : "Dec 31, 2025, 4:30 PM");
  expect(actual.expiration_utc).toBe(params.expiration_utc);
  expect(actual.presentation_messages.observed.params).toEqual(params);
  expect(row.observed).toBe("raw");
  expect(resolveMessage({ ...envelope, params: { expiration_utc: "" } })).toContain("—");
  expect(resolveMessage({ code: "reports.v2.ad.computers.v6.security.unsupported_os.observed", params: { operating_system: "Synthetic OS", support_end_date: "2026-01-01" } }, "", "America/Los_Angeles"))
    .toContain(locale === "ru" ? "01.01.2026" : "Jan 1, 2026");
  expect(resolveMessage({ code: "future.code", params, text: params.expiration_utc })).toBe(params.expiration_utc);
});

it.each(["ru", "en"] as const)("keeps policy wall-clock dates in their own zone in %s", (locale) => {
  setLocale(locale);
  const params = { local_time: "2026-10-21T19:05:00+07:00", timezone: "Asia/Novosibirsk", policy_version: 2 };
  const text = resolveMessage({ code: "workstations.reasons.logon_outside_policy", params }, "", "America/Los_Angeles");
  expect(text).toContain(locale === "ru" ? "21.10.2026, 19:05" : "Oct 21, 2026, 7:05 PM");
  expect(text).toContain("Asia/Novosibirsk");
  expect(params.local_time).toBe("2026-10-21T19:05:00+07:00");
});
