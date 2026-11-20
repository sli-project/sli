// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import type { AgentCollectionHealth } from "../api/client";
import { localeRuntime, setLocale, t } from "../i18n";
import { agentCollectionDetail, agentCollectionHeader, agentCollectionHistory, agentCollectionLabel, agentCollectionSummary } from "./agent-collection-view";

it.each(["ru", "en"] as const)("dates the overdue condition, not outage onset (%s)", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  const overdue = { ...agent, modules: [{ module_id: "sli.windows.ad-dc", channels: [{
    channel: "Security", state: "error" as const, failure_reason: "import_overdue" as const,
    last_packet_at: "2026-10-10T11:59:00Z", last_import_at: "2026-10-10T11:58:00Z",
    import_lag_seconds: 3600, budget_seconds: 900, issue_since_utc: "2026-10-10T11:15:00Z",
    issue_observed_at_utc: "2026-10-10T12:00:00Z",
  }] }] };
  const result = agentCollectionHeader({ ...data, items: [overdue] }, "UTC");
  expect(result.detail).toContain(locale === "ru" ? "Срок ожидания превышен с" : "Wait deadline exceeded since");
  expect(result.detail).toContain("11:15");
  expect(result.detail).not.toContain("11:59");
  expect(result.detail).not.toContain("11:58");
  expect(result.detail).not.toContain(t("operations.agent_collection.start_unknown"));
});

it.each(["ru", "en"] as const)("dates a received error without inventing its start (%s)", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  const observed = { ...agent, modules: [{ module_id: "sli.windows.ad-dc", channels: [{
    channel: "Security", state: "error" as const, failure_reason: "read_error" as const,
    last_packet_at: "2026-10-10T11:40:00Z", last_import_at: null,
    import_lag_seconds: null, budget_seconds: 900, issue_since_utc: null,
    issue_observed_at_utc: "2026-10-10T11:40:00Z",
  }] }] };
  const result = agentCollectionHeader({ ...data, items: [observed] }, "UTC");
  expect(result.detail).toContain(locale === "ru" ? "Ошибка получена" : "Error received");
  expect(result.detail).toContain("11:40");
  expect(result.detail).not.toContain(locale === "ru" ? "Срок ожидания превышен с" : "Wait deadline exceeded since");
});

it("keeps a missing read-error date unknown instead of borrowing another stream's deadline", () => {
  const channel = { channel: "Security", state: "error" as const, last_packet_at: null,
    last_import_at: null, import_lag_seconds: null, budget_seconds: 900 };
  const mixed = { ...agent, modules: [{ module_id: "sli.windows.ad-dc", channels: [
    { ...channel, failure_reason: "read_error" as const, issue_observed_at_utc: "invalid" },
    { ...channel, channel: "System", failure_reason: "import_overdue" as const, issue_since_utc: "2026-10-10T11:15:00Z" },
  ] }] };
  expect(agentCollectionHeader({ ...data, items: [mixed] }, "UTC").detail).toContain(t("operations.agent_collection.start_unknown"));
  expect(agentCollectionHeader({ ...data, items: [mixed] }, "UTC").detail).not.toContain("11:15");
});

it.each(["ru", "en"] as const)("explains unconfirmed agent collection and diagnostic timeouts in %s", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  const unknown = { ...agent, state: "unknown" as const };
  expect(agentCollectionSummary(unknown)).toBe(t("operations.agent_collection.reason.unconfirmed"));
  expect(agentCollectionSummary(unknown, { state: "unavailable", reason: "timeout" }))
    .toBe(t("operations.agent_collection.reason.check_timeout"));
  expect(agentCollectionSummary(unknown, { state: "unavailable", reason: "read_failed" }))
    .toBe(t("operations.agent_collection.reason.check_failed"));
});

const agent: AgentCollectionHealth["items"][number] = {
  id: "fixture-agent", host_id: "fixture-host", name: "fixture-agent", domains: [],
  state: "error", connection: "offline", last_seen: "2026-10-09T12:00:00Z", last_packet_at: null,
  policy_revision: 1, applied_policy_revision: 1, modules: [], href: "/app/agents#agent-fixture-agent",
};
const data: AgentCollectionHealth = { state: "error", items: [agent], active_agents: 1, current_agents: 0, checked_at_utc: "2026-10-10T12:00:00Z" };

it.each(["ru", "en"] as const)("shows the actual collection failure reason (%s)", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  const broken = { ...agent, modules: [{ module_id: "sli.windows.ad-dc", channels: [{ channel: "Security",
    state: "error" as const, failure_reason: "read_error" as const, last_packet_at: null, last_import_at: null,
    import_lag_seconds: null, budget_seconds: 900 }] }] };
  expect(agentCollectionSummary(broken)).toBe(t("operations.agent_collection.reason.read_error"));
  expect(agentCollectionSummary({ ...agent, state: "current" })).toBe(t("operations.agent_collection.state.current"));
});

afterEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("ru"); vi.restoreAllMocks();
});

it.each(["ru", "en"] as const)("localizes agent failures and pause states (%s)", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  expect(agentCollectionHeader(data)).toMatchObject({ state: "error", title: t("shell.freshness.broken.title"), href: agent.href });
  expect(agentCollectionHeader(data).detail).toContain(t("operations.agent_collection.failed", {
    agent: `${agent.name} · ${t("operations.agent_collection.no_domain")}`,
  }));
  expect(agentCollectionLabel("paused")).toBe(t("operations.agent_collection.state.paused"));
});

it.each([
  ["ru", "Агент fixture-host · a.example.test · z.example.test: агент не зарегистрирован"],
  ["en", "Agent fixture-host · a.example.test · z.example.test: agent is not registered"],
] as const)("names never-contacted agents and their domains (%s)", (locale, detail) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  const header = agentCollectionHeader({ ...data, items: [{ ...agent, name: "fixture-host", last_seen: null,
    connection: "never_seen", domains: ["a.example.test", "z.example.test"] }] });
  expect(header.detail).toContain(detail);
  expect(header.href).toBe(agent.href);
});

it.each(["packet", "import"] as const)("keeps collection failures when %s evidence exists without a heartbeat", (evidence) => {
  const header = agentCollectionHeader({ ...data, items: [{ ...agent, last_seen: null, modules: [
    { module_id: "sli.workstations", channels: [{ channel: "Security", state: "error",
      last_packet_at: evidence === "packet" ? "2026-10-09T12:00:00Z" : null,
      last_import_at: evidence === "import" ? "2026-10-09T12:00:00Z" : null,
      import_lag_seconds: null, budget_seconds: 900 }] },
  ] }] });
  expect(header.detail).toContain("Агент fixture-agent · Домен не указан: нет данных или импорта");
});

it.each(["paused", "disabled", "waiting", "unknown"] as const)("does not show a broken banner for %s agents", (state) => {
  expect(agentCollectionHeader({ ...data, items: [{ ...agent, state }] }).state).not.toBe("error");
});

it("does not turn missing or unavailable API data into broken collection", () => {
  expect(agentCollectionHeader().state).toBe("unknown");
  expect(agentCollectionHeader({ ...data, state: "unavailable", items: [] }).state).toBe("unknown");
});

it.each(["ru", "en"] as const)("explains old import backlog despite fresh agent contact (%s)", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  const header = agentCollectionHeader({ ...data, items: [{ ...agent, connection: "online",
    last_packet_at: "2026-10-10T11:59:50Z", modules: [{ module_id: "sli.windows.ad-dc", channels: [{
      channel: "Security", state: "error", failure_reason: "import_overdue",
      last_packet_at: "2026-10-10T11:59:50Z", last_import_at: "2026-10-10T11:59:55Z",
      import_lag_seconds: 8 * 86400, budget_seconds: 900,
    }] }],
  }] });
  expect(header.state).toBe("error");
  expect(header.href).toBe(agent.href);
  expect(header.detail).toContain(t("operations.agent_collection.import_overdue", {
    agent: `${agent.name} · ${t("operations.agent_collection.no_domain")}`,
  }));
});

it("does not hide a read failure behind another channel's old import backlog", () => {
  const channel = { channel: "Security", state: "error" as const, failure_reason: "import_overdue" as const,
    last_packet_at: "2026-10-10T11:59:50Z", last_import_at: "2026-10-10T11:59:55Z",
    import_lag_seconds: 8 * 86400, budget_seconds: 900 };
  const header = agentCollectionHeader({ ...data, items: [{ ...agent, modules: [{ module_id: "sli.windows.ad-dc",
    channels: [channel, { ...channel, channel: "System", failure_reason: "read_error" }],
  }] }] });
  expect(header.detail).toContain(t("operations.agent_collection.failed", {
    agent: `${agent.name} · ${t("operations.agent_collection.no_domain")}`,
  }));
});

it.each(["ru", "en"] as const)("keeps historical quarantine separate from a healthy header (%s)", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  const healthy = { ...agent, state: "current" as const, modules: [{ module_id: "sli.windows.ad-dc", channels: [{
    channel: "Security", state: "current" as const, last_packet_at: "2026-10-19T12:00:00Z",
    last_import_at: "2026-10-19T12:00:01Z", import_lag_seconds: 1, budget_seconds: 900,
    historical_unimported_packets: 12, historical_error_at: "2026-10-11T00:00:00Z",
  }] }] };
  expect(agentCollectionHeader({ ...data, state: "current", items: [healthy], current_agents: 1 }).state).toBe("current");
  const history = agentCollectionHistory(healthy, "UTC");
  expect(history).toHaveLength(1);
  expect(history[0]).toContain("12");
  expect(history[0]).toContain("11");
  expect(history[0]).not.toContain("operations.");
  expect(agentCollectionHistory({ ...healthy, modules: [] }, "UTC")).toEqual([]);
  expect(agentCollectionHeader({ ...data, state: "partial", items: [{ ...healthy, state: "lagging" }] })).toMatchObject({
    state: "partial", detail: locale === "ru" ? "Агент fixture-agent: данные ожидают обработки · время начала неизвестно" : "Agent fixture-agent: data awaiting processing · start time unknown",
  });
});


it.each(["ru", "en"] as const)("keeps accepted historical loss visible without turning current delivery into failure (%s)", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  const healthy = { ...agent, state: "current" as const, completeness: { state: "known_gaps" as const, last_accepted_gap_at: "2026-10-23T01:02:03Z" } };
  const header = agentCollectionHeader({ ...data, state: "current", items: [healthy], current_agents: 1, completeness: { state: "known_gaps" } });
  expect(header.state).toBe("current"); expect(header.detail).toContain(t("operations.agent_collection.accepted_loss"));
  const detail = agentCollectionDetail(healthy, "UTC");
  expect(detail).toContain(t("operations.agent_collection.accepted_loss"));
  expect(detail).toContain("2026");
  expect(agentCollectionHeader({ ...data, state: "current", items: [{ ...healthy, completeness: { state: "not_assessed", last_accepted_gap_at: null } }], completeness: { state: "not_assessed" } }).detail).not.toContain(t("operations.agent_collection.accepted_loss"));
});

it("retains live error detail alongside historical accepted loss", () => {
  const header = agentCollectionHeader({ ...data, completeness: { state: "known_gaps" } });
  expect(header.state).toBe("error"); expect(header.detail).toContain(t("operations.agent_collection.failed", { agent: `${agent.name} · ${t("operations.agent_collection.no_domain")}` }));
  expect(header.detail).toContain(t("operations.agent_collection.accepted_loss"));
});


it.each(["ru", "en"] as const)("labels failed diagnostics as partial with dated last-known facts (%s)", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  const partial: AgentCollectionHealth = { ...data, state: "partial", items: [{ ...agent, state: "unknown", connection: "unknown" }],
    diagnostics: { state: "unavailable", reason: "timeout" } };
  expect(agentCollectionHeader(partial).state).toBe("partial");
  expect(agentCollectionHeader(partial).detail).toContain(t("operations.agent_collection.diagnostics_unavailable"));
  expect(agentCollectionHeader(partial).detail).not.toContain(t("operations.agent_collection.unavailable"));
  expect(agentCollectionDetail(partial.items[0], "UTC")).toContain(t("operations.agent_collection.last_known"));
});


it.each(["ru", "en"] as const)("identifies the delayed agent without treating last import as the start (%s)", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  const delayed = { ...agent, id: "delayed", name: "delayed-host", state: "lagging" as const, href: "/app/agents#delayed", last_seen: "2026-10-10T11:30:00Z", last_packet_at: "2026-10-10T11:40:00Z" };
  const result = agentCollectionHeader({ ...data, state: "partial", items: [{ ...agent, state: "current" }, delayed] });
  expect(result.detail).toContain("delayed-host");
  expect(result.detail).not.toContain("11:30");
  expect(result.detail).not.toContain("11:40");
  expect(result.href).toBe(delayed.href);
});


it.each(["ru", "en"] as const)("does not assign a last-contact time as the failure start (%s)", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  const result = agentCollectionHeader(data);
  expect(result.detail).toContain(locale === "ru" ? "время начала неизвестно" : "start time unknown");
  expect(result.detail).not.toContain("2026-10-09");
});
