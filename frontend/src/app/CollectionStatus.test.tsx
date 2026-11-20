// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import type { AgentCollectionHealth } from "../api/client";
import { OverlayProvider } from "../design-system";
import { localeRuntime, setLocale, t } from "../i18n";
import { CollectionStatus } from "./CollectionStatus";

const agent: AgentCollectionHealth["items"][number] = {
  id: "fixture-agent", host_id: "fixture-host", name: "PC-01", domains: [], state: "unknown",
  connection: "online", last_seen: "2026-10-30T00:00:00Z", last_packet_at: "2026-10-30T00:00:00Z",
  policy_revision: 1, applied_policy_revision: 1, modules: [], href: "/app/agents#agent-fixture-agent",
};
const health: AgentCollectionHealth = {
  state: "partial", active_agents: 7, current_agents: 0, items: [agent], checked_at_utc: "2026-10-30T00:00:00Z",
  diagnostics: { state: "unavailable", reason: "timeout" },
};
const show = (data: AgentCollectionHealth | null, canManageAgents = false) => render(
  <OverlayProvider><header><CollectionStatus data={data} timeZone="UTC" canManageAgents={canManageAgents}/></header></OverlayProvider>,
);
afterEach(() => { cleanup(); vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru"); vi.restoreAllMocks(); });

it.each(["ru", "en"] as const)("keeps diagnostic failure details off the shell and accessible on demand (%s)", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  show(health);
  const status = within(screen.getByRole("banner")).getByRole("status");
  expect(status.textContent).toBe(t("shell.collection.silent_one", { name: "PC-01" }));
  expect(status.textContent).not.toContain(t("operations.agent_collection.diagnostics_unavailable"));
  expect(screen.queryByRole("dialog")).toBeNull();
  const trigger = within(status).getByRole("button", { name: t("shell.collection.silent_one", { name: "PC-01" }) });
  trigger.focus(); fireEvent.click(trigger);
  const drawer = screen.getByRole("dialog");
  expect(drawer.textContent).toContain(t("operations.agent_collection.diagnostics_unavailable"));
  expect(drawer.textContent).toContain(t("operations.agent_collection.reason.check_timeout"));
  expect(within(drawer).queryByRole("link")).toBeNull();
  fireEvent.keyDown(document, { key: "Escape" });
  expect(screen.queryByRole("dialog")).toBeNull();
});

it.each(["ru", "en"] as const)("names a silent agent and offers its navigation to administrators (%s)", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  show({ ...health, diagnostics: undefined, current_agents: 6, items: [{ ...agent, state: "error" }] }, true);
  const status = within(screen.getByRole("banner")).getByRole("status");
  expect(status.textContent).toContain(t("shell.collection.silent_one", { name: "PC-01" }));
  expect(status.textContent).toContain("PC-01");
  fireEvent.click(within(status).getByRole("button"));
  const drawer = screen.getByRole("dialog");
  expect(drawer.textContent).toContain("PC-01");
  expect(within(drawer).getByRole("link", { name: t("operations.agent_collection.open") }).getAttribute("href")).toBe(agent.href);
});

it.each([null, { ...health, items: [] }, { ...health, items: [
  { ...agent, state: "current" as const }, { ...agent, id: "paused", state: "paused" as const }, { ...agent, id: "disabled", state: "disabled" as const },
] }])("hides the indicator without silent sources", (data) => {
  show(data);
  expect(within(screen.getByRole("banner")).queryByRole("status")).toBeNull();
});

it.each(["ru", "en"] as const)("counts silent sources and opens their list (%s)", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  show({ ...health, items: [agent, { ...agent, id: "second-agent", name: "PC-02", state: "lagging" }, { ...agent, id: "healthy", name: "PC-03", state: "current" }] });
  const status = within(screen.getByRole("banner")).getByRole("status");
  expect(status.textContent).toBe(t("shell.collection.silent_many", { count: 2 }));
  fireEvent.click(within(status).getByRole("button"));
  const drawer = screen.getByRole("dialog");
  expect(within(drawer).getByRole("heading", { name: "PC-01" })).toBeTruthy();
  expect(within(drawer).getByRole("heading", { name: "PC-02" })).toBeTruthy();
  expect(drawer.textContent).not.toContain("PC-03");
});
