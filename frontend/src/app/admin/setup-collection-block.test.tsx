// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { SetupPage } from "./setup";
import { localeRuntime, setLocale, t } from "../../i18n";

const state = vi.hoisted(() => ({ status: vi.fn() }));
vi.mock("../App", () => ({ useEffectiveAccess: () => undefined, useTimeZone: () => ({ timeZone: "UTC", setTimeZone: () => undefined }) }));
vi.mock("../../api/client", async (original) => {
  const actual = await original<typeof import("../../api/client")>();
  return { ...actual, api: { ...actual.api, setupStatus: () => state.status() } };
});
beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => {}); });
afterEach(() => { cleanup(); vi.clearAllMocks(); setLocale("ru"); vi.restoreAllMocks(); });

function mount(reason: string | null, enabled = false, action?: "configure" | "check_configuration" | "enable") {
  state.status.mockResolvedValue({ api_version: "v1", generated_at_utc: "2026-01-02T00:00:00Z", read_only: true,
    steps: [{ id: "first-collection", title: "Collection", state: "unavailable", summary: "Unavailable" }, ...(action ? [{ id: "sources", title: "Sources", state: "unavailable", summary: "Unavailable" }] : [])],
    sources: action ? [{ pack_id: "sli.windows.vpn-radius", display_name: "VPN", version: "1", instances: [{ source_instance_id: "fixture.invalid", configured: false, enabled: false, data_state: "unavailable", next_action: action }] }] : [], domains: [], domain_controllers: [], report_domain: null,
    collection: { collection_enabled: enabled, block_reason: reason, channels: 1, last_success_utc: null },
  });
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><SetupPage/></QueryClientProvider>);
}

it.each(["ru", "en"] as const)("explains denied access in %s and keeps code only in collapsed details", async (locale) => {
  setLocale(locale);
  mount("windows_event_log_access_denied");
  expect(await screen.findByText(t("setup.collectionBlock.accessDenied"))).toBeTruthy();
  const code = screen.getByText("windows_event_log_access_denied");
  expect(code.tagName).toBe("CODE");
  expect(code.closest("details")?.open).toBe(false);
  expect(screen.queryAllByRole("button")).toHaveLength(0);
});

it.each(["windows_security_context_invalid", "future_failure", null])("keeps blocked state honest for %s", async (reason) => {
  mount(reason);
  expect(await screen.findByText(t(reason === "windows_security_context_invalid" ? "setup.collectionBlock.securityContext" : "setup.collectionBlock.unknown"))).toBeTruthy();
  if (reason) expect(screen.getByText(reason).closest("details")?.open).toBe(false);
  else expect(document.querySelector("code")).toBeNull();
  expect(screen.getByText(t("setup.details.no"))).toBeTruthy();
});

it("does not show a stale block reason when collection is allowed", async () => {
  mount("windows_event_log_access_denied", true);
  expect(await screen.findByText(t("setup.details.yes"))).toBeTruthy();
  expect(screen.queryByText("windows_event_log_access_denied")).toBeNull();
  expect(screen.queryByText(t("setup.collectionBlock.accessDenied"))).toBeNull();
});

it.each(["ru", "en"] as const)("names the existing Plugins destination without promising a connection form (%s)", async (locale) => {
  setLocale(locale);
  mount(null, false, "configure");
  expect(await screen.findByText(t("setup.source.next.configure"))).toBeTruthy();
  expect(screen.getByRole("link", { name: t("plugins.title") }).getAttribute("href")).toBe("/app/plugins");
  expect(screen.queryByText(/Sources and plugins|Источники и плагины/)).toBeNull();
});


it.each(["ru", "en"] as const)("uses current agent evidence instead of the legacy block (%s)", async (locale) => {
  setLocale(locale);
  state.status.mockResolvedValue({ api_version: "v1", read_only: true, generated_at_utc: "2026-01-02T00:00:00Z",
    steps: [{ id: "first-collection", title: "Collection", state: "todo", summary: "Legacy summary" }],
    sources: [], domains: [], domain_controllers: [], report_domain: null,
    collection: { collection_enabled: false, block_reason: "windows_event_log_access_denied", channels: 1, last_success_utc: null },
    agent_collection: { state: "current", checked_at_utc: "2026-01-02T00:00:00Z", active_agents: 1, current_agents: 1, items: [] },
  });
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><SetupPage/></QueryClientProvider>);
  expect(await screen.findByText(t("setup.agentCollection.current"))).toBeTruthy();
  expect(screen.queryByText(t("setup.details.collectionAllowed"))).toBeNull();
  expect(screen.queryByText(t("setup.collectionBlock.accessDenied"))).toBeNull();
  expect(screen.queryByText("windows_event_log_access_denied")).toBeNull();
  expect(screen.queryByText("Legacy summary")).toBeNull();
});

it.each(["error", "partial", "unknown", "unavailable"] as const)("does not turn %s into working collection", async (healthState) => {
  state.status.mockResolvedValue({ api_version: "v1", read_only: true, generated_at_utc: "2026-01-02T00:00:00Z",
    steps: [{ id: "first-collection", title: "Collection", state: "done", summary: "Old fresh snapshot" }],
    sources: [], domains: [], domain_controllers: [], report_domain: null, collection: null,
    agent_collection: { state: healthState, checked_at_utc: "2026-01-02T00:00:00Z", active_agents: 1, current_agents: 0, items: [] },
  });
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><SetupPage/></QueryClientProvider>);
  expect(await screen.findByText(t(`setup.agentCollection.${healthState}`))).toBeTruthy();
  expect(screen.queryByText(t("setup.agentCollection.current"))).toBeNull();
  expect(screen.queryByText("Old fresh snapshot")).toBeNull();
});

it("routes an empty agent-backed source to agents instead of legacy controller configuration", async () => {
  state.status.mockResolvedValue({ api_version: "v1", read_only: true, generated_at_utc: "2026-01-02T00:00:00Z",
    steps: [{ id: "sources", title: "Sources", state: "todo", summary: "" }],
    sources: [{ pack_id: "sli.windows.ad-dc", display_name: "AD", version: "1", source_kind: "event",
      collection_basis: "agents", configured: false, activation_state: "disabled", enabled: false, data_state: "never", instances: [] }],
    domains: [], domain_controllers: [], report_domain: null, collection: null,
  });
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><SetupPage/></QueryClientProvider>);
  expect(await screen.findByText(t("setup.agentSource.next"))).toBeTruthy();
  expect(screen.getByRole("link", { name: t("agents.title") }).getAttribute("href")).toBe("/app/agents");
});

it("keeps accepted historical gaps inside details even when current delivery works", async () => {
  state.status.mockResolvedValue({ api_version: "v1", read_only: true, generated_at_utc: "2026-01-02T00:00:00Z",
    steps: [{ id: "first-collection", title: "Collection", state: "done", summary: "" }],
    sources: [], domains: [], domain_controllers: [], report_domain: null, collection: null,
    agent_collection: { state: "current", checked_at_utc: "2026-01-02T00:00:00Z", active_agents: 1,
      current_agents: 1, items: [], completeness: { state: "known_gaps" } },
  });
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><SetupPage/></QueryClientProvider>);
  expect(await screen.findByText(t("setup.agentCollection.current"))).toBeTruthy();
  expect(screen.getByText(t("operations.agent_collection.accepted_loss")).closest("details")?.open).toBe(false);
});

it.each(["ru", "en"] as const)("shows each agent's collection state outside technical details (%s)", async (locale) => {
  setLocale(locale);
  const agent = { id: "synthetic-agent", host_id: "synthetic-host", name: "fixture-host", domains: [],
    state: "current", connection: "online", last_seen: null, last_packet_at: null,
    policy_revision: 1, applied_policy_revision: 1, modules: [], href: "/app/agents?agent_id=synthetic-agent" };
  state.status.mockResolvedValue({ api_version: "v1", read_only: true, generated_at_utc: "2026-10-25T00:00:00Z",
    steps: [{ id: "first-collection", title: "Collection", state: "done", summary: "" }],
    sources: [], domains: [], domain_controllers: [], report_domain: null, collection: null,
    agent_collection: { state: "current", checked_at_utc: "2026-10-25T00:00:00Z", active_agents: 1,
      current_agents: 1, items: [agent] },
  });
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><SetupPage/></QueryClientProvider>);
  const link = await screen.findByRole("link", { name: "fixture-host" });
  expect(link.closest("details")).toBeNull();
  expect(link.parentElement?.textContent).toContain(t("operations.agent_collection.state.current"));
  const technical = screen.getByText((content, node) => node?.tagName === "P"
    && content.includes(t("agents.revisions", { desired: 1, applied: 1 })));
  expect(technical.closest("details")?.open).toBe(false);
});
