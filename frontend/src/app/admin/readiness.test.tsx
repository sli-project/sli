// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { localeRuntime, setLocale, t } from "../../i18n";
import { ProjectReadinessPage } from "./readiness";

vi.mock("../App", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../App")>()),
  useEffectiveAccess: () => ({ reports: [{ report_key: "operations.readiness", allowed: true }] }),
  useTimeZone: () => ({ timeZone: "UTC" }),
}));

afterEach(() => { cleanup(); window.history.replaceState({}, "", "/"); });

it.each(["ru", "en"] as const)("keeps the archive action and omits duplicate agent and worker summaries in %s", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  try {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
    client.setQueryData(["v4", "operations", "readiness"], {
      postgres: { available: true }, storage: {}, workers: { items: [{ state: "active" }] },
      archive: { status: "invalid_root" },
      agent_collection: { state: "error", active_agents: 1, current_agents: 0, items: [{ name: "fixture-host", domains: ["example.test"] }] },
    });
    const { container } = render(<QueryClientProvider client={client}><ProjectReadinessPage/></QueryClientProvider>);
    expect(screen.getByRole("heading", { name: t("operations.readiness.title"), level: 1 })).toBeTruthy();
    expect(screen.getAllByRole("row")).toHaveLength(2);
    expect(container.textContent).not.toContain("fixture-host");
    expect(screen.getByText(t("operations.readiness.archive.correctRoot"))).toBeTruthy();
    expect(screen.getByRole("row", { name: new RegExp(t("operations.readiness.archive.name")) }).textContent)
      .toContain(t("operations.readiness.archive.invalidRoot"));
    if (locale === "en") expect(container.textContent).not.toMatch(/[А-Яа-яЁё]/);
  } finally { cleanup(); setLocale("ru"); vi.restoreAllMocks(); }
});
