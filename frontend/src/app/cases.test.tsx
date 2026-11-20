// @vitest-environment jsdom
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { InvestigationCaseSummary, V4Access } from "../api/client";

const state = vi.hoisted(() => ({ access: undefined as unknown }));

vi.mock("./App", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./App")>()),
  useEffectiveAccess: () => state.access,
  useTimeZone: () => ({ timeZone: "UTC" }),
}));
vi.mock("../design-system", async (importOriginal) => ({ ...(await importOriginal<typeof import("../design-system")>()), useOverlays: () => ({ toast: () => undefined }) }));

import { CaseListPage } from "./cases";
import { localeRuntime, setLocale, t } from "../i18n";

const access = (capabilities: string[], allowed = true) => ({
  capabilities,
  reports: [{ report_key: "cases.workspace", allowed }],
}) as unknown as V4Access;

const cases: InvestigationCaseSummary[] = [
  { id: 41, public_id: "00000000-0000-0000-0000-000000000041", title: "Проверка VPN", status: "open", owner: "analyst", created_by: "system", created_at: "2026-09-10T10:00:00Z", updated_at: "2026-09-11T10:00:00Z", evidence_count: 2 },
  { id: 42, title: "Без ответственного", status: "closed", owner: null, created_by: "system", created_at: "2026-09-10T10:00:00Z", updated_at: "2026-09-11T11:00:00Z" },
];

async function render() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["v4", "cases"], { items: cases, limit: 50 });
  const root = createRootRoute();
  const list = createRoute({ getParentRoute: () => root, path: "/investigations", component: CaseListPage });
  const detail = createRoute({ getParentRoute: () => root, path: "/investigations/$investigationId", component: () => null });
  const router = createRouter({ routeTree: root.addChildren([list, detail]), basepath: "/app", history: createMemoryHistory({ initialEntries: ["/app/investigations"] }) });
  await router.load();
  return renderToStaticMarkup(<QueryClientProvider client={client}><RouterProvider router={router}/></QueryClientProvider>);
}

beforeEach(() => { state.access = undefined; vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });

it.each(["ru", "en"] as const)("localizes evidence counts but preserves case titles in %s", async (locale) => {
  setLocale(locale);
  state.access = access(["investigations.view"]);
  const original = cases[0];
  try {
    for (const [count, ru, en] of [[1, "1 доказательство", "1 evidence item"], [2, "2 доказательства", "2 evidence items"], [5, "5 доказательств", "5 evidence items"], [11, "11 доказательств", "11 evidence items"]] as const) {
      cases[0] = { ...original, evidence_count: count };
      const html = await render();
      expect(html).toContain(locale === "ru" ? ru : en);
      expect(html).toContain(original.title);
      if (locale === "en") expect(html).not.toContain("доказательств");
    }
    cases[0] = { ...original, evidence_count: null };
    expect(await render()).toContain(t("investigations.cases.evidenceInCard"));
  } finally { cases[0] = original; }
});

it.each(["ru", "en"] as const)("renders server-coded case statuses in the current %s locale", async (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  state.access = access(["investigations.view"]);
  const before = cases[0];
  cases[0] = { ...before, status: "review", status_message: { code: "investigations.caseStatus.review", params: {}, text: "other language" } };
  try {
    const html = await render();
    expect(html).toContain(t("investigations.caseStatus.review"));
    expect(html).not.toContain("other language");
  } finally { cases[0] = before; }
});

it("lists the cases with links to the case page", async () => {
  state.access = access(["investigations.manage"]);
  const html = await render();
  expect(html).toContain("Расследования");
  expect(html).toContain("Проверка VPN");
  expect(html).toContain('href="/app/investigations/41"');
  expect(html).toContain('href="/app/investigations/42"');
  expect(html).toContain("INV-0000041");
  expect(html).toContain("INV-0000042");
  expect(html).not.toContain("00000000-0000-0000-0000-000000000041");
  expect(html).toContain("не назначен");
  expect(html).toContain("Создать дело");
});

it("hides the create button without the manage capability", async () => {
  state.access = access(["investigations.view"]);
  const html = await render();
  expect(html).toContain("Проверка VPN");
  expect(html).not.toContain("Создать дело");
});

it("shows the denied page when the workspace report is not granted", async () => {
  state.access = access(["investigations.manage"], false);
  const html = await render();
  expect(html).toContain("data-state=\"denied\"");
  expect(html).toContain("не назначен");
  expect(html).not.toContain("Проверка VPN");
});
