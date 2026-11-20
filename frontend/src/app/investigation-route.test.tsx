import { renderToStaticMarkup } from "react-dom/server";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { expect, it, vi } from "vitest";

vi.mock("./investigation-workspace", () => ({
  InvestigationWorkspacePage: () => <main>INVESTIGATION_WORKSPACE</main>,
}));

vi.mock("./cases", () => ({
  CaseListPage: () => <main>CASE_LIST</main>,
}));

import { InvestigationsRoutePage } from "./investigation-route";

async function renderRoute(search = "") {
  const root = createRootRoute();
  const investigations = createRoute({
    getParentRoute: () => root,
    path: "/investigations",
    component: InvestigationsRoutePage,
  });
  const router = createRouter({
    routeTree: root.addChildren([investigations]),
    basepath: "/app",
    history: createMemoryHistory({ initialEntries: [`/app/investigations${search}`] }),
  });
  await router.load();
  return renderToStaticMarkup(<RouterProvider router={router}/>);
}

it("opens the investigation workspace for a bare exact entity context", async () => {
  const html = await renderRoute("?entity_id=2607216");
  expect(html).toContain("INVESTIGATION_WORKSPACE");
  expect(html).not.toContain("CASE_LIST");
});

it("keeps the case list for an empty investigations URL", async () => {
  const html = await renderRoute();
  expect(html).toContain("CASE_LIST");
  expect(html).not.toContain("INVESTIGATION_WORKSPACE");
});

it.each([
  "?q=evidence-reader",
  "?event_db_id=517548",
  "?time_from=2026-09-10T12%3A00%3A00.123456Z",
  "?scope=important",
])("preserves the existing workspace routes for %s", async (search) => {
  expect(await renderRoute(search)).toContain("INVESTIGATION_WORKSPACE");
});
