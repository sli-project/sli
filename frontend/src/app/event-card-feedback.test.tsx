// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRootRoute, createRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { afterEach, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { localeRuntime, setLocale, t } from "../i18n";
import { EventCardPage, EventCaseMutationOutcome } from "./event-card";

afterEach(() => { cleanup(); vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale("ru"); vi.restoreAllMocks(); });

it.each(["ru", "en"] as const)("always acknowledges creation and links exact evidence in %s without trusting unsafe return context", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); setLocale(locale);
  render(<EventCaseMutationOutcome caseId={71} eventDbId={41} returnTo="https://evil.test/" action="create"/>);
  const link = screen.getByRole("link");
  expect(link.textContent).toContain("INV-0000071");
  expect(link.getAttribute("href")).toBe("/app/investigations/71?event_db_id=41");
  expect(screen.getByRole("status").textContent).toContain(locale === "ru" ? "Дело создано" : "Case created");
});

it.each([false, true])("invalidates cache and binds success to the submitted event (navigate while pending: %s)", async (navigatePending) => {
  vi.stubGlobal("scrollTo", vi.fn());
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["bootstrap"], { effective_role: "viewer" });
  for (const id of [41, 42]) {
    client.setQueryData(["event", String(id)], { item: { event_db_id: id, event_id: 4624, event_data: {}, time_created_utc: null } });
    client.setQueryData(["event-relations", String(id)], { items: [] });
    client.setQueryData(["event-entities", String(id)], { items: [] });
    client.setQueryData(["semantic-event-actions", `event_db_id=${id}`], { state: "empty", items: [] });
    client.setQueryData(["semantic-event-scenarios", `event_db_id=${id}`], { state: "empty", items: [] });
  }
  client.setQueryData(["investigation-cases"], { items: [] });
  const list = vi.spyOn(api, "investigationCases").mockResolvedValue({ items: [], limit: 100 });
  let resolveCreate!: (value: Awaited<ReturnType<typeof api.createInvestigation>>) => void;
  const create = vi.spyOn(api, "createInvestigation").mockImplementation(() => new Promise((resolve) => { resolveCreate = resolve; }));
  const root = createRootRoute();
  const event = createRoute({ getParentRoute: () => root, path: "/events/$eventId", component: EventCardPage });
  const investigations = createRoute({ getParentRoute: () => root, path: "/investigations", component: () => null });
  const router = createRouter({ routeTree: root.addChildren([event, investigations]), basepath: "/app", history: createMemoryHistory({ initialEntries: ["/app/events/41"] }) });
  await router.load(); render(<QueryClientProvider client={client}><RouterProvider router={router}/></QueryClientProvider>);
  const button = await screen.findByRole("button", { name: t("events.card.investigationCreateSubmit") }) as HTMLButtonElement;
  fireEvent.submit(button.closest("form")!);
  fireEvent.submit(button.closest("form")!);
  await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
  if (navigatePending) await act(() => router.navigate({ to: "/events/$eventId", params: { eventId: "42" } }));
  await act(async () => resolveCreate({ id: 71 } as Awaited<ReturnType<typeof api.createInvestigation>>));
  if (navigatePending) {
    expect(document.querySelector('[data-case-mutation="create"]')).toBeNull();
    await act(() => router.navigate({ to: "/events/$eventId", params: { eventId: "41" } }));
  }
  await waitFor(() => expect(document.querySelector('[data-case-mutation="create"]')).not.toBeNull());
  const completedButton = screen.getByRole("button", { name: t("events.card.investigationCreateSubmit") }) as HTMLButtonElement;
  expect(completedButton.disabled).toBe(true);
  fireEvent.submit(completedButton.closest("form")!);
  expect(create).toHaveBeenCalledTimes(1);
  await waitFor(() => expect(list).toHaveBeenCalled());
  await act(() => router.navigate({ to: "/events/$eventId", params: { eventId: "42" } }));
  await waitFor(() => expect(document.querySelector('[data-case-mutation="create"]')).toBeNull());
  expect((screen.getByRole("button", { name: t("events.card.investigationCreateSubmit") }) as HTMLButtonElement).disabled).toBe(false);
  client.clear(); vi.unstubAllGlobals();
});
