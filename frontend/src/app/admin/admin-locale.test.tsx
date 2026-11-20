// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { localeRuntime, setLocale } from "../../i18n";
import { AdminPage } from "./admin";

vi.mock("../App", () => ({ useTimeZone: () => ({ timeZone: "UTC" }) }));

afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });

it.each(["ru", "en"] as const)("localizes builtin role descriptions, not custom roles, in %s", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale(locale);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  client.setQueryData(["bootstrap"], { effective_role: "admin" });
  client.setQueryData(["admin-users"], { items: [], roles: [
    { id: "viewer", label: "ИБ", description: "Расследования, события и отчёты ИБ" },
    { id: "operator", label: "ИТ", description: "Отчёты ИБ и эксплуатационные отчёты" },
    { id: "admin", label: "Администратор", description: "Полный доступ и управление пользователями" },
    { id: "custom", label: "Собственная роль", description: "Исходное описание" },
    { id: "__proto__", label: "Future role", description: "Future description" },
  ] });
  client.setQueryData(["admin-api-keys"], { items: [] });
  render(<QueryClientProvider client={client}><AdminPage/></QueryClientProvider>);
  for (const text of locale === "en" ? ["InfoSec", "IT", "Administrator", "Investigations, events and InfoSec reports", "InfoSec and operational reports", "Full access and user management"] : ["ИБ", "ИТ", "Администратор", "Расследования, события и отчёты ИБ"]) {
    expect(screen.getAllByText(text).length).toBeGreaterThan(0);
  }
  expect(screen.getAllByText("Собственная роль").length).toBeGreaterThan(0);
  expect(screen.getByText("Исходное описание")).toBeTruthy();
  expect(screen.getAllByText("Future role").length).toBeGreaterThan(0);
  if (locale === "en") expect(screen.queryByText("Расследования, события и отчёты ИБ")).toBeNull();
});
