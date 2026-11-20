// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { InvestigationCaseSummary } from "../api/client";

const state = vi.hoisted(() => ({
  capabilities: ["investigations.manage"] as string[],
  navigate: vi.fn(),
  toast: vi.fn(),
}));

vi.mock("./App", () => ({ useEffectiveAccess: () => ({ capabilities: state.capabilities }) }));
vi.mock("../design-system", () => ({ useOverlays: () => ({ toast: state.toast }) }));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => state.navigate,
  Link: ({ children, params, className, onClick }: { children: React.ReactNode; params: { investigationId: string }; className?: string; onClick?: () => void }) =>
    <a className={className} href={`/app/investigations/${params.investigationId}`} onClick={(event) => { event.preventDefault(); onClick?.(); }}>{children}</a>,
}));

import { ApiResponseError, api } from "../api/client";
import { ProblemCaseActions, caseActionErrorMessage, filterOpenCases } from "./problem-case-actions";

const cases: InvestigationCaseSummary[] = [
  { id: 41, title: "Проверка VPN", status: "active", owner: "a", created_by: "a", created_at: "", updated_at: "" },
  { id: 42, title: "Старое дело", status: "closed", owner: "a", created_by: "a", created_at: "", updated_at: "" },
  { id: 43, title: "Вход с нового устройства", status: "new", owner: null, created_by: "a", created_at: "", updated_at: "" },
];

function renderActions(row: Record<string, unknown> = { id: 7 }, onOpen?: () => void) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><ProblemCaseActions row={row} onOpen={onOpen}/></QueryClientProvider>);
}

beforeEach(() => {
  state.capabilities = ["investigations.manage"];
  state.navigate.mockReset().mockResolvedValue(undefined);
  state.toast.mockReset();
  vi.spyOn(api, "investigationCases").mockResolvedValue({ items: cases, limit: 50 });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe("ProblemCaseActions", () => {
  it("shows both actions only with the manage capability", () => {
    renderActions();
    expect(screen.getByRole("button", { name: "Открыть расследование" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Привязать к делу" })).toBeTruthy();
    cleanup();
    state.capabilities = ["investigations.view"];
    renderActions();
    expect(screen.queryByRole("button", { name: "Открыть расследование" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Привязать к делу" })).toBeNull();
  });

  it("creates a case from the problem and navigates to it", async () => {
    const create = vi.spyOn(api, "createInvestigationFromFinding").mockResolvedValue({ id: 55 } as never);
    renderActions();
    await userEvent.click(screen.getByRole("button", { name: "Открыть расследование" }));
    await waitFor(() => expect(state.navigate).toHaveBeenCalled());
    expect(create).toHaveBeenCalledWith(7);
    expect(state.navigate).toHaveBeenCalledWith({ to: "/investigations/$investigationId", params: { investigationId: "55" } });
    expect(state.toast).toHaveBeenCalledWith("Расследование создано", expect.stringContaining("55"));
  });

  it("closes a containing dialog before navigating to a newly created investigation", async () => {
    vi.spyOn(api, "createInvestigationFromFinding").mockResolvedValue({ id: 55 } as never);
    const order: string[] = [];
    state.navigate.mockImplementation(() => { order.push("navigate"); return Promise.resolve(); });
    renderActions({ id: 7 }, () => order.push("close"));
    await userEvent.click(screen.getByRole("button", { name: "Открыть расследование" }));
    await waitFor(() => expect(order).toEqual(["close", "navigate"]));
  });

  it("closes a containing dialog when opening a linked investigation", async () => {
    const onOpen = vi.fn();
    renderActions({ id: 7, linked_case: { id: 55 } }, onOpen);
    await userEvent.click(screen.getByRole("link", { name: "Открыть дело №INV-0000055" }));
    expect(onOpen).toHaveBeenCalledOnce();
  });

  it("picks only open cases, searches them and links the problem", async () => {
    const link = vi.spyOn(api, "linkFindingToInvestigation").mockResolvedValue({ id: 43 } as never);
    renderActions();
    await userEvent.click(screen.getByRole("button", { name: "Привязать к делу" }));
    expect(await screen.findByRole("button", { name: /Проверка VPN/ })).toBeTruthy();
    expect(screen.queryByText(/Старое дело/)).toBeNull();
    await userEvent.type(screen.getByLabelText("Поиск по названию или номеру"), "устройства");
    expect(screen.queryByRole("button", { name: /Проверка VPN/ })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: /Вход с нового устройства/ }));
    await waitFor(() => expect(link).toHaveBeenCalledWith(43, 7));
    expect(state.toast).toHaveBeenCalledWith("Проблема привязана к делу", expect.stringContaining("43"));
    expect((await screen.findByRole("link", { name: "Открыть дело №INV-0000043" })).getAttribute("href")).toBe("/app/investigations/43");
  });

  it("shows a link to the case when the problem is already linked", () => {
    renderActions({ id: 7, linked_case: { id: 41, status: "active" } });
    const link = screen.getByRole("link", { name: "Открыть дело №INV-0000041" });
    expect(link.getAttribute("href")).toBe("/app/investigations/41");
    expect(screen.queryByRole("button", { name: "Открыть расследование" })).toBeNull();
  });

  it("reports a refused action with a readable message", async () => {
    vi.spyOn(api, "createInvestigationFromFinding").mockRejectedValue(new ApiResponseError(409, "finding_already_linked", "raw", { investigation_id: 9 }));
    renderActions();
    await userEvent.click(screen.getByRole("button", { name: "Открыть расследование" }));
    await waitFor(() => expect(state.toast).toHaveBeenCalledWith("Действие с делом не выполнено", "Эта проблема уже связана с делом №INV-0000009."));
    expect(state.navigate).not.toHaveBeenCalled();
  });
});

describe("helpers", () => {
  it("maps server errors to messages", () => {
    expect(caseActionErrorMessage(new ApiResponseError(409, "investigation_case_closed"))).toContain("Дело закрыто");
    expect(caseActionErrorMessage(new ApiResponseError(403, "insufficient_capability"))).toContain("Недостаточно прав");
    expect(caseActionErrorMessage(new ApiResponseError(404, "not_found"))).toContain("не найдены");
    expect(caseActionErrorMessage(new Error("boom"))).toContain("Повторите попытку");
  });

  it("filters out closed cases and matches by number", () => {
    expect(filterOpenCases(cases, "").map((item) => item.id)).toEqual([41, 43]);
    expect(filterOpenCases(cases, "№43").map((item) => item.id)).toEqual([43]);
    expect(filterOpenCases(cases, "INV-0000043").map((item) => item.id)).toEqual([43]);
    expect(filterOpenCases(cases, "42")).toEqual([]);
  });
});
