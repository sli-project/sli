// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { localeRuntime, setLocale, t } from "../i18n";

const state = vi.hoisted(() => ({ canManage: true, toast: vi.fn() }));
vi.mock("./App", () => ({ useEffectiveAccess: () => ({ capabilities: state.canManage ? ["investigations.manage"] : [] }) }));
vi.mock("../design-system", () => ({ useOverlays: () => ({ toast: state.toast }) }));
vi.mock("./problem-case-actions", () => ({ ProblemCaseActions: () => null }));

import { ProblemLifecycle, statusLabel } from "./problem-lifecycle";

beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("en");
  state.canManage = true;
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); state.toast.mockReset(); });

function mount(row: Record<string, unknown> = {}) {
  const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><ProblemLifecycle row={{ id: 1, status: "new",
    allowed_statuses: ["new", "active", "review", "confirmed", "false_positive", "closed", "repeated"], ...row }} formatTime={() => "fixture time"}/></QueryClientProvider>);
}

it("renders the English decision form and standard history while preserving comments", () => {
  mount({ status_history: [
    { id: 1, new_status: "new", changed_by: "semantic-worker", note: "created from enabled semantic scenario" },
    { id: 2, new_status: "active", changed_by: "system", note: "created from event" },
    { id: 3, new_status: "repeated", changed_by: "system", note: "repeat evidence added" },
    { id: 4, new_status: "review", changed_by: "fixture-user", note: "Комментарий пользователя" },
    { id: 5, new_status: "review", changed_by: "fixture-user", note: "created from event" },
  ] });
  expect(screen.getByRole("region", { name: "Problem decision" })).toBeTruthy();
  expect(screen.getByRole("heading", { name: "Decision history" })).toBeTruthy();
  expect(screen.getByRole("heading", { name: "Change status" })).toBeTruthy();
  expect(screen.getAllByRole("option").map((option) => option.textContent)).toEqual([
    "Open", "In progress", "False positive",
  ]);
  expect(screen.getByLabelText("Owner").getAttribute("placeholder")).toBe("Account or team");
  expect(screen.getByLabelText("Comment").getAttribute("placeholder")).toBe("Why this decision was made");
  const history = screen.getByRole("list").textContent!;
  expect(history).toContain(`${t("reports.problemLifecycle.semanticWorker")} · ${t("reports.problemLifecycle.created")}`);
  expect(history).toContain("System · Created from an event");
  expect(history).toContain("System · Repeat evidence added");
  expect(history).toContain("fixture-user · Комментарий пользователя");
  expect(history).toContain("fixture-user · created from event");
  expect(statusLabel("unknown-code")).toBe("—");
  expect(screen.getByRole("button", { name: "Save decision" })).toBeTruthy();
});

it("submits unchanged comments and shows English success and failure notifications", async () => {
  const update = vi.spyOn(api, "updateFinding").mockResolvedValue({ status: "ok", changed: true, finding: {} } as never);
  mount({ title_text: "Fixture problem" });
  expect(screen.queryByRole("heading", { name: "Decision history" })).toBeNull();
  fireEvent.change(screen.getByLabelText("Comment"), { target: { value: "Комментарий пользователя" } });
  fireEvent.change(screen.getByLabelText("Status"), { target: { value: "active" } });
  fireEvent.click(screen.getByRole("button", { name: "Save decision" }));
  await waitFor(() => expect(update).toHaveBeenCalledWith(1, { status: "active", note: "Комментарий пользователя" }));
  await waitFor(() => expect(state.toast).toHaveBeenCalledWith("Decision saved", "Status, owner and history confirmed by reading the report again."));
  update.mockRejectedValue(new Error("fixture failure"));
  fireEvent.click(screen.getByRole("button", { name: "Save decision" }));
  await waitFor(() => expect(state.toast).toHaveBeenCalledWith("Could not change the problem status", "Fixture problem"));
});

it.each([
  ["fixture-team", "", { assigned_to: null }],
  ["fixture-team", "   ", { assigned_to: null }],
  ["fixture-team", " fixture-other-team ", { assigned_to: "fixture-other-team" }],
  ["fixture-team", " fixture-team ", {}],
])("submits an explicit assignment change from %s to %s", async (assignedTo, input, assignment) => {
  const update = vi.spyOn(api, "updateFinding").mockResolvedValue({ status: "ok", changed: false, finding: {} } as never);
  mount({ assigned_to: assignedTo });
  fireEvent.change(screen.getByLabelText("Comment"), { target: { value: "Fixture reason" } });
  fireEvent.change(screen.getByLabelText("Owner"), { target: { value: input } });
  fireEvent.click(screen.getByRole("button", { name: "Save decision" }));
  await waitFor(() => expect(update).toHaveBeenCalledWith(1, { status: "new", note: "Fixture reason", ...assignment }));
});

it("renders the English pending and denied states", async () => {
  vi.spyOn(api, "updateFinding").mockImplementation(() => new Promise(() => undefined));
  mount();
  fireEvent.change(screen.getByLabelText("Comment"), { target: { value: "Fixture reason" } });
  fireEvent.click(screen.getByRole("button", { name: "Save decision" }));
  const pending = await screen.findByRole("button", { name: "Saving…" });
  expect((pending as HTMLButtonElement).disabled).toBe(true);
  cleanup();
  state.canManage = false;
  mount();
  expect(screen.getByText("The current user is not allowed to change the status.")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Save decision" })).toBeNull();
});

it("still requires a comment for changes made through the status and assignment form", () => {
  const update = vi.spyOn(api, "updateFinding");
  mount();
  expect((screen.getByLabelText("Comment") as HTMLInputElement).required).toBe(true);
  fireEvent.change(screen.getByLabelText("Status"), { target: { value: "active" } });
  fireEvent.submit(screen.getByRole("button", { name: "Save decision" }).closest("form")!);
  expect(update).not.toHaveBeenCalled();
});
