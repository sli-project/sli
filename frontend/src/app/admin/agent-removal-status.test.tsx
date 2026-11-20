// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import type { AgentItem } from "../../api/client";
import { localeRuntime, setLocale, t } from "../../i18n";
import { AgentRemovalStatus } from "./agent-removal-status";

const removal: NonNullable<AgentItem["removal"]> = {
  operation_id: "00000000-0000-4000-8000-000000000001", command_id: "00000000-0000-4000-8000-000000000002",
  state: "pending", reason: null, connection: "offline", requested_at: "2026-10-09T00:00:00Z", reported_at: null,
};
beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });

it.each(["ru", "en"] as const)("shows offline remainder separately from revocation in %s", (locale) => {
  setLocale(locale);
  render(<AgentRemovalStatus removal={removal}/>);
  expect(screen.getByText(t("agents.removal.pending"))).toBeTruthy();
  expect(screen.getByText(t("agents.removal.offline"))).toBeTruthy();
  expect(screen.getByText(t("agents.removal.historyRetained"))).toBeTruthy();
  expect(screen.queryByText(t("agents.removal.state_cleaned"))).toBeNull();
});

it("shows native failure without claiming cleanup", () => {
  render(<AgentRemovalStatus removal={{ ...removal, state: "cleanup_failed", reason: "agent_removal_requires_admin", connection: "never_seen" }}/>);
  expect(screen.getByText(t("agents.removal.cleanup_failed"))).toBeTruthy();
  expect(screen.getByText(t("agents.removal.agent_removal_requires_admin"))).toBeTruthy();
  expect(screen.getByText(t("agents.removal.never_seen"))).toBeTruthy();
});

it("shows reported state cleanup without treating it as an installed rehearsal", () => {
  render(<AgentRemovalStatus removal={{ ...removal, state: "state_cleaned", connection: "online" }}/>);
  expect(screen.getByText(t("agents.removal.state_cleaned"))).toBeTruthy();
  expect(screen.queryByText(t("agents.removal.pending"))).toBeNull();
});

it("does not imply removal for an ordinary disabled agent", () => {
  const { container } = render(<AgentRemovalStatus removal={null}/>);
  expect(container.textContent).toBe("");
});
