// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import type { AgentItem } from "../../api/client";
import { t } from "../../i18n";
import { AgentEventlogDiagnostics } from "./agent-eventlog-diagnostics";

const agent = { id: "fixture", applied_policy_revision: 3 } as AgentItem;
const item = { channel: "Security", observed_at_utc: "2026-10-11T00:00:00Z", policy_revision: 3,
  error: { exception_class: "error", winerror: 15011, hresult: -2147024891,
    channel: "Security", record_id: 7127010, bookmark_present: true, stage: "seek" } };
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("shows missing diagnostics as awaiting, not successful", () => {
  render(<AgentEventlogDiagnostics agent={agent}/>);
  expect(screen.getByText(t("agents.eventlog.awaiting"))).toBeTruthy();
  expect(screen.queryByText(t("agents.eventlog.ok"))).toBeNull();
});

it("shows native codes, bookmark position and current error", () => {
  vi.spyOn(Date, "now").mockReturnValue(Date.parse(item.observed_at_utc));
  render(<AgentEventlogDiagnostics agent={{ ...agent, eventlog_diagnostics: { reported_at: item.observed_at_utc, items: [item] } }}/>);
  expect(screen.getByText(/Win32: 15011/).textContent).toContain("0x80070005");
  expect(screen.getByText(/Record ID: 7127010/).textContent).toContain("seek");
  expect(screen.queryByRole("status")).toBeNull();
});

it("marks stale observations and preserves their error details", () => {
  vi.spyOn(Date, "now").mockReturnValue(Date.parse(item.observed_at_utc) + 3600_000);
  render(<AgentEventlogDiagnostics agent={{ ...agent, eventlog_diagnostics: { reported_at: item.observed_at_utc, items: [item] } }}/>);
  expect(screen.getByRole("status").textContent).toBe(t("agents.eventlog.stale"));
  expect(screen.getByText(/Win32: 15011/)).toBeTruthy();
});

it("successful reads clear the error without claiming report completeness", () => {
  render(<AgentEventlogDiagnostics agent={{ ...agent, eventlog_diagnostics: { reported_at: item.observed_at_utc, items: [{ ...item, error: null }] } }}/>);
  expect(screen.getByText(new RegExp(t("agents.eventlog.ok")))).toBeTruthy();
  expect(screen.queryByText(/Win32:/)).toBeNull();
  expect(screen.queryByText(/не подтверждает полноту|does not confirm completeness/)).toBeNull();
});
