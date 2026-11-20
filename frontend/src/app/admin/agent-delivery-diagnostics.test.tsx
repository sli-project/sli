// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import type { AgentItem } from "../../api/client";
import { t } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
import { AgentDeliveryDiagnostics } from "./agent-delivery-diagnostics";

const now = "2026-10-23T08:00:00Z";
const item = { module_id: "workstations", packet_id: "12345678-1234-1234-1234-123456789abc", sequence: "9007199254740993", error_code: "agent_sequence_gap", receipt_status: "rejected" as const, http_status: 200, observed_at_utc: "2026-10-22T08:00:00Z", resolved_at_utc: null };
const agent = { id: "fixture", delivery_diagnostics: { reported_at: now, items: [item] } } as AgentItem;
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("keeps absent diagnostics unknown and empty diagnostics distinct from success", () => {
  const { rerender } = render(<AgentDeliveryDiagnostics agent={{ id: "fixture" } as AgentItem}/>);
  expect(screen.queryByText(t("agents.delivery.title"))).toBeNull();
  rerender(<AgentDeliveryDiagnostics agent={{ ...agent, delivery_diagnostics: { reported_at: now, items: [] } }}/>);
  expect(screen.getByText(t("agents.delivery.empty"))).toBeTruthy();
});
it("does not mistake HTTP 200 or last_seen for successful delivery", () => {
  vi.spyOn(Date, "now").mockReturnValue(Date.parse(now));
  render(<AgentDeliveryDiagnostics agent={{ ...agent, last_seen: now }}/>);
  expect(screen.getByText(t("agents.delivery.reason.gap"))).toBeTruthy();
  expect(screen.getByText(/9007199254740993/)).toBeTruthy();
  expect(screen.queryByRole("status")).toBeNull();
  expect(screen.queryByRole("link")).toBeNull();
});
it("marks an old report stale despite a recent last_seen", () => {
  vi.spyOn(Date, "now").mockReturnValue(Date.parse(now) + 3600_000);
  render(<AgentDeliveryDiagnostics agent={{ ...agent, last_seen: "2026-10-23T09:00:00Z" }}/>);
  expect(screen.getByRole("status").textContent).toBe(t("agents.delivery.stale"));
});
it("renders unknown reasons safely without displaying arbitrary server text", () => {
  render(<AgentDeliveryDiagnostics agent={{ ...agent, delivery_diagnostics: { reported_at: now, items: [{ ...item, error_code: "private-token-text" }] } }}/>);
  expect(screen.getByText(t("agents.delivery.reason.unknown"))).toBeTruthy();
  expect(screen.queryByText(/private-token-text/)).toBeNull();
});
it("only offers the existing recovery anchor when explicitly composed and unresolved", () => {
  const { rerender } = render(<AgentDeliveryDiagnostics agent={agent} recoveryAvailable/>);
  expect(screen.getByRole("link").getAttribute("href")).toBe("#agent-sequence-recovery-fixture");
  rerender(<AgentDeliveryDiagnostics recoveryAvailable agent={{ ...agent, delivery_diagnostics: { reported_at: now, items: [{ ...item, resolved_at_utc: now }] } }}/>);
  expect(screen.queryByRole("link")).toBeNull();
  expect(screen.getByText(t("agents.delivery.resolvedAt", { date: formatDateTime(now, "UTC") }))).toBeTruthy();
});


it("does not label a malformed received report as an agent that never reported", () => {
  render(<AgentDeliveryDiagnostics agent={{ ...agent, delivery_diagnostics: {} as NonNullable<AgentItem["delivery_diagnostics"]> }}/>);
  expect(screen.getByText(t("agents.delivery.unknown"))).toBeTruthy();
  expect(screen.queryByText(/Поддержка диагностики этой версией неизвестна/)).toBeNull();
});
