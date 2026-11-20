import { describe, expect, it } from "vitest";
import { deliveryView, deliveryReason } from "./agent-delivery-diagnostics-model";
const now = Date.parse("2026-10-23T08:00:00Z");
const item = { module_id: "sli.windows.ad-dc", packet_id: "00000000-0000-4000-8000-000000000001", sequence: "9223372036854775807", error_code: "agent_sequence_gap", receipt_status: "retry_later", http_status: 200, observed_at_utc: "2026-10-22T08:00:00Z", resolved_at_utc: null };
describe("delivery diagnostics", () => {
  it("does not call missing/empty observations successful", () => {
    expect(deliveryView(undefined, 60, now).state).toBe("unknown");
    expect(deliveryView({ reported_at: new Date(now).toISOString(), items: [] }, 60, now).state).toBe("empty");
  });
  it("uses report freshness, preserving exact bigint sequence and old error time", () => {
    const result = deliveryView({ reported_at: new Date(now).toISOString(), items: [item] }, 60, now);
    expect(result.stale).toBe(false); expect(result.items[0].sequence).toBe(item.sequence);
    expect(result.items[0].observed_at_utc).toBe(item.observed_at_utc);
  });
  it("flags old, missing and future server report timestamps", () => {
    for (const reported_at of ["invalid", new Date(now - 3600000).toISOString(), new Date(now + 3600000).toISOString()]) {
      expect(deliveryView({ reported_at, items: [item] }, 60, now).stale).toBe(true);
    }
  });
  it("does not expose unknown code text or treat it as recovery authorization", () => {
    expect(deliveryReason("secret=private")).toBe("agents.delivery.reason.unknown");
    expect(deliveryReason("agent_sequence_gap")).toBe("agents.delivery.reason.gap");
    expect(deliveryReason("agent_sequence_replayed")).toBe("agents.delivery.reason.replay");
    expect(deliveryReason("agent_sequence_replayed")).not.toBe(deliveryReason("agent_sequence_gap"));
  });
  it("bounds items and retains a malformed/truncated warning", () => {
    const result = deliveryView({ reported_at: new Date(now).toISOString(), items: Array.from({ length: 17 }, (_, i) => ({ ...item, module_id: `sli.module${i}` })) }, 60, now);
    expect(result.items).toHaveLength(16); expect(result.partial).toBe(true);
    expect(deliveryView({ reported_at: new Date(now).toISOString(), items: [{ ...item, sequence: 9223372036854775807 }] }, 60, now).partial).toBe(true);
  });
  it("keeps resolution separate from current delivery and rejects impossible resolution time", () => {
    expect(deliveryView({ reported_at: new Date(now).toISOString(), items: [{ ...item, resolved_at_utc: new Date(now).toISOString() }] }, 60, now).items[0].resolved_at_utc).toBe(new Date(now).toISOString());
    expect(deliveryView({ reported_at: new Date(now).toISOString(), items: [{ ...item, resolved_at_utc: "invalid" }] }, 60, now).partial).toBe(true);
  });
});
