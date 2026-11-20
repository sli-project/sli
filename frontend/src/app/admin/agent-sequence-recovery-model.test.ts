import { expect, it } from "vitest";
import { recoveryRange, validRecoveryPreview } from "./agent-sequence-recovery-model";

it("keeps sequence values exact beyond JavaScript safe integers", () => {
  expect(recoveryRange({ expected_sequence: "9007199254740993", received_sequence: "9007199254741000", missing_packets: "7" }))
    .toEqual({ first: "9007199254740993", last: "9007199254740999", count: "7" });
});
it.each([
  { expected_sequence: "8", received_sequence: "8", missing_packets: "0" },
  { expected_sequence: "9", received_sequence: "8", missing_packets: "1" },
  { expected_sequence: "1", received_sequence: "8", missing_packets: "6" },
  { expected_sequence: "01", received_sequence: "8", missing_packets: "7" },
  { expected_sequence: "1", received_sequence: "9223372036854775808", missing_packets: "9223372036854775807" },
])("does not offer a misleading range for invalid server values %#", (value) => {
  expect(recoveryRange(value)).toBeNull();
});

it("validates one exact bounded preview, rejecting duplicated streams or cross-agent records", () => {
  const stream = { id: "42", agent_id: "agent", module_id: "sli.workstations", status: "pending", expected_sequence: "1", received_sequence: "3", missing_packets: "2" };
  const preview = { preview_token: "a".repeat(64), agent_id: "agent", observation_ids: ["42"], streams: [stream] };
  expect(validRecoveryPreview(preview, "agent")).toBe(true);
  expect(validRecoveryPreview({ ...preview, preview_token: "invalid" }, "agent")).toBe(false);
  expect(validRecoveryPreview({ ...preview, observation_ids: ["43"] }, "agent")).toBe(false);
  expect(validRecoveryPreview({ ...preview, streams: [{ ...stream, agent_id: "other" }] }, "agent")).toBe(false);
  expect(validRecoveryPreview({ ...preview, observation_ids: ["42", "43"], streams: [stream, { ...stream, id: "43" }] }, "agent")).toBe(false);
  expect(validRecoveryPreview({ ...preview, streams: [{ ...stream, status: "accepted" }] }, "agent")).toBe(false);
});
