import { expect, it } from "vitest";
import { aclDifferences, filterAces, type FileAuditAce, type FileAuditAcl } from "./acl";

const ace = (ordinal: number, overrides: Partial<FileAuditAce> = {}): FileAuditAce => ({
  ordinal, type: "allow", ace_type: "A", sid: `S-1-5-21-1-${ordinal}`, mask: 0x120089,
  mask_raw: "0x120089", flags: [], flags_raw: "", inherited: false, inherit_only: false,
  raw: `(A;;0x120089;;;S-1-5-21-1-${ordinal})`, ...overrides,
});
const acl = (aces: FileAuditAce[], state: FileAuditAcl["state"] = "complete"): FileAuditAcl => ({ state, aces, raw: "retained descriptor" });

it("filters the complete ACL beyond the first page while preserving original positions", () => {
  const entries = Array.from({ length: 135 }, (_, index) => ace(index, { inherited: index >= 100 }));
  const matches = filterAces(entries, "S-1-5-21-1-12", "inherited");
  expect(matches.map(item => item.ordinal)).toEqual([120, 121, 122, 123, 124, 125, 126, 127, 128, 129]);
  expect(entries[120].ordinal).toBe(120);
});

it("does not interpret a missing descriptor as removal of all entries", () => {
  expect(aclDifferences(acl([ace(0)]), acl([], "missing"))).toBeNull();
  expect(aclDifferences(acl([], "unsupported"), acl([ace(0)]))).toBeNull();
});

it("retains duplicate ACEs, changed masks and changed order in snapshot comparison", () => {
  const first = ace(0, { sid: "S-1-1-0", raw: "(A;;FR;;;WD)" });
  const second = ace(1, { sid: "S-1-1-0", raw: "(A;CI;FR;;;WD)", flags: ["CI"], flags_raw: "CI" });
  const before = acl([first, second, ace(2)]);
  const after = acl([{ ...second, ordinal: 0 }, { ...first, ordinal: 1, mask: 0x1301bf, mask_raw: "0x1301bf", raw: "(A;;0x1301bf;;;WD)" }]);
  const changes = aclDifferences(before, after)!;
  expect(changes.map(row => row.change)).toEqual(["changed", "changed", "removed"]);
  expect(changes[0]).toMatchObject({ before: { ordinal: 1 }, after: { ordinal: 0 } });
  expect(changes[1]).toMatchObject({ before: { mask: 0x120089 }, after: { mask: 0x1301bf } });
  expect(changes[2].before?.sid).toBe("S-1-5-21-1-2");
});
