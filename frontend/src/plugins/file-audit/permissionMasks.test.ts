import { expect, it } from "vitest";
import { fileMaskLabel } from "./permissionMasks";

const labels = { none: "none", read: "read", write: "write", readWrite: "read/write",
  readExecute: "read/execute", modify: "modify", full: "full", custom: "custom" };

it.each([
  [0, "none"], [0x120089, "read"], [0x120116, "write"],
  [0x12019f, "read/write"], [0x1200a9, "read/execute"],
  [0x1301bf, "modify"], [0x1f01ff, "full"],
])("names only the exact file rights set %s", (mask, expected) => {
  expect(fileMaskLabel(mask, labels)).toBe(expected);
});

it.each([1, 0x10000000, 0x80000000, 0x21f01ff, 0xffffffff])("does not upgrade custom or unsupported bits %s", (mask) => {
  expect(fileMaskLabel(mask, labels)).toBe(`custom (${mask})`);
});

it.each([null, undefined, -1, 0x100000000, 1.5, true, "2032127", {}, []])("preserves unknown/non-numeric input %s", (mask) => {
  expect(fileMaskLabel(mask, labels)).toBeNull();
});

it("uses supplied localized labels without changing the source number", () => {
  const source = { mask: 0x1f01ff };
  expect(fileMaskLabel(source.mask, { ...labels, full: "Полный набор прав" })).toBe("Полный набор прав");
  expect(fileMaskLabel(source.mask, { ...labels, full: "Full rights set" })).toBe("Full rights set");
  expect(source.mask).toBe(2032127);
});
