export type FileMaskLabels = Record<"none" | "read" | "write" | "readWrite" | "readExecute" | "modify" | "full" | "custom", string>;

// Names of exact file-object bit sets, not an effective-access decision.
// https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights
// Unknown bits/generic flags must not be rounded up to a familiar permission.
export function fileMaskLabel(value: unknown, labels: FileMaskLabels): string | null {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 0xffffffff) return null;
  const known: Record<number, keyof FileMaskLabels> = {
    0: "none", 0x120089: "read", 0x120116: "write", 0x12019f: "readWrite",
    0x1200a9: "readExecute", 0x1301bf: "modify", 0x1f01ff: "full",
  };
  return known[value] ? labels[known[value]] : `${labels.custom} (${value})`;
}
