import { dirname, join, resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { testPython } from "./python";

const root = resolve("checkout", "frontend");

describe("test Python selection", () => {
  it("honors an explicit interpreter before any environment discovery", () => {
    const exists = vi.fn(() => true);
    expect(testPython(root, { SLI_TEST_PYTHON: "custom-python", VIRTUAL_ENV: "/opt/venv" }, "linux", exists))
      .toBe("custom-python");
    expect(exists).not.toHaveBeenCalled();
  });

  it("uses the active dev container environment before a checkout-local one", () => {
    const exists = vi.fn(() => true);
    expect(testPython(root, { VIRTUAL_ENV: "/opt/venv" }, "linux", exists))
      .toBe(join("/opt/venv", "bin/python"));
    expect(exists).toHaveBeenCalledTimes(1);
  });

  it("uses the Windows executable layout for an active environment", () => {
    const venv = resolve("active-venv");
    expect(testPython(root, { VIRTUAL_ENV: venv }, "win32", () => true))
      .toBe(join(venv, "Scripts/python.exe"));
  });

  it("falls back from a missing active interpreter to an ancestor's local environment", () => {
    const candidate = join(dirname(root), ".venv", "bin/python");
    expect(testPython(root, { VIRTUAL_ENV: "/missing-venv" }, "linux", (path) => path === candidate))
      .toBe(candidate);
  });

  it("prefers the nearest checkout environment when no environment is active", () => {
    expect(testPython(root, {}, "linux", () => true)).toBe(join(root, ".venv", "bin/python"));
  });

  it("uses the system fallback only when no environment interpreter exists", () => {
    expect(testPython(root, {}, "linux", () => false)).toBe("python3");
  });
});
