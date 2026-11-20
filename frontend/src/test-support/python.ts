import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import process from "node:process";

// Use the active environment, including the dev container's /opt/venv,
// before looking for a checkout-local environment or a system interpreter.
export function testPython(
  root: string,
  env: Record<string, string | undefined> = process.env,
  platform: string = process.platform,
  exists: (path: string) => boolean = existsSync,
): string {
  if (env.SLI_TEST_PYTHON) return env.SLI_TEST_PYTHON;
  const executable = platform === "win32" ? "Scripts/python.exe" : "bin/python";
  if (env.VIRTUAL_ENV) {
    const candidate = join(env.VIRTUAL_ENV, executable);
    if (exists(candidate)) return candidate;
  }
  let directory = root;
  while (true) {
    const candidate = join(directory, ".venv", executable);
    if (exists(candidate)) return candidate;
    const parent = dirname(directory);
    if (parent === directory) return "python3";
    directory = parent;
  }
}
