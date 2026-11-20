import { describe, expect, it } from "vitest";
import { configDefaults } from "vitest/config";
import frontendConfig from "../vite.config";
import rootConfig from "../../vitest.config";

it("excludes Playwright geometry specs and retains the default exclusions", () => {
  expect(frontendConfig.test?.exclude).toEqual([...configDefaults.exclude, "tests/geometry/**"]);
});

describe.each([
  ["frontend", frontendConfig],
  ["repository root", rootConfig],
] as const)("%s Vitest configuration", (_name, config) => {
  it("preserves raw CSS contracts without applying responsive CSS in jsdom", () => {
    const css = config.test?.css;
    if (!css || typeof css === "boolean") throw new Error("Expected a CSS include configuration");
    const included = (path: string) => css.include?.some((pattern) => pattern.test(path));
    expect(included("/src/design-system/ds.css?raw")).toBe(true);
    expect(included("/src/design-system/ds.css?raw&v=1")).toBe(true);
    expect(included("/src/design-system/ds.css")).toBe(false);
    expect(included("/src/design-system/ds.css?v=1")).toBe(false);
  });
});
