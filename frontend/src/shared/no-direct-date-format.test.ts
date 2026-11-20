import { describe, expect, it } from "vitest";

// Vite loads source text without executing components or requiring Node shims.
const sources = import.meta.glob<string>("../**/*.{ts,tsx}", { eager: true, query: "?raw", import: "default" });
const ALLOWED = new Set(["./date-time.ts", "./format.ts"]);
const FORBIDDEN = /\.\s*toLocale(?:Date|Time)?String\s*\(|Intl\s*\.\s*(?:DateTimeFormat|RelativeTimeFormat|NumberFormat)\b|\$\{[^}]+\.slice\(8,\s*10\)\}\.\$\{[^}]+\.slice\(5,\s*7\)\}/;

describe("date and number formatting", () => {
  it("goes through the shared formatters, not component-local locale or dd.mm templates", () => {
    expect(Object.keys(sources).length).toBeGreaterThan(100);
    expect(sources["./date-time.ts"]).toContain("function formatDateTime");
    const offenders = Object.entries(sources).filter(([path, source]) =>
      !ALLOWED.has(path) && !/\.test\.(ts|tsx)$/.test(path) && FORBIDDEN.test(source)).map(([path]) => path);
    expect(offenders).toEqual([]);
  });

  it.each(["new Intl.DateTimeFormat('ru-RU')", "date.toLocaleDateString ()", "date.toLocaleString()",
    "`${date.slice(8, 10)}.${date.slice(5, 7)}`"])("rejects manual formatting: %s", (source) => {
    expect(FORBIDDEN.test(source)).toBe(true);
  });

  it("does not forbid machine-readable filter and grouping keys", () => {
    expect(FORBIDDEN.test("date.toISOString().slice(0, 10)")).toBe(false);
  });
});
