// @vitest-environment jsdom
import { describe, expect, it, vi } from "vitest";
import type { PlatformReadiness } from "../../api/client";
import { operationsReadinessView } from "./readiness-view";
import { localeRuntime, setLocale } from "../../i18n";

describe("operationsReadinessView", () => {
  it.each([
    ["ru", "Архив событий", "Каталог архива не подходит для операционной системы сервера."],
    ["en", "Event archive", "The archive directory is incompatible with the server operating system."],
  ] as const)("shows an incompatible archive directory in %s as one neutral row", (locale, name, meaning) => {
    const reload = vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
    try {
      setLocale(locale);
      const data = { postgres: { available: true }, storage: {}, archive: { status: "invalid_root" } } as PlatformReadiness;
      expect(operationsReadinessView(data).filter((row) => row.key === "archive")).toEqual([
        expect.objectContaining({ name, meaning }),
      ]);
      expect(operationsReadinessView({ ...data, archive: { status: "ok" } }).some((row) => row.key === "archive")).toBe(false);
    } finally { setLocale("ru"); reload.mockRestore(); }
  });

  it("names the archive when its directory check fails", () => {
    const data = { postgres: { available: true }, storage: {}, archive: { status: "unavailable" } } as PlatformReadiness;
    expect(operationsReadinessView(data).find((row) => row.key === "archive")).toMatchObject({
      meaning: "Не удалось проверить каталог архива.",
    });
  });

  it("offers PostgreSQL diagnostics for a warning or an unavailable database", () => {
    const base = { postgres: { available: true }, storage: {} } as PlatformReadiness;
    expect(operationsReadinessView(base)).toEqual([]);
    expect(operationsReadinessView({ ...base, postgres: { available: true, warnings: ["synthetic"] } })).toEqual([
      expect.objectContaining({ key: "postgres", href: "/app/admin/status" }),
    ]);
    expect(operationsReadinessView({ ...base, postgres: { available: false } })).toEqual([
      expect.objectContaining({ key: "postgres", nextStep: "Проверьте службу PostgreSQL на сервере." }),
    ]);
  });
});
