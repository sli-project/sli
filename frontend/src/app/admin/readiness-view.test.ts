// @vitest-environment jsdom
import { describe, expect, it, vi } from "vitest";
import type { OperationsOverview, PlatformReadiness } from "../../api/client";
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
      const data = { postgres: {}, storage: {}, archive: { status: "invalid_root" } } as PlatformReadiness;
      expect(operationsReadinessView(data).checks.filter((row) => row.key === "archive")).toEqual([
        expect.objectContaining({ name, meaning, tone: "neutral" }),
      ]);
      expect(operationsReadinessView({ ...data, archive: { status: "ok" } }).checks.some((row) => row.key === "archive")).toBe(false);
    } finally { setLocale("ru"); reload.mockRestore(); }
  });

  it("names the archive when its directory check fails", () => {
    const data = { postgres: {}, storage: {}, archive: { status: "unavailable" } } as PlatformReadiness;
    expect(operationsReadinessView(data).checks.find((row) => row.key === "archive")).toMatchObject({
      meaning: "Не удалось проверить каталог архива.", tone: "neutral",
    });
  });

  it.each([
    ["critical", "bad"], ["high", "bad"], ["unknown", "neutral"],
    ["not_failed", "neutral"], ["future_warning", "neutral"], ["ok", "good"],
  ])("uses an exact state for readiness colour (%s)", (status, tone) => {
    const view = operationsReadinessView({ postgres: {}, storage: { status } } as PlatformReadiness);
    expect(view.metrics.find((metric) => metric.icon === "layers")?.tone).toBe(tone);
  });

  it("keeps PostgreSQL, storage and worker summary checks", () => {
    const data = {
      generated_at_utc: "2026-10-10T12:00:00Z",
      postgres: { status: "warn", database: { database_human: "30.2 GB" }, warnings: ["dead tuples"] },
      storage: { status: "ok", project_overview: { total_human: "32.5 GB" } },
      workers: { items: [
        { worker_name: "disabled-worker", state: "active", feature_enabled: false },
        { worker_name: "error-worker", state: "active", status: "error" },
        { worker_name: "stale-worker", state: "stale" },
        { worker_name: "unknown-worker", state: "not_registered" },
      ] },
    } as PlatformReadiness;
    const view = operationsReadinessView(data);
    expect(view.metrics[0]).toMatchObject({ label: "PostgreSQL", value: "Требует внимания", caption: "30.2 GB · 1 предупреждение" });
    expect(view.checks.find((check) => check.name === "Рабочие процессы")).toMatchObject({ state: "Требует внимания", meaning: "0 из 4 зарегистрированных процессов передают актуальный сигнал состояния." });
  });

  it("does not use retired collection failures or undated summaries", () => {
    const view = operationsReadinessView({
      collection: { collection_enabled: false, collection_block_reason: "windows_event_log_access_denied" },
      collector_health: { items: [{ server: "fixture-retired", channel: "Security", collection_state: "error" }] },
      postgres: {}, storage: {},
    } as OperationsOverview);
    expect(view.metrics[1].tone).toBe("neutral");
    expect(view.checks.find((check) => check.name === "Сбор событий")?.href).toBe("/app/agents");
    expect(JSON.stringify(view)).not.toContain("fixture-retired");
    expect(JSON.stringify(view)).not.toContain("Нет доступа к журналу событий");
  });

  it("uses storage snapshot staleness", () => {
    const view = operationsReadinessView({ postgres: {}, storage: { footprint: { status: "ok", snapshot: { stale: true } } } } as PlatformReadiness);
    expect(view.metrics.find((metric) => metric.icon === "layers")?.value).toBe("Устарело");
  });

});

