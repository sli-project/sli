// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { localeRuntime, setLocale } from ".";
import { reportMetadataText } from "./report-metadata";
import { ru } from "./ru";
import { en } from "./en";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => {}); });
afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });

it("localizes workstation evidence detail and unavailable history in both languages", () => {
  for (const locale of ["ru", "en"] as const) {
    setLocale(locale);
    for (const family of ["processes", "usb"]) {
      const report = `workstations.${family}`;
      expect(reportMetadataText(report, "detail.title", "Исходное наблюдение"))
        .toBe(locale === "en" ? "Source observation" : "Исходное наблюдение");
      expect(reportMetadataText(report, "detail.columns.source_xml.label", "Исходный XML"))
        .toBe(locale === "en" ? "Source XML" : "Исходный XML");
      expect(reportMetadataText(report, "limitations.history_unavailable", "Постоянная история недоступна; показаны только доступные данные PostgreSQL."))
        .toContain(locale === "en" ? "Permanent history is unavailable" : "Постоянная история недоступна");
      expect(reportMetadataText(report, "limitations.coverage_unverified", "Покрытие сбора не подтверждено. USB-события не доказывают чтение или копирование файлов."))
        .not.toContain(locale === "en" ? "history is not loaded" : "история не загружена");
    }
  }
});

it("keeps workstation history keys identical and evidence hashes localized", () => {
  const keys = (messages: Record<string, string>) => Object.keys(messages).filter((key) =>
    /^reports\.v2\.workstations\.(processes|usb)\.(detail\.|limitations\.history_unavailable)/.test(key)).sort();
  expect(keys(en)).toEqual(keys(ru));
  for (const family of ["processes", "usb"]) {
    expect(en[`reports.v2.workstations.${family}.detail.columns.agent_key.label` as keyof typeof en]).toBe("Agent identifier");
    expect(ru[`reports.v2.workstations.${family}.detail.columns.agent_key.label` as keyof typeof ru]).toBe("Идентификатор агента");
    expect(en[`reports.v2.workstations.${family}.detail.columns.source_sha256.label` as keyof typeof en]).toBe("XML SHA-256");
    expect(ru[`reports.v2.workstations.${family}.detail.columns.observation_sha256.label` as keyof typeof ru]).toBe("SHA-256 наблюдения");
  }
});

it.each(["ru", "en"] as const)("limits the USB caveat to the USB report in %s", (locale) => {
  setLocale(locale);
  for (const family of ["logons", "processes", "protection"]) {
    expect(reportMetadataText(`workstations.${family}`, "limitations.coverage_unverified", "Покрытие сбора не подтверждено. USB-события не доказывают чтение или копирование файлов."))
      .toBe(locale === "ru" ? "Покрытие сбора не подтверждено." : "Collection coverage is not confirmed.");
  }
});
