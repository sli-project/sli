// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { en } from "./en";
import { ru } from "./ru";
import { localeRuntime, setLocale } from "./index";
import { localizeReportView, reportMetadataText } from "./report-metadata";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });

describe("plugin snapshot analytics metadata", () => {
  it("keeps identical translation keys for both plugin tabs", () => {
    const prefixes = ["reports.v2.ad.infrastructure.views.spn_collisions.", "reports.v2.vpn.connections.views.session_overlap."];
    for (const prefix of prefixes) {
      const keys = Object.keys(ru).filter((key) => key.startsWith(prefix));
      expect(keys.length).toBeGreaterThan(10);
      expect(Object.keys(en).filter((key) => key.startsWith(prefix)).sort()).toEqual(keys.sort());
    }
  });

  it("localizes SPN owner quality and freshness without rewriting SPNs", () => {
    setLocale("en");
    const view = localizeReportView({ kind: "table", key: "spn_collisions", source: "spn_collisions", title: "Коллизии SPN", columns: [
      { key: "spn", label: "SPN", kind: "code", path: "spn" },
      { key: "owner_quality", label: "Параметры владельца", kind: "state", path: "owner_quality", labels: { unknown: "Часть неизвестна" } },
      { key: "source_freshness", label: "Свежесть источника", kind: "state", path: "source_freshness", labels: { stale: "Устаревший" } },
    ] }, "ad.infrastructure");
    expect(view.title).toBe("SPN collisions");
    expect(view.columns?.[0].path).toBe("spn");
    expect(view.columns?.[1].labels?.unknown).toBe("Partly unknown");
    expect(view.columns?.[2].labels?.stale).toBe("Stale");
  });

  it("explains an empty Accounting projection explicitly in English", () => {
    setLocale("en");
    expect(reportMetadataText("vpn.connections", "limitations.overlap_no_accounting", "fallback"))
      .toBe("No Accounting data: the session projection is empty or unavailable. NPS decisions do not replace VPN sessions.");
    expect(reportMetadataText("vpn.connections", "views.session_overlap.columns.interval_quality.labels.observed", "fallback"))
      .toBe("Incomplete, observed");
  });
});
