// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { en } from "./en";
import { ru } from "./ru";
import { localeRuntime, setLocale } from "./index";
import { localizeReportView, reportMetadataText } from "./report-metadata";
import adDefinitions from "../../../server-dotnet/src/Sli.Server/Ad/report-definitions.json";
import type { ReportViewDto } from "../api/report-v2-types";

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

  it("shows the SPN and observation time without source commentary or run IDs", () => {
    setLocale("en");
    const declaration = adDefinitions["ad.infrastructure"].declaration.views.find((view) => view.key === "spn_collisions") as ReportViewDto;
    const view = localizeReportView(declaration, "ad.infrastructure");
    expect(view.title).toBe("SPN collisions");
    const columns = view.columns?.map((column) => column.path);
    expect(columns).toContain("spn");
    expect(columns).toContain("observed_at_utc");
    for (const path of ["owner_quality", "source_freshness", "run_id"]) expect(columns).not.toContain(path);
    expect(view.note).toBeUndefined();
  });

  it("explains an empty Accounting projection explicitly in English", () => {
    setLocale("en");
    expect(reportMetadataText("vpn.connections", "limitations.overlap_no_accounting", "fallback"))
      .toBe("No Accounting data: the session projection is empty or unavailable. NPS decisions do not replace VPN sessions.");
    expect(reportMetadataText("vpn.connections", "views.session_overlap.columns.interval_quality.labels.observed", "fallback"))
      .toBe("Incomplete, observed");
  });
});
