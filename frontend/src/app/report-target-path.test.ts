import { describe, expect, it } from "vitest";
import { AD_STATE_LEGACY_ROUTE, reportSupportsPreference, reportTargetPath } from "./report-labels";

describe("reportTargetPath", () => {
  it.each([
    ["security.queue", "/report/security.problems"],
    ["ad.state", "/report/ad.infrastructure"],
    ["ad.users", "/report/ad.users.v2"],
    ["ad.computers", "/report/ad.computers.v6"],
    ["ad.computers.v5", "/report/ad.computers.v6"],
    ["ad.computers.v6", "/report/ad.computers.v6"],
    ["ad.computer-logons", "/report/ad.computer-logons"],
    ["ad.privileged", "/reports"],
    ["ad.gpo.review", "/report/ad.gpo.v2"],
    ["vpn.audit", "/report/vpn.accounts"],
    ["vpn.connections", "/report/vpn.connections"],
    ["security.events.chains", "/report/security.events.chains"],
  ])("opens %s in its specialized workspace", (reportKey, expected) => {
    expect(reportTargetPath({ report_key: reportKey, target_path: `/reports/${reportKey}` })).toBe(expected);
  });

  it("keeps the registered path for ordinary reports", () => {
    expect(reportTargetPath({ report_key: "operations.runtime", target_path: "/project-readiness" })).toBe("/project-readiness");
  });

  it("routes the legacy ad.state URL to the dedicated Active Directory workspace", () => {
    expect(AD_STATE_LEGACY_ROUTE).toBe("/reports/ad.state");
  });

  it("does not offer registry preferences for a derived catalog surface", () => {
    expect(reportSupportsPreference({ preference_supported: false })).toBe(false);
    expect(reportSupportsPreference({})).toBe(true);
  });
});
