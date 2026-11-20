import { expect, it } from "vitest";
import { reportCatalogTitle } from "./report-titles";
import { t } from "../i18n";

it("resolves the decoy registry title without a report result endpoint", () => {
  expect(reportCatalogTitle([], "decoys.registry", "Decoy registry")).toBe(t("decoys.title"));
});

it("resolves the account watch registry title without a report result endpoint", () => {
  expect(reportCatalogTitle([], "watch.registry", "Account watch")).toBe(t("watch.title"));
});

it("resolves the workstation workspace title before its result endpoint is installed", () => {
  expect(reportCatalogTitle([], "workstations.overview", "Workstations")).toBe(t("shell.section.workstations"));
});

it("uses v2 titles for built-in report aliases and keeps custom names", () => {
  const items = [{ key: "ad.computer-logons", title: "Logon catalog title" }, { key: "ad.infrastructure", title: "AD catalog title" }, { key: "vpn.accounts", title: "VPN catalog title" }];
  expect(reportCatalogTitle(items, "ad.computer-logons", "Legacy logons")).toBe("Logon catalog title");
  expect(reportCatalogTitle(items, "ad.state", "example.invalid")).toBe("AD catalog title");
  expect(reportCatalogTitle(items, "vpn.audit", "Legacy VPN")).toBe("VPN catalog title");
  expect(reportCatalogTitle(items, "custom.report", "Custom title")).toBe("Custom title");
  expect(reportCatalogTitle(items, "custom.alias", "Fallback", "/report/vpn.accounts")).toBe("VPN catalog title");
  expect(reportCatalogTitle([], "vpn.audit", "Fallback")).toBe("Fallback");
});
