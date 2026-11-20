import { ReportRenderer } from "../../app/report-v2/ReportRenderer";

export const AD_PLUGIN_ID = "sli.ad";

// Bundled, host-approved pages keep their existing report keys and URLs.
// No external plugin module is required; authorization stays in the renderer.
const pages = {
  "ad.infrastructure": () => <ReportRenderer reportKey="ad.infrastructure"/>,
  "ad.users.v2": () => <ReportRenderer reportKey="ad.users.v2"/>,
  "ad.computers.v6": () => <ReportRenderer reportKey="ad.computers.v6"/>,
  "ad.computer-logons": () => <ReportRenderer reportKey="ad.computer-logons"/>,
  "ad.new-logon-pairs": () => <ReportRenderer reportKey="ad.new-logon-pairs"/>,
  "ad.privileged": () => <ReportRenderer reportKey="ad.privileged"/>,
  "ad.users": () => <ReportRenderer reportKey="ad.users"/>,
  "ad.computers": () => <ReportRenderer reportKey="ad.computers"/>,
  "ad.computers.v2": () => <ReportRenderer reportKey="ad.computers.v2"/>,
  "ad.computers.v4": () => <ReportRenderer reportKey="ad.computers.v4"/>,
  "ad.computers.v5": () => <ReportRenderer reportKey="ad.computers.v5"/>,
} as const;

export function adReportPage(reportKey: string) {
  return Object.hasOwn(pages, reportKey) ? pages[reportKey as keyof typeof pages] : undefined;
}

export function adReportPageForRoute(route: string) {
  const prefix = "/report/";
  return route.startsWith(prefix) ? adReportPage(route.slice(prefix.length)) : undefined;
}
