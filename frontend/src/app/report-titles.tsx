import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { reportTargetPath } from "./report-labels";
import { t } from "../i18n";
import { TechnicalKey } from "./technical-key";

/** Resolve the same v2 destination that the reports catalog uses. */
export function reportCatalogTitle(items: ReadonlyArray<{ key: string; title: string }>, key: string, fallback: string, targetPath = "") {
  if (key === "workstations.overview") return t("shell.section.workstations");
  if (key === "watch.registry") return t("watch.title");
  if (key === "decoys.registry") return t("decoys.title");
  const path = reportTargetPath({ report_key: key, target_path: targetPath });
  const match = /^\/report\/([^/?#]+)/.exec(path);
  const catalogKey = match ? decodeURIComponent(match[1]) : key;
  return items.find((item) => item.key === catalogKey)?.title ?? fallback;
}

export function useReportTitles() {
  const catalog = useQuery({ queryKey: ["report-v2", "catalog"], queryFn: api.reportsV2Catalog, staleTime: 60_000, retry: false });
  return (key: string, fallback = key, targetPath?: string) => reportCatalogTitle(catalog.data?.items ?? [], key, fallback, targetPath);
}

export function ReportTitle({ reportKey, name, targetPath }: { reportKey: string; name: string; targetPath?: string }) {
  const title = useReportTitles();
  const resolved = title(reportKey, name, targetPath);
  return <>{resolved === reportKey ? t("access.center.audit.report") : resolved} <TechnicalKey value={reportKey} label={t("access.audit.reportKey")}/></>;
}
