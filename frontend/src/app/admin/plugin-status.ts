import type { PluginState } from "../../api/client";
import { plural, t, type MessageKey } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
import { EMPTY_VALUE, formatNumber } from "../../shared/format";

const moduleNames = {
  "sli.ad": "plugins.ad",
  "sli.gpo": "plugins.gpo",
  "sli.file-audit": "plugins.fileAudit",
  "sli.remote-access": "plugins.remoteAccess",
  "sli.workstations": "plugins.workstations",
  "sli.sigma": "plugins.sigma",
} satisfies Record<string, MessageKey>;

export const moduleRows = (items: PluginState[]) => Object.keys(moduleNames)
  .flatMap((id) => items.filter((item) => item.plugin_id === id));
export const moduleName = (item: PluginState) => t(moduleNames[item.plugin_id as keyof typeof moduleNames]);
export const moduleStatusId = (item: PluginState) => `module-${item.plugin_id}`;
export function pluginNextAction(status: PluginState["status"]) {
  return status?.next_action ? t(`plugins.next.${status.next_action}`) : undefined;
}
export function moduleStatusText(item: PluginState, timeZone: string) {
  const status = item.status;
  if (!status) return t("plugins.unavailable");
  if (status.state === "disabled") return t("plugins.status.disabled");
  const count = item.source_count;
  const noun = item.plugin_id === "sli.file-audit" ? "servers"
    : item.plugin_id === "sli.workstations" ? "computers" : "sources";
  const form = plural(count ?? 0, { one: "one", few: "few", many: "many", other: "many" }) as "one" | "few" | "many";
  const connected = count && count > 0 ? t(`plugins.connected.${noun}.${form}`, { count: formatNumber(count) }) : null;
  let detail: string;
  switch (status.state) {
    case "no_sources": detail = status.reason === "no_folders"
      ? [connected, t("plugins.status.noFolders")].filter(Boolean).join(" · ")
      : t("plugins.status.noSources");
      break;
    case "waiting": detail = [connected, t("plugins.status.waiting")].filter(Boolean).join(" · "); break;
    case "working": detail = connected ?? t("plugins.status.working", { time: formatDateTime(status.last_data_at, timeZone) }); break;
    case "error": detail = status.reason === "status_unavailable" ? t("plugins.unavailable")
      : [t(status.reason === "collection_delayed" ? "plugins.status.delayed" : "plugins.status.failed"),
        status.error_object, status.error_at && formatDateTime(status.error_at, timeZone)].filter(Boolean).join(" · ");
      break;
  }
  return [t("plugins.enabled"), detail, pluginNextAction(status)].filter(Boolean).join(" · ");
}

export function moduleSources(item: PluginState) {
  const names = item.source_names ?? [];
  if (!names.length) {
    return item.source_count || (item.source_count === undefined && !["sli.remote-access", "sli.sigma"].includes(item.plugin_id))
      ? t("plugins.sourcesUnavailable") : EMPTY_VALUE;
  }
  const count = item.source_count ?? names.length;
  const shown = names.slice(0, 2);
  return count > 3
    ? t("plugins.moreSources", { names: shown.join(", "), count: formatNumber(count - shown.length) })
    : names.join(", ");
}

export function moduleLastData(item: PluginState) {
  const receipts = item.data_receipts;
  return [item.status?.last_data_at, receipts?.last_received_at, receipts?.last_imported_at,
    receipts?.last_snapshot_completed_at, item.last_data_at_utc]
    .filter((time): time is string => Boolean(time) && Number.isFinite(Date.parse(time!)))
    .sort((left, right) => Date.parse(right) - Date.parse(left))[0];
}
