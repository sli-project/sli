import type { PluginState } from "../../api/client";
import { t, type MessageKey } from "../../i18n";
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
export const fileServersUnassigned = (item: PluginState) => item.plugin_id === "sli.file-audit" && item.source_count === 0;

export function moduleStatusText(item: PluginState, timeZone: string) {
  if (fileServersUnassigned(item) || !item.enabled) return t("plugins.status.disabled");
  if (item.status?.state === "working") return t("plugins.status.active");
  if (item.status?.state === "error") {
    const time = item.status.error_at ? formatDateTime(item.status.error_at, timeZone) : null;
    return [t("plugins.status.failed"), item.status.error_object, time].filter(Boolean).join(" · ");
  }
  return pluginStatusText(item.status, moduleName(item), timeZone);
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

export function pluginStatusText(status: PluginState["status"], name: string, timeZone: string) {
  switch (status?.state) {
    case "disabled": return t("plugins.status.disabled");
    case "no_sources": return t("plugins.status.noSources");
    case "waiting": return t("plugins.status.waiting");
    case "working": return t("plugins.status.working", { time: formatDateTime(status.last_data_at, timeZone) });
    case "error": return t("plugins.status.error", { object: status.error_object || name, time: formatDateTime(status.error_at, timeZone) });
    default: return t("plugins.unavailable");
  }
}
