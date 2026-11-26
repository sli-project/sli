import type { PluginState } from "../../api/client";
import { t } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";

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
