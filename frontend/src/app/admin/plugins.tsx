import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiResponseError, type PluginState } from "../../api/client";
import { Button, FactList, PageHeader, Panel, StateView } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { FieldError } from "./gate";
import { formatDateTime } from "../../shared/date-time";
import { useEffectiveAccess, useTimeZone } from "../App";
import { AccessRequestStateView, useAccessRequest } from "../access-request-state";
import { pluginStatusText } from "./plugin-status";

const pluginLabels: Record<string, { name: MessageKey; description: MessageKey }> = {
  "sli.ad": { name: "plugins.ad", description: "plugins.description.ad" },
  "sli.gpo": { name: "plugins.gpo", description: "plugins.description.gpo" },
  "sli.file-audit": { name: "plugins.fileAudit", description: "plugins.description.fileAudit" },
  "sli.workstations": { name: "plugins.workstations", description: "plugins.description.workstations" },
  "sli.remote-access": { name: "plugins.remoteAccess", description: "plugins.description.remoteAccess" },
  "sli.sigma": { name: "plugins.sigma", description: "plugins.description.sigma" },
};

const pluginDetails: Record<string, string | undefined> = {
  "sli.ad": "/app/admin/plugins/sli.ad",
  "sli.gpo": "/app/admin/plugins/sli.gpo",
  "sli.file-audit": "/app/admin/plugins/sli.file-audit",
  "sli.remote-access": "/app/admin/plugins/sli.remote-access",
  "sli.workstations": "/app/admin/plugins/sli.workstations",
  "sli.sigma": "/app/admin/plugins/sli.sigma",
};

export function PluginsRoute() {
  const access = useEffectiveAccess();
  const request = useAccessRequest();
  if (access?.capabilities.includes("operations.view") && !request?.error) return <PluginsPage/>;
  return <section className="sli-ds-report">
    <PageHeader title={t("plugins.title")}/>
    {!access || request?.error ? <AccessRequestStateView/> : <StateView state="denied"/>}
  </section>;
}

export function PluginsPage() {
  const plugins = useQuery({ queryKey: ["plugins"], queryFn: api.plugins, refetchInterval: 5_000 });
  return <section className="sli-ds-report">
    <PageHeader title={t("plugins.title")}/>
    {plugins.isLoading ? <StateView state="loading"/> : plugins.error ? <StateView state="unavailable" detail={t("plugins.unavailable")} onRetry={() => void plugins.refetch()}/> : null}
    {!plugins.isError && plugins.data ? <>
      {!plugins.data.can_manage ? <p role="note">{t("plugins.readOnly")}</p> : null}
      {plugins.data.items.map((item) => <PluginCard key={item.plugin_id} item={item} canManage={plugins.data.can_manage}/>)}
    </> : null}
  </section>;
}

function PluginCard({ item, canManage }: { item: PluginState; canManage: boolean }) {
  const { timeZone } = useTimeZone();
  const client = useQueryClient();
  const change = useMutation({
    mutationFn: (enabled: boolean) => api.setPluginEnabled(item, enabled),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["report-v2"] });
      return client.invalidateQueries({ queryKey: ["plugins"] });
    },
    onError: () => void client.invalidateQueries({ queryKey: ["plugins"] }),
  });
  const labels = Object.prototype.hasOwnProperty.call(pluginLabels, item.plugin_id) ? pluginLabels[item.plugin_id] : undefined;
  const name = labels ? t(labels.name) : item.plugin_id;
  const details = pluginDetails[item.plugin_id];
  const facts = item.data_receipts;
  const formatFact = (value: string | null | undefined) => formatDateTime(value, timeZone);
  const errorCode = change.error instanceof ApiResponseError ? change.error.code : undefined;
  const errorMessage = (() => {
    switch (errorCode) {
      case "plugin_management_owner_or_admin_required": return t("plugins.readOnly");
      case "plugin_not_found": return t("plugins.error.notFound");
      case "plugin_state_request_invalid": return t("plugins.error.invalidRequest");
      case "plugin_revision_conflict": return t("plugins.error.revisionConflict");
      case "plugin_not_installed": return t("plugins.error.notInstalled");
      case "plugin_not_configured": return t("plugins.error.notConfigured");
      case "plugin_runtime_not_stopped": return t("plugins.error.notStopped");
      case "plugin_runtime_not_running": return t("plugins.error.notRunning");
      case "plugin_queue_not_drained": return t("plugins.error.queueNotDrained");
      case "plugin_active_leases": return t("plugins.error.activeLeases");
      case "plugin_runtime_transition_unsupported": return t("plugins.error.unsupported");
      case "plugin_runtime_precondition_failed": return t("plugins.error.preconditionFailed");
      case "plugin_state_unavailable": return t("plugins.unavailable");
      default: return t("plugins.changeFailed");
    }
  })();
  return <Panel title={name} subtitle={pluginStatusText(item.status, name, timeZone)}>
    <p>{t(labels?.description ?? "plugins.description.unknown")}</p>
    <FactList facts={[
      { label: t("plugins.version"), value: item.package_version },
      ...(facts?.last_received_at ? [{ label: t("plugins.lastReceipt"), value: formatFact(facts.last_received_at) }] : []),
      ...(facts?.last_imported_at ? [{ label: t("plugins.lastImport"), value: formatFact(facts.last_imported_at) }] : []),
      ...(facts?.last_snapshot_completed_at ? [{ label: t("plugins.lastSnapshotCompleted"), value: formatFact(facts.last_snapshot_completed_at) }] : []),
    ]}/>
    {change.error ? <FieldError error={new Error(errorMessage)}/> : null}
    <div className="sli-ds-filters__fields">
      {details ? <a href={details}>{t("plugins.open", { name })}</a> : null}
      <a href="/app/operations#runtime-workers">{t("plugins.diagnostics")}</a>
      {canManage ? <Button
      disabled={change.isPending || !item.installed || (!item.enabled && (!item.configured || item.component_runtime !== "stopped"))}
      onClick={() => change.mutate(!item.enabled)}>{t(item.enabled ? "plugins.disable" : "plugins.enable")}</Button> : null}
    </div>
  </Panel>;
}
