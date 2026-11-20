import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiResponseError, type PluginState } from "../../api/client";
import { Badge, FactList, PageHeader, StateView } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { FieldError } from "./gate";
import { formatDateTime } from "../../shared/date-time";
import { useTimeZone } from "../App";

const pluginLabels: Record<string, { name: MessageKey; description: MessageKey }> = {
  "sli.ad": { name: "plugins.ad", description: "plugins.description.ad" },
  "sli.gpo": { name: "plugins.gpo", description: "plugins.description.gpo" },
  "sli.file-audit": { name: "plugins.fileAudit", description: "plugins.description.fileAudit" },
  "sli.workstations": { name: "plugins.workstations", description: "plugins.description.workstations" },
  "sli.remote-access": { name: "plugins.remoteAccess", description: "plugins.description.remoteAccess" },
  "sli.sigma": { name: "plugins.sigma", description: "plugins.description.sigma" },
};

export function PluginsPage() {
  const plugins = useQuery({ queryKey: ["plugins"], queryFn: api.plugins, refetchInterval: 5_000 });
  return <section className="sli-ds-report">
    <PageHeader title={t("plugins.title")} subtitle={t("plugins.subtitle")}/>
    <p>{t("plugins.updateWithSli")}</p>
    <p>{t("plugins.receiptNote")}</p>
    {plugins.isLoading ? <StateView state="loading"/> : plugins.error ? <StateView state="unavailable" detail={t("plugins.unavailable")} onRetry={() => void plugins.refetch()}/> : null}
    {plugins.data && !plugins.data.can_manage ? <p role="note">{t("plugins.readOnly")}</p> : null}
    {plugins.data?.items.map((item) => <PluginCard key={item.plugin_id} item={item} canManage={plugins.data.can_manage}/>)}
  </section>;
}

function PluginCard({ item, canManage }: { item: PluginState; canManage: boolean }) {
  const { timeZone } = useTimeZone();
  const client = useQueryClient();
  const change = useMutation({
    mutationFn: (enabled: boolean) => api.setPluginEnabled(item, enabled),
    onSuccess: ({ item: updated }) => {
      client.setQueryData<{ items: PluginState[]; can_manage: boolean }>(["plugins"], (current) => current ? { ...current, items: current.items.map((value) => value.plugin_id === updated.plugin_id ? { ...updated, data_receipts: value.data_receipts } : value) } : current);
      void client.invalidateQueries({ queryKey: ["plugins"] });
      void client.invalidateQueries({ queryKey: ["report-v2"] });
    },
    onError: () => void client.invalidateQueries({ queryKey: ["plugins"] }),
  });
  const yesNo = (value: boolean) => t(value ? "plugins.yes" : "plugins.no");
  const draining = item.component_runtime === "draining";
  const runtime = item.component_runtime === "running" ? t("plugins.runtime.running")
    : draining ? t("plugins.runtime.draining") : item.component_runtime === "stopped" ? t("plugins.runtime.stopped") : t("plugins.runtime.unknown");
  const labels = Object.prototype.hasOwnProperty.call(pluginLabels, item.plugin_id) ? pluginLabels[item.plugin_id] : undefined;
  const name = labels ? t(labels.name) : item.plugin_id;
  const facts = item.data_receipts;
  const formatFact = (value: string | null | undefined) => formatDateTime(value, timeZone);
  const receipt = facts?.state === "unavailable" ? t("plugins.receiptUnavailable")
    : facts?.state === "not_supported" ? t("plugins.receiptUnsupported")
    : formatFact(facts ? facts.last_received_at : item.last_data_at_utc);
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
  return <div className="sli-ds-filters">
    <h2 className="sli-ds-section-title">{name} <Badge tone={item.enabled ? "success" : "warning"}>{t(item.enabled ? "plugins.enabled" : "plugins.disabled")}</Badge></h2>
    <p>{t(labels?.description ?? "plugins.description.unknown")}</p>
    <FactList facts={[
      { label: t("plugins.installed"), value: yesNo(item.installed) },
      { label: t("plugins.configured"), value: yesNo(item.configured) },
      { label: t("plugins.enabled"), value: yesNo(item.enabled) },
      { label: t("plugins.version"), value: item.package_version },
      { label: t("plugins.lastReceipt"), value: receipt },
      ...(facts && item.last_data_at_utc ? [
        { label: t("plugins.legacyObservation"), value: formatFact(item.last_data_at_utc) },
      ] : []),
      ...(facts && (facts.state === "observed" || facts.state === "no_receipts") ? [
        { label: t("plugins.lastImport"), value: formatFact(facts.last_imported_at) },
        ...(item.plugin_id === "sli.ad" || item.plugin_id === "sli.gpo" ? [
          { label: t("plugins.lastSnapshotCompleted"), value: formatFact(facts.last_snapshot_completed_at) },
        ] : []),
      ] : []),
      { label: t("plugins.runtime"), value: runtime },
    ]}/>
    <a href="/app/operations#runtime-workers">{t("plugins.diagnostics")}</a>
    {!item.enabled ? <p role="status">{t(draining ? "plugins.draining" : "plugins.preserved")}</p> : null}
    {change.error ? <FieldError error={new Error(errorMessage)}/> : null}
    {canManage ? <div className="sli-ds-filters__actions"><button type="button" className="sli-ds-button"
      disabled={change.isPending || !item.installed || (!item.enabled && (!item.configured || item.component_runtime !== "stopped"))}
      onClick={() => change.mutate(!item.enabled)}>{t(change.isPending ? "plugins.saving" : item.enabled ? "plugins.disable" : "plugins.enable")}</button></div> : null}
  </div>;
}
