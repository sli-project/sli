import { useId, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Dialog, Heading, Modal, ModalOverlay } from "react-aria-components";
import { api, ApiResponseError, type PluginState } from "../../api/client";
import { Button, DataTable, PageHeader, StateView } from "../../design-system";
import { t } from "../../i18n";
import { FieldError } from "./gate";
import { formatDateTime } from "../../shared/date-time";
import { useEffectiveAccess, useTimeZone } from "../App";
import { AccessRequestStateView, useAccessRequest } from "../access-request-state";
import { moduleLastData, moduleName, moduleRows, moduleSources, moduleStatusId, moduleStatusText } from "./plugin-status";

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
  const { timeZone } = useTimeZone();
  const canManage = plugins.data?.can_manage === true;
  return <section className="sli-ds-report">
    <PageHeader title={t("plugins.title")}/>
    {plugins.isLoading ? <StateView state="loading"/> : plugins.error ? <StateView state="unavailable" detail={t("plugins.unavailable")} onRetry={() => void plugins.refetch()}/> : null}
    {!plugins.isError && plugins.data ? <DataTable
      caption={t("plugins.title")} rows={moduleRows(plugins.data.items)} rowKey={(item) => item.plugin_id}
      showFooter={false} density="compact" columns={[
        { key: "name", label: t("plugins.module"), width: "20%", wrap: true, render: moduleName },
        { key: "status", label: t("systemStatus.state"), width: "24%", wrap: true, render: (item) =>
          <a href={`/app/admin/status#${moduleStatusId(item)}`}>{moduleStatusText(item, timeZone)}</a> },
        { key: "sources", label: t("systemStatus.sources"), width: "12%", wrap: true, render: (item) => <span>{moduleSources(item)}</span> },
        { key: "lastData", label: t("plugins.lastData"), width: "18%", kind: "datetime", render: (item) => {
          const time = moduleLastData(item);
          return time ? <time dateTime={time}>{formatDateTime(time, timeZone)}</time> : <span>{formatDateTime(null, timeZone)}</span>;
        } },
        { key: "action", label: t("plugins.action"), width: "26%", render: (item) => <PluginActions item={item} canManage={canManage}/> },
      ]}/> : null}
  </section>;
}

function PluginActions({ item, canManage }: { item: PluginState; canManage: boolean }) {
  const [confirming, setConfirming] = useState<PluginState | null>(null);
  const descriptionId = useId();
  const client = useQueryClient();
  const change = useMutation({
    mutationFn: ({ target, enabled }: { target: PluginState; enabled: boolean }) => api.setPluginEnabled(target, enabled),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["report-v2"] });
      return client.invalidateQueries({ queryKey: ["plugins"] });
    },
    onError: () => void client.invalidateQueries({ queryKey: ["plugins"] }),
  });
  const name = moduleName(item);
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
  return <>
    <a className="sli-ds-button" href={`/app/admin/plugins/${item.plugin_id}`}>
      {t("plugins.open")}
    </a>
    {canManage ? <>{" "}<Button
      disabled={change.isPending || !item.installed || (!item.enabled && (!item.configured || item.component_runtime !== "stopped"))}
      onClick={() => {
        if (item.enabled) setConfirming(item);
        else change.mutate({ target: item, enabled: true });
      }}>{t(item.enabled ? "plugins.disable" : "plugins.enable")}</Button></> : null}
    {change.error ? <FieldError error={new Error(errorMessage)}/> : null}
    <ModalOverlay className="sli-ds-modal" isOpen={canManage && Boolean(confirming)} isDismissable onOpenChange={(open) => { if (!open) setConfirming(null); }}>
      <Modal className="sli-ds-modal__panel"><Dialog aria-describedby={descriptionId}>
        <Heading slot="title" level={2}>{t("plugins.confirmDisable", { name })}</Heading>
        <p id={descriptionId}>{item.plugin_id === "sli.ad" ? t("plugins.disableAdImpact") : t("plugins.disableImpact", { name })}</p>
        <Button autoFocus onClick={() => setConfirming(null)}>{t("agents.cancel")}</Button>{" "}
        <Button data-danger disabled={change.isPending} onClick={() => {
          if (confirming) change.mutate({ target: confirming, enabled: false });
          setConfirming(null);
        }}>{t("plugins.disable")}</Button>
      </Dialog></Modal>
    </ModalOverlay>
  </>;
}
