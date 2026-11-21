import { useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import { DataTable, LoadingRegion, PageHeader, TableSkeleton, type TableColumn } from "../../design-system";
import { t } from "../../i18n";
import { EMPTY_VALUE, formatNumber } from "../../shared/format";
import { formatDate, formatDateTime } from "../../shared/date-time";
import { useEffectiveAccess, useTimeZone } from "../App";
import { downloadOperationsExport } from "../operations-actions";
import { statusAuditChecks, statusServices, statusSources } from "./status-view";
import { RestoreAgentAction } from "./agent-restore-action";
import { OldAgentsTable } from "./agent-removal-status";

const updateCommand = "sudo apt update && sudo apt upgrade";

function Status({ tone, children }: { tone: string; children: ReactNode }) {
  return <span className="sli-ds-shell__freshness" data-state={tone}><span className="sli-ds-shell__light" aria-hidden="true"/>{children}</span>;
}

/** Each request has its own result; a failed source never hides server health. */
export function SystemStatusPage() {
  const access = useEffectiveAccess();
  const canViewOperations = Boolean(access?.platform_owner || access?.capabilities.includes("operations.view"));
  const { timeZone } = useTimeZone();
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  const [exportError, setExportError] = useState(false);
  const [exporting, setExporting] = useState(false);
  const options = { retry: false, refetchInterval: 30_000 } as const;
  const setup = useQuery({ queryKey: ["setup-status"], queryFn: api.setupStatus, ...options });
  const operations = useQuery({ queryKey: ["operations-workers"], queryFn: api.operationsWorkers, ...options });
  const storage = useQuery({ queryKey: ["operations-storage"], queryFn: api.storageOverview, ...options });
  const diagnostics = useQuery({ queryKey: ["operations-diagnostics"], queryFn: api.diagnostics, ...options });
  const securityLogFull = useQuery({ queryKey: ["operations-security-log-full"], queryFn: api.securityLogFull, ...options,
    enabled: canViewOperations });
  const notifications = useQuery({ queryKey: ["system-status-notifications"], queryFn: () => api.notificationWorkspace(new URLSearchParams()), ...options });
  const smtp = useQuery({ queryKey: ["smtp-setup"], queryFn: api.smtpSetupStatus, ...options,
    enabled: !!notifications.data?.can_configure && notifications.data.channels.some((channel) => channel.kind === "smtp" && channel.enabled) });
  const telegram = useQuery({ queryKey: ["telegram-setup-status"], queryFn: () => api.telegramSetup("status"), ...options,
    enabled: !!notifications.data?.can_configure && notifications.data.channels.some((channel) => channel.kind === "telegram" && channel.enabled) });
  const health = setup.data?.agent_collection;
  const gaps = [...new Map((health?.items ?? []).flatMap((agent) => (agent.data_gaps ?? [])
    .map((gap) => [`${agent.id}:${gap.from_utc}:${gap.to_utc}`, { name: agent.name, ...gap }] as const))).entries()];
  const sources = statusSources(health, setup.data?.domains ?? [], timeZone);
  const auditChecks = statusAuditChecks(health, setup.data?.domains ?? []);
  const agentIssues = (health?.items ?? []).flatMap((agent) => [
    ...(agent.password_domain_required ? [{ id: `${agent.id}:password-domain`, name: agent.name,
      state: t("systemStatus.passwordDomainRequired", { name: agent.name }), action: EMPTY_VALUE, plain: true }] : []),
    ...(agent.duplicate_agents && agent.duplicate_agents > 1 ? [{ id: `${agent.id}:duplicate`, name: agent.name,
      state: t("agents.twoAgents", { name: agent.name }), action: t("agents.removeExtra"), plain: false }] : []),
    ...(agent.identity_conflict ? [{ id: `${agent.id}:identity`, name: agent.name,
      state: t("agents.identityConflict"), action: t("agents.checkIdentity"), plain: false }] : []),
  ]);
  const workers = operations.data?.workers;
  const services = statusServices(workers?.items ?? [], timeZone);
  const disk = storage.data?.storage.postgres_volume;
  const backup = storage.data?.storage.footprint?.backups;
  const bytes = (value: number | null | undefined) => typeof value === "number" && Number.isFinite(value) && value >= 0
    ? `${formatNumber(value / 1024 ** 3, { maximumFractionDigits: 1 })} ${t("operations.source.unit_gb")}` : EMPTY_VALUE;
  const diskRows = disk ? [{
    mount: disk.mount_point,
    used: bytes(disk.used_bytes),
    free: bytes(disk.free_bytes),
  }] : [];
  const latest = sources.map((source) => source.lastData).filter((time): time is string => Boolean(time))
    .sort((a, b) => Date.parse(b) - Date.parse(a))[0];
  const connected = sources.some((source) => source.connected);
  const channelReady = !notifications.isError && (notifications.data?.channels.some((channel) => channel.enabled && (channel.last_accepted_at
    || (channel.kind === "smtp" && !smtp.isError && smtp.data?.host && smtp.data.sender && smtp.data.secret_set && smtp.data.needs_save === false)
    || (channel.kind === "telegram" && !telegram.isError && telegram.data?.secret_set && telegram.data.chat_bound))) ?? false);
  const sourcesReady = !setup.isError && health && health.state !== "unavailable" && !health.diagnostics;
  const showSteps = sourcesReady && !(connected && channelReady && latest);
  const release = diagnostics.data?.release_metadata;
  const failed = (label: string, retry: () => unknown) => <p role="status">{t("systemStatus.failed", { table: label })} <button type="button" className="sli-ds-button" onClick={() => void retry()}>{t("systemStatus.retry")}</button></p>;
  const loading = (columns: number) => <LoadingRegion><TableSkeleton columns={columns}/></LoadingRegion>;
  const sourceColumns: TableColumn<(typeof sources)[number]>[] = [
    { key: "name", label: t("systemStatus.computer"), render: (row) => row.href
      ? <a href={row.href}>{row.name === EMPTY_VALUE ? t("systemStatus.openAgent") : row.name}</a> : row.name },
    { key: "collection", label: t("systemStatus.collection") },
    { key: "time", label: t("systemStatus.lastData") },
    { key: "state", label: t("systemStatus.state") },
    { key: "action", label: t("systemStatus.action"), render: (row) => row.fallback ? access?.platform_owner ? <RestoreAgentAction agentId={row.fallback.agent_id} currentAgentId={row.currentAgent} name={row.name} canRestore={row.fallback.can_restore}/> : EMPTY_VALUE : row.action },
  ];
  const serviceColumns: TableColumn<(typeof services)[number]>[] = [
    { key: "name", label: t("systemStatus.service") },
    { key: "state", label: t("systemStatus.state"), render: (row) => <Status tone={row.tone}>{row.state}</Status> },
    { key: "started", label: t("systemStatus.started") },
  ];

  return <section className="sli-ds-report">
    <PageHeader title={t("shell.adminNav.status")} actions={<button type="button" className="sli-ds-button" disabled={exporting} onClick={() => {
      setExporting(true);
      void api.operations().then((data) => { downloadOperationsExport(data); setExportError(false); })
        .catch(() => setExportError(true)).finally(() => setExporting(false));
    }}>{t("systemStatus.download")}</button>} meta={<>
      <span>{t("systemStatus.version", {
        version: release?.release_tag || release?.project_version || EMPTY_VALUE,
        commit: release?.git_commit || EMPTY_VALUE,
        date: formatDate(release?.installed_at_utc, timeZone),
      })} · </span>
      <code>{updateCommand}</code> <button type="button" className="sli-ds-button" onClick={() => {
        void (async () => {
          try { await navigator.clipboard.writeText(updateCommand); setCopied(true); setCopyError(false); }
          catch { setCopyError(true); setCopied(false); }
        })();
      }}>{t(copied ? "systemStatus.copied" : "systemStatus.copy")}</button>
    </>}/>
    {copyError ? <p role="alert">{t("systemStatus.copyFailed")}</p> : null}
    {exportError ? <p role="alert">{t("systemStatus.downloadFailed")}</p> : null}
    {showSteps ? <ol aria-label={t("systemStatus.firstRun")}>
      <li><span aria-label={t(connected ? "systemStatus.done" : "systemStatus.pending")}>{connected ? "✓" : "○"}</span> {t("systemStatus.step.agent")} <a className="sli-ds-button" href="/app/agents">{t("systemStatus.connect")}</a></li>
      <li><span aria-label={t(channelReady ? "systemStatus.done" : "systemStatus.pending")}>{channelReady ? "✓" : "○"}</span> {t("systemStatus.step.notifications")} <a className="sli-ds-button" href="/app/notifications">{t("systemStatus.configure")}</a></li>
      <li><span aria-label={t(latest ? "systemStatus.done" : "systemStatus.pending")}>{latest ? "✓" : "○"}</span> {latest ? t("systemStatus.step.received", { time: formatDateTime(latest, timeZone, { withYear: false }) }) : t("systemStatus.step.waiting")}</li>
    </ol> : null}
    {showSteps && (notifications.isError || smtp.isError || telegram.isError) ? failed(t("systemStatus.notifications"), () => Promise.all([notifications.refetch(), smtp.isEnabled ? smtp.refetch() : null, telegram.isEnabled ? telegram.refetch() : null])) : null}
    <h2 className="sli-ds-section-title">{t("systemStatus.sources")}</h2>
    {setup.isPending ? loading(sourceColumns.length) : sourcesReady ? <DataTable columns={sourceColumns} rows={sources} rowKey={(row) => row.id} caption={t("systemStatus.sources")} showFooter={false}/>
      : failed(t("systemStatus.sources"), setup.refetch)}
    {gaps.map(([key, gap]) => <p key={key}>{t("systemStatus.dataGap", { computer: gap.name || EMPTY_VALUE,
      period: `${formatDateTime(gap.from_utc, timeZone)} — ${formatDateTime(gap.to_utc, timeZone)}` })}</p>)}
    {canViewOperations && securityLogFull.data?.items.map((event) => <p key={`${event.server}:${event.time_created_utc}:${event.record_id}`}>
      {t("systemStatus.securityLogFull", { computer: event.server, time: formatDateTime(event.time_created_utc, timeZone, { seconds: true }), record: event.record_id })}
    </p>)}
    {canViewOperations && securityLogFull.isError ? failed(t("systemStatus.securityLogEvents"), securityLogFull.refetch) : null}
    {agentIssues.length ? <><h2 className="sli-ds-section-title">{t("agents.title")}</h2><DataTable columns={[
      { key: "name", label: t("systemStatus.computer") },
      { key: "state", label: t("systemStatus.state"), render: (row) => row.plain ? row.state : <Status tone="error">{row.state}</Status> },
      { key: "action", label: t("systemStatus.action") },
    ]} rows={agentIssues} rowKey={(row) => row.id} caption={t("agents.title")} showFooter={false}/></> : null}
    <OldAgentsTable agents={health?.replaced_agents ?? []} canRemove={Boolean(access?.platform_owner)}/>
    <h2 className="sli-ds-section-title">{t("systemStatus.services")}</h2>
    {operations.isPending ? loading(serviceColumns.length) : workers && workers.status !== "unavailable" && workers.items && !operations.isError
      ? <DataTable columns={serviceColumns} rows={services} rowKey={(row) => row.id} caption={t("systemStatus.services")} showFooter={false}/>
      : failed(t("systemStatus.services"), operations.refetch)}
    {auditChecks.length ? <><h2 className="sli-ds-section-title">{t("systemStatus.auditChecks")}</h2>
      <DataTable columns={[
        { key: "name", label: t("systemStatus.computer") }, { key: "check", label: t("systemStatus.auditCheck") },
        { key: "action", label: t("systemStatus.action"), render: (row) => <a href={row.href}>{row.action}</a> },
      ]} rows={auditChecks} rowKey={(row) => row.id} caption={t("systemStatus.auditChecks")} showFooter={false}/></> : null}
    {storage.isPending ? <><h2 className="sli-ds-section-title">{t("systemStatus.disk")}</h2>{loading(3)}</>
      : storage.isError ? <><h2 className="sli-ds-section-title">{t("systemStatus.disk")}</h2>{failed(t("systemStatus.disk"), storage.refetch)}</>
      : diskRows.length ? <><h2 className="sli-ds-section-title">{t("systemStatus.disk")}</h2><DataTable columns={[
        { key: "mount", label: t("operations.disk.partition") },
        { key: "used", label: t("systemStatus.used") }, { key: "free", label: t("systemStatus.free") },
      ]} rows={diskRows} rowKey={(row) => row.mount} caption={t("systemStatus.disk")} showFooter={false}/></> : null}
    {backup?.last_backup_at_utc && !storage.isError ? <p>{t(backup.same_disk_as_postgres === true
      ? "systemStatus.lastBackupSameDisk" : "systemStatus.lastBackup", {
      time: formatDateTime(backup.last_backup_at_utc, timeZone),
    })}</p> : null}
    {storage.data?.storage.agent_inbox_capacity === "full" ? <p>{t("systemStatus.inboxDiskFull")}</p> : null}
    {storage.data?.storage.agent_inbox_capacity === "unavailable" ? <p>{t("systemStatus.inboxDiskUnavailable")}</p> : null}
  </section>;
}
