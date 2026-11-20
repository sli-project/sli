import { formatNumber } from "../shared/format";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ApiResponseError, api } from "../api/client";
import type { SigmaHistoryExecution, SigmaValidationRequest, SigmaValidationRule } from "../api/sigma-types";
import { Badge, Button, Callout, DataTable, FactList, Panel, StateView, type TableColumn } from "../design-system";
import { t, type MessageKey } from "../i18n";
import { sigmaReasonLabel, sigmaStateLabel, sigmaValidationRows, type SigmaValidationRow } from "./sigma-validation-view";

const fields: Array<{ key: keyof SigmaValidationRequest; label: MessageKey; optional?: boolean; date?: boolean }> = [
  { key: "installation_id", label: "security.sigma.scope.installation" },
  { key: "plugin_id", label: "security.sigma.scope.plugin" },
  { key: "source_instance_id", label: "security.sigma.scope.source" },
  { key: "source_generation", label: "security.sigma.scope.generation" },
  { key: "collection_scope_id", label: "security.sigma.scope.collection", optional: true },
  { key: "catalog_sha256", label: "security.sigma.scope.catalog" },
  { key: "since", label: "security.sigma.scope.since", date: true },
  { key: "until", label: "security.sigma.scope.until", date: true },
];
const emptyRequest: SigmaValidationRequest = { installation_id: "", plugin_id: "", source_instance_id: "",
  source_generation: "", collection_scope_id: "", catalog_sha256: "", since: "", until: "" };

export function ExecutionDetails({ row }: { row: { execution?: SigmaHistoryExecution; state: string;
  rule: Pick<SigmaValidationRule, "raw_sha256" | "upstream_commit"> } }) {
  const execution = row.execution;
  const number = (value: number | null) => value === null ? t("security.sigma.unmeasured")
    : formatNumber(value, { maximumFractionDigits: 2 });
  return <details>
    <summary>{t("security.sigma.details")}</summary>
    {execution ? <>
      <FactList facts={[
        { label: t("security.sigma.count.suppressed"), value: execution.counts.suppressed },
        { label: t("security.sigma.count.unknown"), value: execution.counts.unknown },
        { label: t("security.sigma.count.skipped"), value: execution.counts.skipped },
        { label: t("security.sigma.evaluable_percent"), value: number(execution.evaluable_percent) },
        { label: t("security.sigma.noise"), value: number(execution.matches_per_1000_evaluable) },
        { label: t("security.sigma.required_fields"), value: execution.required_fields.join(", ") },
      ]}/>
      <h3>{t("security.sigma.intervals")}</h3>
      {execution.evaluation_intervals.length ? <ul>{execution.evaluation_intervals.map((interval) =>
        <li key={`${interval.since}:${interval.until}`}>{interval.since} — {interval.until}</li>)}</ul>
        : <p>{t("security.sigma.state.incomplete")}</p>}
      <h3>{t("security.sigma.quality")}</h3>
      {execution.quality.map((quality, index) => <div key={index}>
        <p>{quality.since} — {quality.until} · {sigmaStateLabel(quality.status)}</p>
        <ul>{quality.reasons.map(([reason, count]) => <li key={reason}>{sigmaReasonLabel(reason)} · {count}</li>)}
          {quality.unknown_fields.map(([field, reason, count]) => <li key={`${field}:${reason}`}><code>{field}</code> · {sigmaReasonLabel(reason)} · {count}</li>)}</ul>
      </div>)}
    </> : <p>{t(row.state === "blocked" ? "security.sigma.reason.unsupported" : "security.sigma.reason.no_history")}</p>}
    <FactList facts={[
      { label: t("security.sigma.version.rule"), value: <code>{row.rule.raw_sha256}</code> },
      { label: t("security.sigma.version.upstream"), value: <code>{row.rule.upstream_commit}</code> },
      ...(execution ? [
        { label: t("security.sigma.version.manifest"), value: <code>{execution.manifest_sha256}</code> },
        { label: t("security.sigma.version.plan"), value: <code>{execution.plan_sha256}</code> },
        { label: t("security.sigma.version.compiler"), value: execution.compiler_version },
        { label: t("security.sigma.version.mapping"), value: execution.mapping_version },
        { label: t("security.sigma.version.overlay"), value: execution.overlay_sha256 ? <code>{execution.overlay_sha256}</code> : t("security.sigma.no_overlay") },
      ] : []),
    ]}/>
  </details>;
}

export function SigmaValidationPanel() {
  const [draft, setDraft] = useState(emptyRequest);
  const [request, setRequest] = useState<SigmaValidationRequest | null>(null);
  const query = useQuery({ queryKey: ["sigma-validation", request],
    queryFn: () => api.sigmaValidation(request!), enabled: request !== null, retry: false, refetchOnWindowFocus: false });
  const since = Date.parse(`${draft.since}Z`), until = Date.parse(`${draft.until}Z`);
  const valid = fields.every((field) => field.optional || draft[field.key].trim())
    && /^[a-f0-9]{64}$/.test(draft.catalog_sha256.trim())
    && Number.isFinite(since) && until > since && until - since <= 7 * 86400000;
  const data = request && !query.isError ? query.data : undefined;
  const rows = data ? sigmaValidationRows(data) : [];
  const columns: TableColumn<SigmaValidationRow>[] = [
    { key: "rule", label: t("security.sigma.rule"), render: (row) => <code>{row.rule.rule_id}</code> },
    { key: "state", label: t("security.sigma.state"), render: (row) => <Badge tone={["blocked", "not_evaluable", "degraded", "incomplete"].includes(row.state) ? "warning" : "neutral"}>{sigmaStateLabel(row.state)}</Badge> },
    ...(["scanned", "evaluable", "matched"] as const).map((key) => ({ key, label: t(`security.sigma.count.${key}`),
      render: (row: SigmaValidationRow) => row.execution ? row.execution.counts[key] : t("security.sigma.unmeasured") })),
    { key: "details", label: t("security.sigma.details"), render: (row) => <ExecutionDetails row={row}/> },
  ];
  const denied = query.error instanceof ApiResponseError && [401, 403].includes(query.error.status);
  return <Panel title={t("security.sigma.title")} subtitle={t("security.sigma.description")}>
    <Callout tone="neutral">{t("security.sigma.boundary")}</Callout>
    <form className="sli-ds-filters" onSubmit={(event) => {
      event.preventDefault();
      if (valid) setRequest({ ...Object.fromEntries(Object.entries(draft).map(([key, value]) => [key, value.trim()])) as SigmaValidationRequest,
        since: new Date(since).toISOString(), until: new Date(until).toISOString() });
    }}>
      <div className="sli-ds-filters__fields">{fields.map((field) => <div className="sli-ds-field" key={field.key}>
        <label htmlFor={`sigma-${field.key}`}>{t(field.label)}</label>
        <input id={`sigma-${field.key}`} type={field.date ? "datetime-local" : "text"} required={!field.optional}
          maxLength={256} value={draft[field.key]} onChange={(event) => {
            setDraft({ ...draft, [field.key]: event.target.value }); setRequest(null);
          }}/>
      </div>)}</div>
      <p className="sli-ds-header__subtitle">{t("security.sigma.scope.hint")}</p>
      <div className="sli-ds-filters__actions"><Button type="submit" disabled={!valid || (request !== null && query.isFetching)}>{t("security.sigma.load")}</Button></div>
    </form>
    {!request ? <StateView state="empty" detail={t("security.sigma.choose_scope")}/> : query.isPending ? <StateView state="loading"/> : null}
    {request && query.isError ? <StateView state={denied ? "denied" : "unavailable"} detail={t("security.sigma.reason.unavailable")} onRetry={() => void query.refetch()}/> : null}
    {data?.state === "unavailable" ? <StateView state="unavailable" detail={sigmaReasonLabel(data.reason ?? "projection_unavailable")} onRetry={() => void query.refetch()}/> : null}
    {data?.state === "available" ? <>
      <FactList facts={[
        { label: t("security.sigma.scope.source"), value: `${data.scope.plugin_id} · ${data.scope.source_instance_id} · ${data.scope.source_generation}` },
        { label: t("security.sigma.intervals"), value: `${data.since} — ${data.until}` },
      ]}/>
      {rows.length ? <DataTable columns={columns} rows={rows} rowKey={(row) => row.key} caption={t("security.sigma.title")}/>
        : <StateView state="empty" detail={t("security.sigma.no_rules")}/>}
    </> : null}
  </Panel>;
}
