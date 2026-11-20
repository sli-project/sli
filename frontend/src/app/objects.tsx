import { formatNumber } from "../shared/format";
import { useMemo, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useLocation, useNavigate } from "@tanstack/react-router";
import { api, type EntityWorkspaceItem, type V4ObjectItem } from "../api/client";
import { DataTable, FilterBar, MetricStrip, PageHeader, StateView, type FilterField, type FilterValues, type TableColumn } from "../design-system";
import { t } from "../i18n";
import { formatDateTime } from "../shared/date-time";
import { useTimeZone } from "./App";
import { sectionResultState } from "./entity-card";
import { РЕЖИМЫ_СУЩНОСТЕЙ, параметрыРежима, подписьРежима, числоВРежиме, type РежимСущностей } from "./entity-scope";
import { отказЗапроса } from "./event-presentation";
import { statusLabel } from "./status-labels";
import { objectTypeLabel } from "./report-labels";
import { globalSearchTarget, navigationRedirect } from "./navigation";
import { TechnicalKey } from "./technical-key";

type Source = "entities" | "registry";

const MODE_PARAMS: Record<string, РежимСущностей> = { participants: "участники", circumstances: "обстоятельства", all: "все" };
const MODE_KEYS: Record<РежимСущностей, string> = { "участники": "participants", "обстоятельства": "circumstances", "все": "all" };

const registryTypes = () => [
  { value: "ad_user", label: t("entities.objects.type.adUser") },
  { value: "computer", label: t("entities.objects.type.computer") },
  { value: "ad_group", label: t("entities.objects.type.group") },
  { value: "gpo", label: t("entities.objects.type.gpo") },
];

/** Retired lists preserve their filters in the global search results. */
export function entitiesRouteRedirect(search: Record<string, unknown>) {
  return navigationRedirect("/entities", search)!;
}

const failureState = (error: unknown) => ((error as { status?: number } | null)?.status === 403 ? "denied" as const : "unavailable" as const);

function EntitySource({ q, mode, format }: { q: string; mode: РежимСущностей; format: (value: string | null | undefined) => string }) {
  // The vocabulary is needed before the first filtered request: the server rejects a whole
  // request that names a type the corpus does not contain.
  const vocabulary = useQuery({ queryKey: ["entity-types"], queryFn: () => api.entitiesWorkspace(new URLSearchParams({ limit: "1" })), staleTime: 300_000, refetchOnWindowFocus: false });
  const counts = vocabulary.data?.type_counts;
  const filter = параметрыРежима(mode, counts);
  const entities = useQuery({ queryKey: ["entities", q, mode, filter], queryFn: () => api.entitiesWorkspace(new URLSearchParams([["q", q], ["limit", "50"], ...(filter ?? [])])), enabled: filter !== null, staleTime: 60_000, refetchOnWindowFocus: false });

  if (vocabulary.isError) {
    const failure = отказЗапроса(vocabulary.error as { status?: number; code?: string } | null, t("entities.objects.error.typesDictionary"));
    return <StateView state={failureState(vocabulary.error)} detail={t("entities.objects.error.typesDictionaryDetail", { detail: String(failure.detail) })} onRetry={failure.retry ? () => void vocabulary.refetch() : undefined}/>;
  }
  if (filter === null && !vocabulary.isLoading) {
    return <StateView state="empty" detail={t("entities.objects.empty.noTypes")}/>;
  }
  if (entities.isLoading || vocabulary.isLoading) return <StateView state="loading" skeleton="table"/>;
  if (entities.isError || !entities.data) {
    const failure = отказЗапроса(entities.error as { status?: number; code?: string } | null, t("entities.objects.error.entities"));
    return <StateView state={failureState(entities.error)} detail={failure.detail} onRetry={failure.retry ? () => void entities.refetch() : undefined}/>;
  }
  const data = entities.data;
  const inMode = числоВРежиме(mode, data.type_counts);
  const stateful = data.items.filter((item) => item.latest_state).length;
  const columns: TableColumn<EntityWorkspaceItem>[] = [
    { key: "display_name", label: t("entities.objects.col.entity"), render: (item) => <>
      <Link to="/entities/$entityId" params={{ entityId: String(item.id) }}>{item.display_name || t("entities.objects.unnamed")}</Link>
      <TechnicalKey value={item.natural_key} label={t("entities.key.details")}/>
    </> },
    { key: "type", label: t("entities.objects.col.type"), render: (item) => (item.type ? objectTypeLabel(item.type) : t("entities.objects.typeUnknown")) },
    { key: "latest_state", label: t("entities.objects.col.latestState"), render: (item) => {
      const state = item.latest_state;
      if (!state) return t("entities.objects.noState");
      return <>
        {statusLabel(state.status)}{state.summary ? ` · ${state.summary}` : ""}
        {state.evidence_event_db_id ? <div><Link to="/events/$eventId" params={{ eventId: String(state.evidence_event_db_id) }}>{t("entities.objects.evidenceDb", { id: String(state.evidence_event_db_id) })}</Link></div> : null}
      </>;
    } },
    { key: "first_seen_utc", label: t("entities.objects.col.firstSeen"), render: (item) => (format(item.first_seen_utc)) },
    { key: "last_seen_utc", label: t("entities.objects.col.lastSeen"), render: (item) => (format(item.last_seen_utc)) },
  ];
  return <>
    <MetricStrip items={[
      { key: "shown", label: t("entities.objects.metric.shown"), value: data.items.length, caption: q ? t("entities.objects.metric.shownCaptionQuery") : t("entities.objects.metric.shownCaptionRecent") },
      { key: "mode", label: mode === "все" ? t("entities.objects.metric.modeTotal") : t("entities.objects.metric.modeCurrent"), value: inMode, caption: подписьРежима(mode, data.type_counts) },
      { key: "state", label: t("entities.objects.metric.state"), value: stateful, caption: stateful ? t("entities.objects.metric.stateCaptionConfirmed") : t("entities.objects.metric.stateCaptionNone") },
    ]}/>
    {data.items.length
      ? <DataTable<EntityWorkspaceItem> caption={t("entities.objects.tableCaptionEntities")} columns={columns} rows={data.items} rowKey={(item) => String(item.id)}/>
      : <StateView state="empty" detail={q ? t("entities.objects.empty.query") : t("entities.objects.empty.initial")}/>}
    {data.has_more ? <StateView compact state="partial" detail={t("entities.objects.partial.moreMatches", { limit: String(data.limits.items ?? 50) })}/> : null}
  </>;
}

function RegistrySource({ q, type, format }: { q: string; type: string; format: (value: string | null | undefined) => string }) {
  const query = useQuery({ queryKey: ["v4", "objects", q, type], queryFn: () => api.v4Objects(new URLSearchParams({ ...(q ? { q } : {}), ...(type ? { type } : {}) })) });
  if (query.isLoading) return <StateView state="loading" skeleton="table"/>;
  if (query.isError || !query.data) {
    const failure = отказЗапроса(query.error as { status?: number; code?: string } | null, t("entities.objects.error.registry"));
    return <StateView state={failureState(query.error)} detail={failure.detail} onRetry={failure.retry ? () => void query.refetch() : undefined}/>;
  }
  const data = query.data;
  const items = data.items ?? [];
  const result = data.state === "empty" ? { state: "ok" as const, detail: null } : sectionResultState(data.state);
  const columns: TableColumn<V4ObjectItem>[] = [
    { key: "display_name", label: t("entities.objects.col.object"), render: (item) => <><Link to="/entities/$entityId" params={{ entityId: item.object_id }}>{item.display_name || t("entities.objects.unnamed")}</Link><TechnicalKey value={item.natural_key ?? item.object_id} label={t("entities.key.details")}/></> },
    { key: "object_type", label: t("entities.objects.col.type"), render: (item) => objectTypeLabel(item.object_type) },
    { key: "source", label: t("entities.objects.col.source") },
    { key: "freshness", label: t("entities.objects.col.freshness"), render: (item) => item.freshness ?? t("entities.objects.freshnessUnknown") },
    { key: "observed_at_utc", label: t("entities.objects.col.observed"), render: (item) => { const value = item.observed_at_utc ?? item.last_seen_utc; return format(value); } },
  ];
  let body: ReactNode;
  if (result.state !== "ok") body = <StateView state={result.state} detail={result.detail}/>;
  else if (!items.length) body = <StateView state="empty" detail={q || type ? t("entities.objects.empty.registryQuery") : t("entities.objects.empty.registryNoRecords")}/>;
  else body = <DataTable<V4ObjectItem> caption={t("entities.objects.tableCaptionRegistry")} columns={columns} rows={items} rowKey={(item) => `${item.object_type}:${item.object_id}`}/>;
  return <>
    {data.scope_filtered ? <StateView compact state="partial" detail={t("entities.objects.partial.scopeFiltered")}/> : null}
    {body}
    {data.has_more ? <StateView compact state="partial" detail={t("entities.objects.partial.limitedSelection")}/> : null}
  </>;
}

export function ObjectsPage() {
  const { timeZone } = useTimeZone();
  const location = useLocation();
  const navigate = useNavigate();
  const search = new URL(location.href, "http://localhost").search;
  const parameters = new URLSearchParams(search);
  const q = (parameters.get("q") ?? "").trim();
  const source: Source = parameters.get("source") === "registry" ? "registry" : "entities";
  const mode = MODE_PARAMS[parameters.get("mode") ?? ""] ?? "участники";
  const type = registryTypes().some((option) => option.value === parameters.get("type")) ? parameters.get("type")! : "";
  const format = (value: string | null | undefined) => formatDateTime(value, timeZone);
  const go = (next: { q?: string; source?: Source; mode?: РежимСущностей; type?: string }) => {
    const target: Record<string, string> = {};
    const nextQ = next.q ?? q; const nextSource = next.source ?? source; const nextMode = next.mode ?? mode; const nextType = next.type ?? type;
    if (nextQ) target.q = nextQ;
    if (nextSource === "registry") { target.source = "registry"; if (nextType) target.type = nextType; }
    else if (nextMode !== "участники") target.mode = MODE_KEYS[nextMode];
    void navigate({ to: globalSearchTarget("").to, search: target as never, replace: true });
  };

  const fields = useMemo<FilterField[]>(() => [
    { key: "q", label: t("entities.objects.filter.qLabel"), kind: "text", placeholder: t("entities.objects.filter.qPlaceholder") },
    ...(source === "registry" ? [{ key: "type", label: t("entities.objects.col.type"), kind: "select" as const, options: registryTypes() }] : []),
  ], [source]);
  const values = useMemo<FilterValues>(() => ({ q: q || undefined, type: type || undefined }), [q, type]);
  const counts = useQuery({ queryKey: ["entity-types"], queryFn: () => api.entitiesWorkspace(new URLSearchParams({ limit: "1" })), staleTime: 300_000, refetchOnWindowFocus: false, enabled: source === "entities" }).data?.type_counts;

  return <section className="sli-ds-report">
    <PageHeader
      title={t("entities.search.title")}
      subtitle={t("entities.objects.pageSubtitle")}
      meta={<span className="sli-ds-chip">{t("entities.objects.badgeLimited")}</span>}
    />
    <div className="sli-ds-header__meta" role="group" aria-label={t("entities.objects.sourceAria")}>
      <button type="button" className="sli-ds-chip" aria-pressed={source === "entities"} onClick={() => go({ source: "entities" })}>{t("entities.objects.sourceEntities")}</button>
      <button type="button" className="sli-ds-chip" aria-pressed={source === "registry"} onClick={() => go({ source: "registry" })}>{t("entities.objects.sourceRegistry")}</button>
    </div>
    <p className="sli-ds-header__subtitle">{source === "entities"
      ? t("entities.objects.subtitleEntities")
      : t("entities.objects.subtitleRegistry")}</p>
    <FilterBar fields={fields} values={values} defaults={{}} onApply={(next) => go({ q: typeof next.q === "string" ? next.q.trim() : "", type: typeof next.type === "string" ? next.type : "" })}/>
    {source === "entities" ? <div className="sli-ds-header__meta" role="group" aria-label={t("entities.objects.viewModeAria")}>
      {РЕЖИМЫ_СУЩНОСТЕЙ().map(({ режим, подпись, пояснение }) => {
        const number = числоВРежиме(режим, counts);
        return <button key={режим} type="button" className="sli-ds-chip" title={пояснение} aria-pressed={mode === режим} onClick={() => go({ mode: режим })}>{подпись}{number === null ? "" : ` · ${formatNumber(number)}`}</button>;
      })}
    </div> : null}
    <div className="sli-ds-report__views">
      {source === "entities" ? <EntitySource q={q} mode={mode} format={format}/> : <RegistrySource q={q} type={type} format={format}/>}
    </div>
  </section>;
}
