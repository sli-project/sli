import { useEffect, useMemo, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto } from "../../api/report-v2-types";
import { ReportDenied } from "../../app/report-v2/ReportDenied";
import { Button, DataTable, FactList, FilterBar, ReportLayout, SeverityBadge, StateView, TabList, Tabs, type FilterValues, type PeriodValue, type ResultState, type TableColumn } from "../../design-system";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { t, type MessageKey } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
import { formatNumber } from "../../shared/format";
import { ActivityCounts, ActivityTable } from "./StationActivity";
import { ACTIVITY_TABS, appliedFilters, EVENT_VIEWS, eventHistory, eventPage, eventRows, evidenceHref, exactWindow, filterValues, fleetReturnHref,
  findingHref, journalHref, localHref, PAGE_SIZES, pageSize, patchedSearch, requestParams, resetEvents,
  stationRows, stationTab, WORKSTATIONS_KEY, type Station, type StationDetailResult, type StationEvent } from "./model";

export function StationName({ station }: { station: Station }) {
  const name = station.display_name ?? station.host_name ?? t("workstations.overview.unnamed");
  return <span className="sli-workstations__cell"><span>{name}</span>{station.host_name && station.host_name !== name ? <small>{station.host_name}</small> : null}</span>;
}

export function CollectionIndicator({ station, decorative = false }: { station: Station; decorative?: boolean }) {
  const label = t(`workstations.workspace.collection_${station.collection_state}`);
  return <span className="sli-workstations__dot" data-state={station.collection_state} title={label}
    role={decorative ? undefined : "img"} aria-label={decorative ? undefined : label} aria-hidden={decorative || undefined}/>;
}

export function CollectionStatus({ station }: { station: Station }) {
  return <span className="sli-workstations__status"><CollectionIndicator station={station} decorative/>
    {t(`workstations.workspace.collection_${station.collection_state}`)}
  </span>;
}

function EventInterval({ row, timeZone }: { row: StationEvent; timeZone: string }) {
  const format = (value: string | null) => formatDateTime(value, timeZone, { seconds: true });
  return <span className="sli-workstations__cell"><span>{format(row.first)}</span>
    {row.last && row.last !== row.first ? <small>— {format(row.last)}</small> : null}</span>;
}

function EventResult({ value }: { value: string | null }) {
  return value === "success" || value === "failure" ? <span className="sli-ds-result" data-result={value}>
    {t(`reports.v2.events.journal.result.${value}`)}</span> : <>—</>;
}

function FindingLink({ row, station, back }: { row: StationEvent; station: Station; back: string }) {
  const href = findingHref(row, station, back);
  return href ? <a href={href} onClick={event => event.stopPropagation()} className="sli-workstations__finding">
    {row.severity ? <SeverityBadge severity={row.severity}/> : null}<span>{t("workstations.workspace.finding", { id: row.findingId! })}</span>
  </a> : <>—</>;
}

const profileChannel: Record<number, string> = {
  4624: "Security", 4625: "Security", 1102: "Security", 4688: "Security", 4698: "Security", 4732: "Security", 4733: "Security", 6416: "Security",
  5001: "Microsoft-Windows-Windows Defender/Operational", 5010: "Microsoft-Windows-Windows Defender/Operational", 5012: "Microsoft-Windows-Windows Defender/Operational",
  7036: "System", 7040: "System", 7045: "System",
};

function eventTitle(row: StationEvent): string {
  return row.code && Object.hasOwn(profileChannel, row.code) && row.channel === profileChannel[Number(row.code)]
    ? t(`workstations.workspace.event_${row.code}` as MessageKey) : row.title ?? t("workstations.workspace.unknown_event");
}

function fileName(path: string | null): string | null {
  return path?.split(/[\\/]/).pop() || null;
}

function CollectionDetails({ station }: { station: Station }) {
  const { formatDateTime: format } = useDateFormatters();
  const events = station.profile.event_ids.map(code => ({ code, channel: profileChannel[code] ?? "—" }));
  const status = ["active", "revoked", "pending", "disabled"].includes(station.agent_status ?? "")
    ? t(`workstations.workspace.agent_${station.agent_status}` as MessageKey) : station.agent_status ?? "—";
  return <div className="sli-workstations__collection">
    <section><h2>{t("workstations.workspace.binding")}</h2><FactList facts={[
      { label: t("workstations.workspace.collection"), value: <CollectionStatus station={station}/> },
      { label: t("workstations.workspace.registration"), value: status },
      { label: t("workstations.workspace.last_contact"), value: format(station.last_seen) },
      { label: t("workstations.workspace.assigned_revision"), value: station.policy_revision ?? "—" },
      { label: t("workstations.workspace.applied_revision"), value: station.applied_policy_revision ?? "—" },
      { label: t("workstations.overview.os"), value: [station.operating_system, station.operating_system_version].filter(Boolean).join(" · ") || "—" },
      { label: t("workstations.workspace.metadata_at"), value: format(station.metadata_observed_at) },
      { label: t("workstations.workspace.source_id"), value: station.source_instance_id ?? "—" },
    ]}/></section>
    <section><h2>{t("workstations.workspace.profile")}</h2>
      {station.profile.state !== "supported" ? <p className="sli-workstations__local-state">{t(`workstations.workspace.profile_${station.profile.state}`)}</p> : null}
      {events.length ? <DataTable caption={t("workstations.workspace.profile_events")} rows={events} rowKey={row => String(row.code)} compact density="compact" stickyHeader={false} showFooter={false}
        columns={[{ key: "code", label: t("workstations.workspace.event_code"), value: row => row.code, width: "6rem" },
          { key: "operation", label: t("workstations.workspace.operation"), value: row => Object.hasOwn(profileChannel, row.code)
            ? t(`workstations.workspace.event_${row.code}` as MessageKey) : t("workstations.workspace.unknown_event") },
          { key: "channel", label: t("workstations.workspace.channel"), value: row => row.channel }]}/> : null}
      {station.profile.channels.length ? <p className="sli-workstations__local-state">{t("workstations.workspace.channels")}: {station.profile.channels.join(" · ")}</p> : null}
    </section>
    <details className="sli-workstations__technical"><summary>{t("workstations.workspace.identifiers")}</summary><FactList facts={[
      { label: t("workstations.workspace.agent_id"), value: station.agent_key },
      { label: t("workstations.workspace.transport_id"), value: station.transport_agent_id ?? "—" },
      { label: t("workstations.workspace.server_id"), value: station.server_id ?? "—" },
      { label: t("workstations.workspace.domain_id"), value: station.domain_id ?? "—" },
    ]}/></details>
  </div>;
}

function EventFacts({ row, station, detail, search, timeZone }: { row: StationEvent; station: Station; detail: StationDetailResult["detail"]; search: URLSearchParams; timeZone: string }) {
  const back = localHref(search), evidence = evidenceHref(row, station, back), journal = journalHref(detail, back, row);
  const period = exactWindow(search, timeZone);
  const crossesBoundary = row.group && period && (row.first && Date.parse(row.first) < Date.parse(period.from) || row.last && Date.parse(row.last) >= Date.parse(period.to));
  return <section className="sli-workstations__event" aria-label={t("workstations.workspace.event_facts")}>
    <div className="sli-workstations__event-heading"><h2 title={row.title ?? undefined}>{eventTitle(row)}</h2>
      {row.findingId ? <FindingLink row={row} station={station} back={back}/> : null}
    </div>
    <FactList facts={[
      { label: t("workstations.workspace.event_code"), value: row.code ?? "—" },
      { label: t("workstations.workspace.interval"), value: <EventInterval row={row} timeZone={timeZone}/> },
      { label: t("workstations.workspace.observations"), value: row.count === null ? "—" : formatNumber(row.count) },
      { label: t("workstations.workspace.account"), value: row.account ?? "—" },
      ...(row.initiator ? [{ label: t("workstations.workspace.initiator"), value: row.initiator }] : []),
      ...(row.imagePath ? [{ label: t("workstations.workspace.process_path"), value: row.imagePath }] : []),
      ...(row.parentImagePath ? [{ label: t("workstations.workspace.parent_process"), value: fileName(row.parentImagePath) }] : []),
      ...(row.commandLine ? [{ label: t("workstations.workspace.command_line"), value: row.commandLine }] : []),
      ...(row.deviceName ? [{ label: t("workstations.workspace.device_name"), value: row.deviceName }] : []),
      ...(row.deviceClass ? [{ label: t("workstations.workspace.device_class"), value: row.deviceClass }] : []),
      { label: t("workstations.workspace.result"), value: <EventResult value={row.result}/> },
      ...(row.logonType ? [{ label: t("workstations.workspace.logon_type"), value: row.logonType }] : []),
      ...(row.address ? [{ label: t("workstations.workspace.address"), value: row.address }] : []),
      { label: t("workstations.workspace.channel"), value: row.channel ?? "—" },
      ...(row.computer ? [{ label: t("workstations.workspace.event_computer"), value: row.computer }] : []),
    ]}/>
    {crossesBoundary ? <p className="sli-workstations__local-state">{t("workstations.workspace.group_boundary")}</p> : null}
    <div className="sli-ds-header__actions">{evidence ? <a className="sli-ds-button" href={evidence}>{t("workstations.workspace.original")}</a> : null}
      {journal ? <a className="sli-ds-button" href={journal}>{t(row.expandable && row.id ? "workstations.workspace.group_journal" : "workstations.workspace.open_journal")}</a> : null}</div>
  </section>;
}

export function WorkstationWorkspace({ definition, stationId, search, session, timeZone, update, onBack }: {
  definition: ReportDefinitionDto; stationId: string; search: URLSearchParams; session: string; timeZone: string;
  update: (patch: Record<string, string | null>, replace?: boolean) => void; onBack: () => void;
}) {
  const { formatDateTime: format } = useDateFormatters();
  const params = requestParams(search, timeZone, definition, true);
  const query = useQuery({ queryKey: [WORKSTATIONS_KEY, session, "station", stationId, params?.toString()],
    queryFn: () => api.reportV2Detail(WORKSTATIONS_KEY, stationId, params!) as Promise<StationDetailResult>,
    enabled: Boolean(params), retry: false, refetchOnWindowFocus: false, staleTime: 30_000 });
  const denied = query.data?.access?.allowed === false || query.data?.state === "denied"
    || query.error instanceof ApiResponseError && [401, 403].includes(query.error.status);
  const failed = Boolean(query.error) || query.data?.state === "error";
  const result = !denied && !failed && !query.isFetching ? query.data : undefined;
  const detail = result?.detail;
  let station: Station | undefined, rows: StationEvent[] = [], invalid = false;
  try {
    if (result) {
      if (!detail?.station || !detail.events || !Array.isArray(detail.events.items)) throw new Error("workstation_detail_invalid");
      station = stationRows([detail.station])[0];
      if (station.station_id !== stationId) throw new Error("workstation_detail_invalid");
      if (!["denied", "error", "not_collected"].includes(detail.events.state)) rows = eventRows(detail.events.items);
    }
  } catch { station = undefined; rows = []; invalid = true; }
  const state: ResultState = denied ? "denied" : failed || invalid ? "error" : !params ? "empty"
    : query.isPending || query.isFetching ? "loading" : station ? "ok" : "not_collected";
  const tab = stationTab(search);
  const activity = detail && ["ok", "empty"].includes(detail.events?.state) ? detail.activity : null;
  const program = search.get("program");
  const selected = tab === "events" ? search.get("event") : null;
  const row = selected ? rows.find(event => event.key === selected) : undefined;
  const eventList = useRef<HTMLDivElement>(null), scroll = useRef(0);
  const previousSelection = useRef(selected);
  useEffect(() => {
    if (previousSelection.current && !selected && eventList.current) {
      const viewport = eventList.current.querySelector<HTMLElement>(".sli-ds-table__scroll");
      if (viewport) viewport.scrollTop = scroll.current;
    }
    previousSelection.current = selected;
  }, [selected]);
  const backHref = fleetReturnHref(search);
  const values = useMemo(() => filterValues(search, timeZone), [search.toString(), timeZone]);
  const eventFilters = useMemo<FilterValues>(() => ({ view: values.view }), [values.view]);
  const apply = (draft: FilterValues) => update({ ...appliedFilters(draft, search, timeZone), ...resetEvents, cursor: null });
  const bounds = exactWindow(search, timeZone);
  const size = pageSize(search.get("event_limit") ?? search.get("limit"), definition.limits.max);
  const page = eventPage(search), trail = eventHistory(search);
  const nextPage = () => {
    const cursor = detail?.events.next_cursor;
    if (!cursor) return;
    update({ event_cursor: cursor, event_history: JSON.stringify([...trail, search.get("event_cursor")]), event_page: String(page + 1), event: null });
  };
  const previousPage = () => {
    const previous = trail.at(-1) ?? null;
    update({ event_cursor: previous, event_history: trail.length > 1 ? JSON.stringify(trail.slice(0, -1)) : null,
      event_page: trail.length ? String(Math.max(0, page - 1)) : null, event: null });
  };
  const select = (event: StationEvent) => {
    scroll.current = eventList.current?.querySelector<HTMLElement>(".sli-ds-table__scroll")?.scrollTop ?? 0;
    update({ event: event.key });
  };
  const back = localHref(search);
  const columns: TableColumn<StationEvent>[] = [
    { key: "interval", label: t("workstations.workspace.interval"), render: event => <EventInterval row={event} timeZone={timeZone}/>, minWidth: "12rem" },
    { key: "importance", label: t("workstations.activity.importance"), width: "10%", render: event => <SeverityBadge severity={event.importance}/> },
    { key: "operation", label: t("workstations.workspace.operation"), width: "28%", minWidth: "15rem", render: event => <span className="sli-workstations__cell">
      <a className="sli-ds-table__link" title={event.title ?? undefined} href={localHref(patchedSearch(search, { event: event.key }))} onClick={click => {
        click.stopPropagation(); if (click.ctrlKey || click.metaKey || click.shiftKey || click.altKey) return; click.preventDefault(); select(event);
      }}>{[eventTitle(event), fileName(event.imagePath) ?? event.deviceName].filter(Boolean).join(" · ")}</a>
      <small>{[event.code, event.deviceClass, event.parentImagePath && t("workstations.workspace.parent_process_value", {
        name: fileName(event.parentImagePath) ?? event.parentImagePath,
      })].filter(Boolean).join(" · ")}</small>
      {event.commandLine ? <span className="sli-ds-table__cell-line"><small title={event.commandLine}>{event.commandLine}</small></span> : null}</span> },
    { key: "account", label: t("workstations.workspace.account"), value: event => event.account ?? "—", hiddenByDefault: false },
    { key: "initiator", label: t("workstations.workspace.initiator"), value: event => event.initiator ?? "—", hiddenByDefault: !rows.some(event => event.initiator) },
    { key: "address", label: t("workstations.workspace.address"), value: event => event.address ?? "—", hiddenByDefault: !rows.some(event => event.address) },
    { key: "result", label: t("workstations.workspace.result"), render: event => <EventResult value={event.result}/>, hiddenByDefault: !rows.some(event => event.result) },
    { key: "count", label: t("workstations.workspace.observations"), kind: "number", value: event => event.count },
    { key: "finding", label: t("workstations.workspace.related_finding"), render: event => station ? <FindingLink row={event} station={station} back={back}/> : "—", hiddenByDefault: !rows.some(event => event.findingId) },
    { key: "channel", label: t("workstations.workspace.channel"), value: event => event.channel ?? "—", hiddenByDefault: true },
  ];
  const eventsState = detail?.events.state;
  const journal = station && !program ? journalHref(detail, back) : null;
  const title = station?.display_name ?? station?.host_name ?? t("workstations.overview.station");
  const retry = () => search.get("event_cursor") ? update(resetEvents) : void query.refetch();
  const changeTab = (value: string) => update({ station_tab: value, program: null, ...resetEvents });
  const showFilters = !denied && tab !== "collection" && !selected;
  const showCategory = tab === "events" && !program;
  return <div className="sli-workstations sli-workstations--station"><Tabs items={[
    ...ACTIVITY_TABS.map(key => ({ key, label: t(`workstations.activity.${key}`) })),
    { key: "events", label: t("workstations.workspace.events") },
  ]} active={tab === "collection" ? "important" : tab} onChange={changeTab}>
    <ReportLayout title={title} tabbed={tab !== "collection"} state={state}
      metrics={activity && tab !== "collection" ? <ActivityCounts activity={activity} search={search} update={update}/> : <></>}
      controls={showFilters ? { period: { value: values.period as PeriodValue, presets: ["24h", "7d", "30d", "custom"], precision: "datetime-local",
        showPrevious: false, strictRange: true, onChange: period => apply({ period }) } } : {}}
      meta={station ? <><span>{station.domain_name ?? "—"}</span>{station.operating_system ? <span>{station.operating_system}</span> : null}
        <span>{t("workstations.workspace.last_contact")}: {format(station.last_seen)}</span><CollectionStatus station={station}/></> : null}
      actions={<><a className="sli-ds-button" href={backHref} onClick={event => {
        if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return; event.preventDefault(); onBack();
      }}>{t("workstations.workspace.back_fleet")}</a>
        {selected && !denied ? <button type="button" className="sli-ds-button" onClick={() => update({ event: null })}>{t("workstations.workspace.back_events")}</button> : null}
        {station ? <Button onClick={() => changeTab(tab === "collection" ? "important" : "collection")}>
          {t(tab === "collection" ? "workstations.activity.important" : "workstations.workspace.collection_tab")}</Button> : null}
        {!denied ? <button type="button" className="sli-ds-button" disabled={query.isFetching} onClick={() => {
          if (search.get("event_cursor")) update(resetEvents); else void query.refetch();
        }}>{t("workstations.workspace.refresh")}</button> : null}</>}
      tabs={tab !== "collection" ? <TabList label={title} variant="underline"/> : undefined}
      filters={showFilters && showCategory ? <FilterBar align="start" layout="inline" compact applyInline primaryKeys={["view"]}
        fields={[{ key: "view", label: t("workstations.workspace.event_view"), kind: "select",
          options: EVENT_VIEWS.map(value => ({ value, label: t(`workstations.workspace.view_${value}`) })) }]}
        values={eventFilters} defaults={{ view: "all" }} onApply={apply}/> : null}
      stateView={denied ? <ReportDenied reportKey={WORKSTATIONS_KEY}/>
        : !params ? <p role="status" className="sli-workstations__local-state">{t("workstations.workspace.invalid_period")}</p>
        : <StateView state={state} onRetry={retry}/> }>
      {station && detail ? tab === "collection" ? <CollectionDetails station={station}/>
        : <>
          {tab === "events" ? <div className="sli-workstations__context"><span>{t("workstations.workspace.event_period")}: {format(bounds?.from)} — {format(bounds?.to)} · {timeZone}</span>
            {journal && !selected ? <a href={journal}>{t("workstations.workspace.open_journal")}</a> : null}
            {program && !selected ? <Button onClick={() => update({ program: null, ...resetEvents })}>
              {t("workstations.activity.clear_program", { program })}</Button> : null}</div> : null}
          {eventsState === "denied" ? <p role="status" className="sli-workstations__local-state">{t("workstations.workspace.events_denied")}</p>
            : eventsState === "error" ? <StateView state="error" onRetry={retry}/>
            : eventsState === "not_collected" ? <p role="status" className="sli-workstations__local-state">{t("workstations.workspace.events_unavailable")}</p>
            : tab !== "events" ? activity ? <ActivityTable key={tab} tab={tab} activity={activity} search={search} timeZone={timeZone} update={update}/>
              : <StateView state="error" onRetry={retry}/>
            : selected ? row ? <EventFacts row={row} station={station} detail={detail} search={search} timeZone={timeZone}/>
              : <p role="status" className="sli-workstations__local-state">{t("workstations.workspace.event_missing")}</p>
            : <div ref={eventList}><DataTable caption={t("workstations.workspace.station_events")} rows={rows} columns={columns} rowKey={event => event.key}
              onRowClick={select} compact density="compact" total={detail.events.filtered_count}
              emptyContent={<p>{t("workstations.workspace.events_empty")}</p>}
              pageSize={{ value: size, options: PAGE_SIZES.filter(value => value <= definition.limits.max), onChange: value => update({ event_limit: String(value), ...resetEvents }) }}
              pagination={{ start: page * size + 1, busy: query.isFetching,
                onPrevious: trail.length || search.get("event_cursor") ? previousPage : undefined,
                onNext: detail.events.has_more && detail.events.next_cursor ? nextPage : undefined }}/></div>}
        </> : null}
    </ReportLayout>
  </Tabs></div>;
}
