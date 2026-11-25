import { EventJournal } from "./journal";
import { DomainChanges } from "./DomainChanges";
import { ProblemsQueue, ProblemJournal } from "./ProblemsQueue";
import { workstationColumns } from "./workstation-columns";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { formatClockWithOffset, isValidTimeZone, localDateTimeToUtc } from "../../shared/date-time";
import { useEffect, useMemo, useRef, useState } from "react";
import { keepPreviousData, useInfiniteQuery, useQuery } from "@tanstack/react-query";
import {
  DataTable, DetailDrawer, FactList, FilterBar, MetricStrip, periodBounds, ReportLayout, StateView, TabList, Tabs,
  type FilterValues, type PeriodPreset, type PeriodValue, type ResultState, type SortState,
} from "../../design-system";
import type { PageHeaderControls } from "../../design-system/PageHeader";
import { t } from "../../i18n";
import { reportMetadataText } from "../../i18n/report-metadata";
import { api, ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import { useEffectiveAccess, useTimeZone } from "../App";
import { canResolveProblem, queueStatus, ResolveProblem, statusLabel } from "../problem-lifecycle";
import {
  AD_DOMAIN_REPORTS, apiParams, applyPreset, columnValue, defaultValues, fillTemplate, filterFields, isPresetActive, paramOptions,
  primaryFilterKeys, searchFromValues, valuesFromSearch, valuesReady, visiblePresets, vpnViewBranchKey,
} from "./state";
import { withReturnTo } from "./legacy";
import { CellComponent, cellKind, CopyFactsButton, DetailSection, ResultWindowContext, rowFactsText, tableColumns } from "./DetailSection";
import { CollectionView, ViewTabs } from "./views";
import { PAGE_ACTIONS, VIEW_COMPONENTS } from "./custom";
import { reportEmptyText } from "./empty-copy";
import { accessErrorReason, accessReason, categoryNames } from "./access";
import { EmptyRecoveryActions, EmptyRecoveryDetail, reportEmptyRecovery } from "./empty-recovery";
import { ReportPassportMeta } from "./ReportPassportMeta";
import { ArchiveDomainNotice } from "./ADSourceNotice";
import { ReportState } from "./ReportState";
import { FirstAdSource, useFirstAdSource } from "../first-ad-source";
import { ReportDenied } from "./ReportDenied";
import { PairsWindowState } from "./PairsWindowState";
import { preserveNavigationView } from "../navigation";
import { FileAuditReport } from "../../plugins/file-audit/FileAuditReport";
import { WorkstationsReport } from "../../plugins/workstations/WorkstationsReport";
import { isFileAuditReport } from "../../plugins/file-audit/report";
import { ComputerChecks, computerTableColumns } from "../../plugins/ad/ComputerChecks";
import { UserChanges, UserChecks, userTableColumns } from "../../plugins/ad/UserChecks";
import { UserCard } from "../../plugins/ad/UserCard";
import { gpoReportDefinition } from "../../plugins/ad/gpo-report";
import { GpoPolicyReport } from "../../plugins/ad/GpoPolicyReport";
import { ComputerLogonsEmpty, ComputerPanel, computerEmpty, computerInventoryColumns, computerLogonCount } from "./ComputersPanel";
import { AdStateReport } from "./AdStateReport";

type Row = Record<string, unknown>;
type AdditionalTabs = { additionalTabs?: { key: string; label: string }[]; onAdditionalTab?: (key: string) => void };
const problemDescriptionColumns = ["what", "why", "next"];

function queueWindow(period: PeriodValue, timeZone: string) {
  if (period.preset !== "custom" || !period.from || !period.to || period.from.includes("T") || period.to.includes("T")) return periodBounds(period);
  if (timeZone !== "browser" && !isValidTimeZone(timeZone)) return null;
  const nextDay = new Date(Date.parse(period.to) + 86_400_000).toISOString().slice(0, 10);
  const from = localDateTimeToUtc(`${period.from}T00:00`, timeZone);
  const to = localDateTimeToUtc(`${nextDay}T00:00`, timeZone);
  return from && to ? { from, to } : null;
}

const WORKSTATION_SOURCE_REASONS = {
  source_timeout: "reports.workstations.source_timeout",
  source_not_initialized: "reports.workstations.source_not_initialized",
  source_access_denied: "reports.workstations.source_access_denied",
  source_unavailable: "reports.workstations.source_unavailable",
} as const;

function getSectionCrumb(section: string): string {
  const crumbs: Record<string, string> = {
    investigation: t("reports.renderer.crumb_investigation"),
    "reports/identity": t("reports.renderer.crumb_identity"),
    "reports/computers": t("reports.renderer.crumb_computers"),
    "reports/policies": t("reports.renderer.crumb_policies"),
    "reports/remote-access": t("reports.renderer.crumb_remote_access"),
    operations: t("reports.renderer.crumb_operations"),
    admin: t("reports.renderer.crumb_admin"),
  };
  return crumbs[section] ?? t("reports.renderer.crumb_reports");
}

export function errorState(error: unknown): { state: ResultState; detail?: string } {
  if (error instanceof ApiResponseError) {
    if (error.status === 401 || error.status === 403) return { state: "denied", detail: accessErrorReason(error) };
    if (error.code === "gpo_snapshot_unavailable") return { state: "error", detail: t("reports.renderer.error_gpo_snapshot") };
    if (error.status === 400) return { state: "error", detail: t("reports.renderer.error_params", { code: error.code ?? "400" }) };
  }
  return { state: "error" };
}

function replaceUrl(search: URLSearchParams) {
  preserveNavigationView(search, window.location.search);
  const query = search.toString();
  const next = `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`;
  if (next !== `${window.location.pathname}${window.location.search}${window.location.hash}`) window.history.replaceState(window.history.state, "", next);
}

function EventListError({ reportKey, onRetry }: { reportKey: string; onRetry: () => void }) {
  return <div role="alert">{t(reportKey === "events.journal" ? "reports.v2.events.journal.load_failed" : "reports.domain_events.load_failed")}{" "}
    <button className="sli-ds-button" type="button" onClick={onRetry}>{t("state.retry")}</button>
  </div>;
}

/** Renders any report declared on the v2 framework (ADR 0010 §4). */
export function ReportRenderer({ reportKey, initialSearch, ...tabs }: { reportKey: string; initialSearch?: string } & AdditionalTabs) {
  const definition = useQuery({ queryKey: ["report-v2", "definition", reportKey], queryFn: () => api.reportV2Definition(reportKey), staleTime: 5 * 60_000, retry: false });
  const search = new URLSearchParams(initialSearch ?? window.location.search);
  const access = useEffectiveAccess();
  const vpn = reportKey === "vpn.connections" && definition.isSuccess ? definition.data : undefined;
  const vpnDefaults = vpn && searchFromValues(vpn, defaultValues(vpn));
  const vpnNeedsFirstDomain = vpn && access?.capabilities.includes("access.manage") && vpn.access?.allowed === true
    && vpn.views[0]?.access?.allowed !== false && vpn.plugin?.plugin_id === "sli.remote-access"
    && vpn.plugin.state === "enabled" && vpn.plugin.read_only === false
    && vpn.default_domain_state === "unknown" && vpn.default_domain_id == null
    && !paramOptions(vpn, "domain").length
    && !["domain", "domain_id", "scope"].some(key => search.has(key))
    && [...search].every(([key, value]) => {
      if (key === "nav_view") return value === "connections";
      if (key === "tab") return value === vpn.views[0]?.key;
      return vpnDefaults?.get(key) === value;
    });
  const firstAdSource = useFirstAdSource(search, Boolean(vpnNeedsFirstDomain)
    || (AD_DOMAIN_REPORTS.has(reportKey) && definition.isSuccess
      && definition.data.default_domain_state !== "available" && !definition.data.filter_options?.domain?.length));
  if (definition.isLoading || firstAdSource === undefined) return <ReportLayout title={t("reports.renderer.loading_title")} state="loading"/>;
  if (definition.error || !definition.data) {
    const { state, detail } = errorState(definition.error);
    if (state === "denied") return <ReportDenied reportKey={reportKey} reason={detail} page/>;
    if (reportKey === "events.journal" || reportKey === "security.events.chains") {
      return <ReportLayout title={t(reportKey === "events.journal" ? "reports.v2.events.journal.title" : "reports.v2.security.events.chains.title")}
        state={state} stateView={<EventListError reportKey={reportKey} onRetry={() => void definition.refetch()}/>}/>;
    }
    const title = reportMetadataText(reportKey, "title", t("reports.renderer.default_title"));
    return <ReportLayout title={title} state={state} stateView={<ReportState state={state} detail={detail} subject={title} onRetry={() => void definition.refetch()}/>}/>;
  }
  if (firstAdSource) return <ReportLayout title={definition.data.title} state="empty" stateView={vpnNeedsFirstDomain
    ? <StateView state="empty" titleMessage={{ code: "pluginPage.noDomains", params: {} }} detail={
      <a className="sli-ds-button" href="/app/setup#setup-domains">{t("setup.domain.add")}</a>
    }/> : <FirstAdSource/>}/>;
  if (reportKey === "events.journal") {
    const query = new URLSearchParams(initialSearch ?? window.location.search);
    const finding = Number(query.get("finding"));
    if (Number.isSafeInteger(finding) && finding > 0) return <ProblemJournal definition={definition.data} finding={finding} domain={query.get("domain") ?? ""}/>;
    return <EventJournal definition={definition.data} initialSearch={initialSearch}/>;
  }
  if (reportKey === "workstations.overview") return <WorkstationsReport definition={definition.data}/>;
  if (reportKey === "security.events.chains" && definition.data.params.some(({ key }) => key === "changes_view")) {
    const search = new URLSearchParams(initialSearch ?? window.location.search);
    if (search.get("category") !== "authentication" && !["4624", "4625", "4771", "4776"].includes(search.get("event_id") ?? ""))
      return <DomainChanges definition={definition.data} initialSearch={initialSearch}/>;
  }
  if (reportKey === "ad.gpo.v2" && definition.data.views.some((view) => view.component === "gpo.policy-list"))
    return <GpoPolicyReport definition={definition.data} search={initialSearch}/>;
  if (reportKey === "security.problems" && definition.data.params.some(({ key }) => key === "queue_view")) return <ProblemsQueue definition={definition.data} initialSearch={initialSearch}/>;
  if (reportKey === "ad.infrastructure" && definition.data.views.some((view) => view.key === "controls")) {
    return <AdStateReport definition={definition.data} initialSearch={initialSearch}/>;
  }
  return isFileAuditReport(reportKey) ? <FileAuditReport key={reportKey} definition={definition.data}/> : <ReportBody key={reportKey} definition={definition.data} initialSearch={initialSearch} {...tabs}/>;
}

function ReportBody({ definition: sourceDefinition, initialSearch, additionalTabs = [], onAdditionalTab }: { definition: ReportDefinitionDto; initialSearch?: string } & AdditionalTabs) {
  const definition = useMemo(() => {
    if (sourceDefinition.key === "ad.gpo.v2") return gpoReportDefinition(sourceDefinition);
    if (sourceDefinition.key === "ad.computers.v6") return { ...sourceDefinition,
      params: sourceDefinition.params.map((param) => param.key === "domain" ? { ...param, hidden: false } : param) };
    if (sourceDefinition.key !== "security.problems") return sourceDefinition;
    return {
      ...sourceDefinition,
      params: sourceDefinition.params.map((param) => param.key === "status" && param.options
        ? { ...param, options: param.options.filter(({ value }) => queueStatus(value) === value).map(({ value }) => ({ value, label: statusLabel(value) })) }
        : param),
      columns: sourceDefinition.columns.map((column) => column.key === "status" && column.labels
        ? { ...column, labels: Object.fromEntries(Object.keys(column.labels).map((value) => [value, statusLabel(queueStatus(value))])) }
        : column),
    };
  }, [sourceDefinition]);
  const { formatCell, formatDateTime } = useDateFormatters();
  const { timeZone } = useTimeZone();
  const access = useEffectiveAccess();
  const independentUsers = definition.key === "ad.users.v2";
  const computerReport = definition.key === "ad.computers.v6";
  const computerLogons = definition.key === "ad.computer-logons";
  const computersScreen = computerReport || computerLogons;
  const [computerPageSize, setComputerPageSize] = useState(50);
  const [columnsTarget, setColumnsTarget] = useState<HTMLDivElement | null>(null);
  const [compact, setCompact] = useState(true);
  const [detailsVisible, setDetailsVisible] = useState(true);
  const [refreshWindow, setRefreshWindow] = useState(0);
  const gpoReport = definition.key === "ad.gpo.v2";
  const infrastructure = definition.key === "ad.infrastructure";
  const problemQueue = definition.key === "security.problems";
  const canManageProblems = problemQueue && Boolean(access?.capabilities.includes("investigations.manage"));
  const domainEvents = definition.key === "security.events.chains";
  const [values, setValues] = useState<FilterValues>(() => {
    const search = new URLSearchParams(initialSearch ?? window.location.search);
    const initial = valuesFromSearch(definition, search);
    if (problemQueue && typeof initial.status === "string") initial.status = queueStatus(initial.status);
    if (independentUsers && ["active", "disabled"].includes(search.get("tab") ?? "")) initial.account_state = search.get("tab") === "disabled" ? "disabled" : "enabled";
    if (independentUsers && initial.domain_id && !initial.domain) { initial.domain = initial.domain_id; delete initial.domain_id; }
    return initial;
  });
  const [sort, setSort] = useState<SortState | null>(() => {
    const search = new URLSearchParams(initialSearch ?? window.location.search);
    const field = search.get("sort");
    return field ? { field, direction: search.get("direction") === "desc" ? "desc" : "asc" } : null;
  });
  const [selected, setSelected] = useState<Row | null>(null);
  const [userDetailTab, setUserDetailTab] = useState("account");
  const [userPageSize, setUserPageSize] = useState(50);
  const [userDensity, setUserDensity] = useState<"compact" | "comfortable">("compact");
  const [userColumnsTarget, setUserColumnsTarget] = useState<HTMLSpanElement | null>(null);
  const [queuePreset, setQueuePreset] = useState<PeriodPreset>("custom");
  const [originalPeriod, setOriginalPeriod] = useState<string | null>(null);
  const views = useMemo(() => {
    const declared = domainEvents ? definition.views.filter((item) => item.key === "events") : independentUsers ? definition.views.filter((item) => !["users", "temporary_memberships"].includes(item.key)) : definition.views;
    return declared.length ? declared : [{ kind: "table" as const, key: "table", source: "items" }];
  }, [definition.views, independentUsers, domainEvents]);
  const [activeView, setActiveView] = useState(() => {
    const search = new URLSearchParams(initialSearch ?? window.location.search);
    let requested = search.get("tab");
    if (independentUsers && requested === "users") requested = "all";
    if (independentUsers && views.some((item) => item.key === "checks")) requested = requested === "active" || requested === "disabled" ? "all" : requested === "risk" || requested === "semantic" ? "checks" : requested;
    if (computerReport && !requested && search.has("view")) return search.get("view") === "changes" ? "changes" : "computers";
    return views.some((view) => view.key === requested) ? requested! : computerReport ? "computers" : views[0].key;
  });
  const view = views.find((item) => item.key === activeView) ?? views[0];
  const canLinkReport = (key: string) => !access || access.reports.some((report) => report.allowed
    && (report.report_key === key || report.target_path === `/app/report/${key}`));
  const selectUser = (row: Row, tab = view.key === "changes" ? "changes" : "account") => {
    setSelected(row);
    setUserDetailTab(tab);
  };
  const infrastructureChanges = infrastructure ? views.filter((item) => ["changes", "privileged_changes"].includes(item.key)) : [];
  const infrastructureChange = infrastructureChanges.some((item) => item.key === view.key);
  const displayedViews = infrastructureChanges.some((item) => item.key === "changes")
    ? views.filter((item) => item.key !== "privileged_changes") : views;
  const tabFilters = useRef<Record<string, { values: FilterValues; sort: SortState | null }>>({});
  useEffect(() => { tabFilters.current[activeView] = { values, sort }; }, [activeView, values, sort]);
  const selectView = (key: string) => {
    if (key === activeView) return;
    if (independentUsers || computerReport) {
      const saved = tabFilters.current[key] ?? { values: defaultValues(definition), sort: null };
      const next: FilterValues = { ...saved.values, domain: values.domain, domain_id: values.domain_id, scope: values.scope };
      if (independentUsers) next.q = values.q;
      const search = searchFromValues(definition, next, saved.sort);
      search.set("tab", key);
      window.history.pushState(window.history.state, "", `${window.location.pathname}?${search.toString()}`);
      setValues(next);
      setSort(saved.sort);
    }
    setSelected(null);
    setActiveView(key);
  };
  useEffect(() => {
    if (!independentUsers && !computerReport) return;
    const restore = () => {
      const search = new URLSearchParams(window.location.search);
      const tab = independentUsers && search.get("tab") === "users" ? "all" : search.get("tab");
      setActiveView(views.some((item) => item.key === tab) ? tab! : computerReport ? "computers" : views[0].key);
      setValues(valuesFromSearch(definition, search));
      setSort(search.get("sort") ? { field: search.get("sort")!, direction: search.get("direction") === "desc" ? "desc" : "asc" } : null);
      setSelected(null);
    };
    window.addEventListener("popstate", restore);
    return () => window.removeEventListener("popstate", restore);
  }, [definition, independentUsers, computerReport, views]);
  const mainView = views.find((item) => item.kind === "table" && (item.source ?? "items") === "items") ?? views[0];
  const selectPreset = (preset: Record<string, string>) => {
    setValues((current) => applyPreset(definition, current, preset));
    setActiveView(mainView.key);
  };
  const resetValues = defaultValues(definition);
  resetValues.scope = values.scope;
  for (const param of definition.params) {
    if (param.kind === "period" || param.kind === "domain") resetValues[param.key] = values[param.key];
  }
  if (independentUsers || computerReport) {
    resetValues.domain = values.domain;
    resetValues.domain_id = values.domain_id;
  }
  if (problemQueue) {
    resetValues.time_from = values.time_from;
    resetValues.time_to = values.time_to;
  }
  const viewDenied = view.access?.allowed === false;
  const ready = valuesReady(definition, values, activeView);

  useEffect(() => {
    const search = searchFromValues(definition, values, sort);
    if (independentUsers || computerReport || activeView !== views[0].key) search.set("tab", activeView);
    replaceUrl(search);
  }, [definition, values, sort, activeView, views, independentUsers, computerReport]);

  const collectionTab = independentUsers || (view.source ?? "items") !== "items" || view.key !== views[0].key ? view.key : null;
  // Keep the VPN preset's exact window across tabs, pagination and exports.
  const vpnPeriod = useMemo(() => {
    const period = values.period as PeriodValue | undefined;
    return definition.key === "vpn.connections" && period && ["24h", "7d", "30d", "90d"].includes(period.preset) ? periodBounds(period) : null;
  }, [definition.key, values.period]);
  const computerPeriod = useMemo(() => {
    const period = values.period as PeriodValue | undefined;
    return computerLogons && period && period.preset !== "custom" ? periodBounds(period) : null;
  }, [computerLogons, values.period, refreshWindow]);
  const inventoryLogonWindow = useMemo(() => periodBounds({ preset: "30d" }), [refreshWindow]);
  const baseParams = useMemo(() => {
    const params = apiParams(definition, values, { sort, timeZone, view: activeView, ...(computersScreen || independentUsers || domainEvents ? { limit: computersScreen ? computerPageSize : independentUsers ? userPageSize : 50 } : {}) });
    if (independentUsers) {
      params.delete("check");
      if (activeView !== "privileged") params.delete("as_of");
    }
    if (vpnPeriod) {
      params.set("period", "custom");
      params.set("from", vpnPeriod.from);
      params.set("to", vpnPeriod.to);
    }
    if (computerPeriod) {
      params.set("period", "custom");
      params.set("from", computerPeriod.from);
      params.set("to", computerPeriod.to);
    }
    if (collectionTab) params.set("tab", collectionTab);
    return params.toString();
  }, [definition, values, sort, timeZone, collectionTab, vpnPeriod, activeView, independentUsers, domainEvents, userPageSize, computerPeriod, computersScreen, computerPageSize]);
  const data = useInfiniteQuery({
    queryKey: ["report-v2", "data", definition.key, baseParams],
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams(baseParams);
      if (pageParam) params.set("cursor", pageParam);
      return api.reportV2Data(definition.key, params);
    },
    initialPageParam: null as string | null,
    getNextPageParam: (page: ReportResultDto) => (page.has_more ? page.next_cursor : null),
    enabled: ready && !viewDenied,
    retry: false,
    // On refetch (new filters/sort) keep the previous result visible with a
    // busy indicator instead of blanking to a skeleton.
    placeholderData: independentUsers || computersScreen ? undefined : keepPreviousData,
    // Report queries are heavy and an infinite query refetches every loaded
    // page: do not repeat them on each window focus; a minute is fresh enough
    // (filters, paging and retries still request explicitly).
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });

  const selectedId = String(selected?.id ?? "");
  const hasProblemDescription = selected !== null && ["what_happened", "why_text", "next_text"].some((key) => Object.hasOwn(selected, key));
  const problemDetails = useQuery({
    queryKey: ["report-v2", "data", definition.key, "finding", selectedId, baseParams],
    queryFn: async () => {
      const params = new URLSearchParams(baseParams);
      params.set("id", selectedId);
      params.set("limit", "1");
      return (await api.reportV2Data(definition.key, params)).items.find((item) => String(item.id) === selectedId) ?? null;
    },
    enabled: problemQueue && Boolean(selectedId) && !hasProblemDescription && !viewDenied,
    retry: false,
  });
  const problemDetailsReady = hasProblemDescription || Boolean(problemDetails.data);
  const selectedFacts = selected && problemQueue && problemDetails.data ? { ...selected, ...problemDetails.data } : selected;

  const [userPaging, setUserPaging] = useState({ params: "", index: 0 });
  const userPage = userPaging.params === baseParams ? userPaging.index : 0;

  const first = data.data?.pages[0];
  const coverageDomain = new URLSearchParams(baseParams).get("domain");
  const passwordCoverage = useQuery({
    queryKey: ["report-v2", "problem-password-coverage", coverageDomain],
    queryFn: ({ signal }) => api.problemPasswordCoverage(new URLSearchParams(coverageDomain ? { domain: coverageDomain } : {}), signal),
    enabled: problemQueue && ready && !viewDenied && !data.error && !data.isPlaceholderData
      && (first?.state === "ok" || first?.state === "empty" || first?.state === "partial" || first?.state === "stale"),
    retry: false,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });
  const viewBranches = definition.key === "vpn.connections" && first?.branches ? Object.fromEntries(views.map((item) => [
    item.key, first.branches![vpnViewBranchKey(item.key)],
  ])) : undefined;
  const branch = viewBranches?.[view.key];
  const branchDetail = branch?.limitations.map((item) => item.text).join(" ") || undefined;
  const rows = useMemo(() => {
    const page = data.data?.pages[userPage];
    const items = independentUsers
      ? ((view.source !== "items" && view.source ? page?.collections?.[view.source] : undefined) ?? page?.items ?? []) as Row[]
      : computersScreen ? (page?.items ?? []) as Row[]
      : data.data?.pages.flatMap((item) => item.items as Row[]) ?? [];
    if (!infrastructure || view.key !== "controls") return items;
    return items.filter((row) => ["passed", "failed"].includes(String(row.qualification))
      || (row.actual_text != null && String(row.actual_text).trim() !== "" && row.actual_text !== "—"));
  }, [data.data, independentUsers, infrastructure, view.key, view.source, userPage, computersScreen]);
  const rowKey = (row: Row) => String(row[computerReport && view.key === "changes" ? "row_id" : definition.row_key] ?? JSON.stringify(row));
  const activeComputer = computersScreen && detailsVisible ? (selected && rows.find((row) => rowKey(row) === rowKey(selected)))
    || (view.key === "checks" ? selected : rows[0]) : undefined;
  const chooseComputer = (row: Row) => { setDetailsVisible(true); setSelected(row); };
  const compareView = views.find((item) => item.key === "changes" && item.access?.allowed !== false);
  const cardLogonParams = new URLSearchParams(inventoryLogonWindow ? { period: "custom", from: inventoryLogonWindow.from,
    to: inventoryLogonWindow.to, tz: timeZone } : { period: "30d", tz: timeZone });
  if (activeComputer?.domain_id) cardLogonParams.set("domain_id", String(activeComputer.domain_id));
  const [openedDeepLink, setOpenedDeepLink] = useState(false);
  useEffect(() => {
    // Select only an exact row returned by the access-filtered server query.
    const id = definition.key === "security.problems" ? values.id
      : definition.key === "ad.infrastructure" ? values.row_id : undefined;
    if (!id || openedDeepLink || data.isPlaceholderData || first?.state === "denied" || first?.state === "error") return;
    const row = rows.find((item) => String(item[definition.row_key]) === String(id));
    if (row && definition.detail !== "none") { setSelected(row); setOpenedDeepLink(true); }
  }, [definition, values, rows, first?.state, data.isPlaceholderData, openedDeepLink]);
  const liveOptions = first?.filter_options;
  const fields = useMemo(() => filterFields(independentUsers
    ? { ...definition, params: definition.params.map((param) => param.key === "domain" ? { ...param, hidden: false } : param) }
    : definition, liveOptions, activeView).filter((field) =>
    independentUsers ? (["domain", "q"].includes(field.key)
      || ["account_state", "department", "ou"].includes(field.key) && (view.key === "all" || view.key === "privileged"))
      : !computerReport || (field.key === "domain" || field.key === "domain_id" || field.key === "q" && view.key !== "checks"
        || view.key === "computers" && ["type", "enabled", "activity"].includes(field.key))).map((field) => {
      if (independentUsers && field.key === "q" && field.kind === "text") return { ...field,
        placeholder: t(view.key === "all" || view.key === "privileged" ? "reports.ad.users.list.search" : "reports.ad.users.list.search_account") };
      if (computerLogons && field.key === "with_logons") return { key: field.key, kind: "checkbox" as const, label: t("reports.computers.only_logons"), onValue: "yes", offValue: "no" };
      if (computersScreen && field.kind === "text" && ["q", "user"].includes(field.key)) {
        const label = field.key === "user" ? t("reports.computers.user") : computerLogons ? t("reports.computers.computer") : t("reports.computers.search");
        return { ...field, label, placeholder: label };
      }
      if (computerReport && field.kind === "select" && ["type", "enabled", "activity"].includes(field.key)) {
        const counts = liveOptions?.[field.key];
        return { ...field, options: field.options.map((option) => ({ ...option,
          label: ["missing", "unknown"].includes(option.value) ? t("table.noValue") : option.label,
          count: counts ? counts.find((bucket) => bucket.value === option.value)?.count ?? (first?.state === "ok" ? 0 : undefined) : undefined })) };
      }
      return field;
    }), [definition, liveOptions, activeView, computerReport, computerLogons, computersScreen, independentUsers, view.key, first?.state]);
  const headerPeriodField = fields.find((field) => field.kind === "period");
  const hasDepartment = !independentUsers || !!values.department || !!liveOptions?.department?.length || rows.some((row) => Boolean(row.department));
  const bodyFields = fields.filter((field) => (computersScreen || field !== headerPeriodField) && (field.key !== "department" || hasDepartment))
    .map((field) => independentUsers && field.kind === "select" ? { ...field, immediate: true } : field);
  const declaredColumns = useMemo(() => workstationColumns(definition.key, tableColumns(definition.columns.filter((column) =>
      (!problemQueue || !["actor_identifier", "entity_identifiers", "identity_sources", ...problemDescriptionColumns].includes(column.key))
      && !(domainEvents && ["change", "actor", "group"].includes(column.key) && rows.length > 0
        && rows.every((row) => {
          const value = columnValue(column, row);
          return value == null || typeof value === "string" && ["", "-", "—"].includes(value.trim());
        }))), timeZone), rows).map((column) =>
      definition.key === "security.problems" && column.key === "title"
        ? { ...column, minWidth: "var(--sli-field-max-width)" } : column), [definition, view.key, timeZone, rows]);

  const columns = canManageProblems ? declaredColumns.map((column) =>
    column.key === "status" ? { ...column, render: (row: Row) => <>
      {statusLabel(queueStatus(String(row.status ?? "")))}
      {canResolveProblem(row) ? <> <ResolveProblem row={row} compact/></> : null}
    </> } : column) : declaredColumns;

  let state: ResultState = "ok";
  let stateDetail: string | undefined;
  if (viewDenied) { state = "denied"; stateDetail = accessReason(view.access); }
  else if (!ready) { state = "empty"; stateDetail = t("reports.renderer.required_conditions"); }
  else if (data.isLoading) state = "loading";
  else if (data.error) {
    ({ state, detail: stateDetail } = errorState(data.error));
    if (definition.key === "vpn.connections" && data.error instanceof ApiResponseError
      && data.error.code === "report_read_timeout" && state !== "denied") {
      stateDetail = t("reports.v2.vpn.connections.limitations.source_read_timeout");
    }
  }
  else if (first) {
    state = first.state;
    if (state === "error" || state === "not_collected") stateDetail = first.limitations.map((item) => item.text).join(" ") || undefined;
    if (state === "denied") stateDetail = accessReason(first.access);
    if (state === "empty") stateDetail = definition.key === "workstations.usb" ? t("workstations.usb.empty") : reportEmptyText(view, definition.title);
    if (definition.key === "workstations.usb" && state === "not_collected") stateDetail = t("workstations.usb.not_collected");
    if (branchDetail && (state === "error" || state === "denied" || branch?.state === "partial")) stateDetail = branchDetail;
  }

  const vpnTimeoutRetry = definition.key === "vpn.connections" && state === "partial"
    && Object.values(first?.branches ?? {}).some((source) => source.reason === "source_read_timeout")
    ? <button type="button" className="sli-ds-button" disabled={data.isFetching}
        onClick={() => void data.refetch()}>{t("state.retry")}</button> : undefined;

  if (problemQueue && (state === "ok" || state === "empty") && !data.isPlaceholderData
    && (passwordCoverage.data?.state === "partial" || passwordCoverage.isError)) state = "partial";

  const window_ = first?.window;
  const sourceReason = first?.coverage.reason;
  const workstationFailure = definition.section === "reports/workstations" && state === "error" && !data.error
    && typeof sourceReason === "string" && Object.hasOwn(WORKSTATION_SOURCE_REASONS, sourceReason)
    ? t(WORKSTATION_SOURCE_REASONS[sourceReason as keyof typeof WORKSTATION_SOURCE_REASONS]) : null;
  const hiddenCategories = first?.access?.hidden_categories ?? definition.access?.hidden_categories ?? [];
  const inventorySnapshot = definition.key === "ad.gpo.v2" && view.key !== "changes";
  const snapshotAt = !data.isPlaceholderData ? first?.coverage.observed_at_utc : undefined;
  const userSnapshot = independentUsers && Boolean(values.domain ?? values.domain_id) && typeof snapshotAt === "string" && Number.isFinite(Date.parse(snapshotAt))
    ? t("reports.ad.users.list.snapshot", { time: formatDateTime(snapshotAt), zone: formatClockWithOffset(new Date(snapshotAt), timeZone).zone }) : undefined;
  const periodMeta = inventorySnapshot
    ? typeof snapshotAt === "string" && snapshotAt ? t("reports.renderer.snapshot_at", { time: formatDateTime(snapshotAt) }) : null
    : window_?.from_utc ? t("reports.renderer.period_range", { from: formatDateTime(window_.from_utc), to: formatDateTime(window_.to_utc_exclusive ?? window_.to_utc ?? "") }) : null;
  // A chip that repeats a clickable metric is the same action twice: keep the metric.
  const presets = gpoReport ? definition.presets : visiblePresets(definition, values, problemQueue ? [] : (first?.metrics ?? []).flatMap((metric) => metric.filter ? [metric.filter] : []));
  const exportsByTab = independentUsers || computerReport || definition.key === "ad.infrastructure" || definition.key === "ad.gpo.v2";
  const exportParams = new URLSearchParams(baseParams);
  exportParams.delete("limit");
  if (exportsByTab) exportParams.set("tab", view.key);
  else exportParams.delete("tab");
  const exportHref = definition.export && ready && !viewDenied ? `/api/v2/reports/${encodeURIComponent(definition.key)}/export.csv?${exportParams.toString()}` : null;
  const exportsSelectedView = view === mainView || exportsByTab;
  const PageAction = definition.page_actions ? PAGE_ACTIONS[definition.page_actions] : undefined;
  const defaultSort: SortState | null = computerLogons ? { field: "name", direction: "asc" }
    : computerReport && view.key === "computers" ? { field: "display_name", direction: "asc" } : null;
  const activeSort = sort ?? defaultSort;
  const toggleSort = (field: string) => setSort({ field, direction: activeSort?.field === field && activeSort.direction === "asc" ? "desc" : "asc" });
  const pagination = (size: number) => ({
    start: userPage * size + 1,
    end: userPage * size + rows.length,
    busy: data.isFetchingNextPage,
    onPrevious: userPage > 0 ? () => { setSelected(null); setUserPaging({ params: baseParams, index: userPage - 1 }); } : undefined,
    onNext: data.data?.pages[userPage]?.has_more ? () => { setSelected(null); void (async () => {
      if (!data.data?.pages[userPage + 1]) { const next = await data.fetchNextPage(); if (next.isError) return; }
      setUserPaging({ params: baseParams, index: userPage + 1 });
    })(); } : undefined,
  });
  const userTablePaging = { pagination: pagination(userPageSize), density: userDensity, total: first?.filtered_count,
    pageSize: { value: userPageSize, options: [25, 50, 100, 200], onChange: (size: number) => {
      setSelected(null); setUserPaging({ params: "", index: 0 }); setUserPageSize(size);
    } } };
  const periodParam = definition.params.find((param) => param.kind === "period");
  const recovery = ready && !data.isPlaceholderData && !data.isFetching && !data.error && state !== "denied" ? reportEmptyRecovery(first, timeZone, periodParam ? values[periodParam.key] as PeriodValue : undefined) : null;
  const showLatest = periodParam && recovery?.period ? () => {
    setOriginalPeriod((current) => current ?? recovery.originalPeriod);
    setSelected(null);
    setValues((current) => ({ ...current, [periodParam.key]: recovery.period! }));
  } : undefined;
  const gpoEmpty = <p role="status">{t("reports.ad.gpo.empty")}</p>;
  const emptyDetail = <EmptyRecoveryDetail recovery={recovery}/>;
  const emptyActions = recovery ? <EmptyRecoveryActions recovery={recovery} onShowLatest={showLatest}/> : undefined;
  // A previous filter result or another VPN source lane cannot certify this header.
  const qualityResult = ready && !viewDenied && state !== "denied" && state !== "unavailable" && state !== "error" && state !== "not_collected"
    && branch?.state !== "denied" && branch?.state !== "error" && branch?.state !== "not_collected" && branch?.state !== "not_requested"
    && !data.error && !data.isPlaceholderData ? first : undefined;
  const qualityCoverage = definition.key === "vpn.connections" && vpnViewBranchKey(view.key) !== "accounting"
    ? undefined : qualityResult?.coverage;
  const qualityState: ResultState = qualityResult ? branch?.state === "not_requested" ? "loading" : branch?.state ?? state : "loading";

  const description = definition.description && definition.description !== definition.title ? definition.description : undefined;
  const archiveContext = qualityResult?.domains?.some((domain) => domain.is_archived)
    ? <ArchiveDomainNotice domains={qualityResult.domains} coverage={qualityResult.coverage} timeZone={timeZone} detail/> : null;
  const reportDetails = problemQueue || gpoReport || infrastructure || domainEvents || computersScreen ? null : !independentUsers && definition.intent
    ? <ReportPassportMeta intent={definition.intent} coverage={qualityCoverage} state={qualityState} timeZone={timeZone} description={description}>{archiveContext}</ReportPassportMeta>
    : independentUsers ? null
      : <>{first?.coverage?.completeness === "not_proven" ? <span className="sli-ds-badge" data-tone="warning">{t("reports.renderer.completeness_not_proven")}</span> : null}{description || archiveContext ? <details><summary>{t("reports.passport.more")}</summary>{description ? <p>{description}</p> : null}{archiveContext}</details> : null}</>;

  const domainEventsEmpty = state === "ok" || state === "empty" ? <p role="status">{t("reports.domain_events.empty")}</p> : null;
  const eventListFailure = domainEvents && (state === "error" || state === "unavailable");
  const windowEnd = window_?.to_utc_exclusive ?? window_?.to_utc;
  const bounds = window_?.from_utc && windowEnd && !data.isPlaceholderData ? { from: window_.from_utc, to: windowEnd } : undefined;
  const queueBounds = typeof values.time_from === "string" && typeof values.time_to === "string" ? { from: values.time_from, to: values.time_to } : undefined;
  const changeQueuePeriod = (value?: PeriodValue) => {
    const window = value ? queueWindow(value, timeZone) : null;
    if (value && !window) return;
    setQueuePreset(value?.preset ?? "custom");
    setSelected(null);
    setValues((current) => ({ ...current, time_from: window?.from, time_to: window?.to }));
  };
  const headerPeriod: PageHeaderControls["period"] = headerPeriodField?.kind === "period" ? {
    value: values[headerPeriodField.key] as PeriodValue | undefined,
    presets: headerPeriodField.presets,
    bounds,
    onChange: (value) => { setSelected(null); setValues((current) => ({ ...current, [headerPeriodField.key]: value })); },
  } : problemQueue ? {
    value: queueBounds ? { preset: queuePreset, ...queueBounds } : undefined,
    bounds: queueBounds,
    onChange: changeQueuePeriod,
    onClear: changeQueuePeriod,
  } : undefined;

  const namedViews = displayedViews.map((item) => {
    const itemBranch = viewBranches?.[item.key];
    const label = computersScreen ? t(computerLogons ? "reports.computers.logons" : item.key === "checks" ? "reports.computers.review"
      : item.key === "changes" ? "reports.computers.changes" : "reports.computers.all") : item.title || item.key;
    const count = independentUsers && item.access?.allowed !== false && first && !data.error
      ? item.key === view.key ? item.key === "checks" ? first.coverage.affected_objects : first.filtered_count
        : view.key === "all" && item.key === "privileged" ? first.coverage.privileged_accounts : undefined : undefined;
    return { key: item.key, label: <>{label}{typeof count === "number" ? <> <span>{count}</span></> : null}{itemBranch ? <> <span className="sli-ds-badge" data-tone={itemBranch.state === "ok" ? "success" : itemBranch.state === "not_requested" || itemBranch.state === "empty" ? "neutral" : "warning"}>{t(`reports.renderer.branch_state.${itemBranch.state}`)}</span></> : null}</> };
  });
  const linkedViews = additionalTabs.map((item) => ({ key: item.key, label: <>{item.label}</> }));
  const listPagination = { ...pagination(computerPageSize),
    label: computersScreen ? typeof first?.filtered_count === "number"
      ? t("reports.computers.page_of", { page: userPage + 1, total: Math.ceil(first.filtered_count / computerPageSize) })
      : t("reports.computers.page", { page: userPage + 1 }) : undefined };
  const computerTable = computerReport ? computerInventoryColumns(definition.columns, timeZone, chooseComputer)
    : columns.filter((column) => column.key !== "state").map((column) => ({ ...column, hiddenByDefault: column.key === "name" ? undefined : false,
      ...(column.key === "count" ? { render: computerLogonCount } : {}) }));
  const computerEmptyView = !computerLogons ? computerEmpty()
    : first && ready && !data.isPlaceholderData && !data.error
      ? <ComputerLogonsEmpty state={first.coverage.observation_state ?? state}/> : null;
  const logonsNotCollected = computerLogons && state === "not_collected" && !data.isPlaceholderData;
  const scopeInstant = computerLogons ? bounds?.to : typeof snapshotAt === "string" ? snapshotAt : undefined;
  const computerScope = computersScreen && scopeInstant ? <span className="sli-ds-badge">
    {first?.domains?.length === 1 && !bodyFields.some((field) => field.key === "domain") ? <>{first.domains[0].display_name} · </> : null}
    {computerLogons && bounds ? t("reports.renderer.period_range", { from: formatDateTime(bounds.from), to: formatDateTime(bounds.to) })
      : t("reports.renderer.snapshot_at", { time: formatDateTime(scopeInstant) })}
    {isValidTimeZone(timeZone) && Number.isFinite(Date.parse(scopeInstant))
      ? ` · ${formatClockWithOffset(new Date(scopeInstant), timeZone).zone}` : null}
  </span> : undefined;
  return <ResultWindowContext.Provider value={first?.window}><Tabs items={computerLogons ? [...linkedViews, ...namedViews] : [...namedViews, ...linkedViews]} active={infrastructureChange && displayedViews.some((item) => item.key === "changes") ? "changes" : view.key} onChange={(key) => {
    if (additionalTabs.some((item) => item.key === key)) onAdditionalTab?.(key);
    else selectView(key);
  }}><ReportLayout
    title={definition.title}
    domain={String(values.domain ?? values.domain_id ?? "") || undefined} showDomain={!independentUsers}
    controls={state === "denied" ? undefined : {
      period: computersScreen ? undefined : headerPeriod,
      updatedAt: !independentUsers && qualityResult && !computersScreen ? qualityResult.window.generated_at_utc ?? data.dataUpdatedAt : undefined,
      refreshing: data.isFetching,
      showRefreshLabel: computersScreen || independentUsers,
      showBreadcrumbs: computersScreen,
      onRefresh: ready ? () => {
        if (computersScreen) setRefreshWindow((value) => value + 1);
        if (!computerPeriod) void data.refetch({ cancelRefetch: false });
        if (passwordCoverage.isEnabled) void passwordCoverage.refetch({ cancelRefetch: false });
      } : undefined,
    }}
    crumbs={computerLogons
      ? [{ label: t("shell.nav.computers-report"), href: "/app/report/ad.computers.v6" }, { label: t("reports.computers.logons_tab") }]
      : computerReport ? [{ label: t("reports.computers.directory") }, { label: definition.title }]
      : independentUsers ? [
      { label: t("shell.section.active-directory"), href: canLinkReport("ad.infrastructure") ? "/app/report/ad.infrastructure" : undefined },
      { label: definition.title },
    ] : [{ label: getSectionCrumb(definition.section) }]}
    meta={infrastructure || computersScreen ? undefined : independentUsers || domainEvents ? null : <>{definition.default_domain_state && definition.default_domain_state !== "available" && !values.domain && !values.domain_id && values.scope !== "all" ? <span role="status">{t("domain.archive.noDefault")}</span> : null}{hiddenCategories.length ? <span role="status">{t("reports.access.hidden_columns", { categories: categoryNames(hiddenCategories) })}</span> : null}{periodMeta ? <span>{periodMeta}</span> : null}{originalPeriod ? <span>{originalPeriod}</span> : null}{periodMeta && definition.key === "vpn.connections" && !first?.window.nps_period_clamped ? <span>{t("reports.v2.vpn.connections.period_note")}</span> : null}{reportDetails}</>}
    actions={<>
      {PageAction && state !== "denied" && !(first?.plugin ?? definition.plugin)?.read_only ? <PageAction rows={rows as Record<string, unknown>[]} result={first}/> : null}
      {exportHref ? <a className="sli-ds-button" href={exportHref} download>{exportsSelectedView ? t("reports.renderer.export_csv") : t("reports.renderer.export_csv_all", { view: mainView.title ?? mainView.key })}</a> : null}
    </>}
    metrics={!problemQueue && !gpoReport && !infrastructure && !domainEvents && !independentUsers && !computersScreen && state !== "denied" && state !== "error" && state !== "not_collected" && first?.metrics.length ? <MetricStrip compact items={first.metrics.map((metric) => ({
      key: metric.key, label: metric.label,
      value: metric.quality === "unknown" ? t("reports.metrics.no_data") : metric.value,
      tone: metric.quality && metric.quality !== "complete" ? "warning" : metric.tone,
      caption: metric.quality === "observed" ? t("reports.metrics.observed", { count: metric.value ?? "" }) : metric.caption,
      onSelect: metric.filter ? () => selectPreset(metric.filter!) : undefined,
      active: metric.filter ? isPresetActive(definition, values, metric.filter) : undefined,
    }))}/> : null}
    filters={<>
      {independentUsers && view.key === "privileged" ? <label className="sli-ds-field">{t("reports.ad.users.as_of")}<input type="date" value={String(values.as_of ?? "")} onChange={(event) => { setSelected(null); setValues((current) => ({ ...current, as_of: event.target.value })); }}/></label> : null}
      {!gpoReport && !infrastructure && !domainEvents && !independentUsers && !computersScreen && presets.length ? <div className="sli-ds-header__meta" role="group" aria-label={t("reports.renderer.quick_scenarios")}>
        {presets.map((preset) => <button key={preset.label} type="button" className="sli-ds-chip" aria-pressed={isPresetActive(definition, values, preset.params)} onClick={() => selectPreset(preset.params)}>{preset.label}</button>)}
      </div> : null}
      {bodyFields.length ? <FilterBar fields={bodyFields} layout={independentUsers || computersScreen ? "inline" : undefined}
        primaryKeys={computersScreen ? undefined : gpoReport || infrastructure ? ["q", "period"] : independentUsers ? bodyFields.map((field) => field.key) : fields.length > 4 ? primaryFilterKeys(definition) : undefined}
        applyInline={computersScreen} leadingControls={computerScope ?? (userSnapshot ? <span className="sli-ds-chip">{userSnapshot}</span> : undefined)}
        values={values} defaults={resetValues} onApply={(next) => {
          setSelected(null);
          const domainChanged = next.domain !== values.domain;
          if (independentUsers || (computerReport && domainChanged)) {
            const current: FilterValues = { ...next, domain_id: domainChanged ? undefined : next.domain_id };
            setValues({ ...current, scope: current.domain || current.domain_id ? undefined : "all" });
          } else setValues(next);
        }}
        quickFilters={infrastructureChange && infrastructureChanges.length > 1 ? <label className="sli-ds-field">{t("reports.v2.ad.infrastructure.views.changes.title")}
          <select value={view.key} onChange={(event) => selectView(event.target.value)}>
            {infrastructureChanges.map((item) => <option key={item.key} value={item.key}>{item.title}</option>)}
          </select>
        </label> : domainEvents && presets.length ? <div className="sli-ds-header__meta" role="group" aria-label={t("reports.renderer.quick_scenarios")}>
          {presets.map((preset) => <button key={preset.label} type="button" className="sli-ds-chip" aria-pressed={isPresetActive(definition, values, preset.params)} onClick={() => selectPreset(preset.params)}>{preset.label}</button>)}
        </div> : gpoReport && view === mainView ? <div role="group" aria-label={t("reports.renderer.quick_scenarios")} className="sli-ds-header__actions">
        {presets.map((preset) => {
          const count = !data.isPlaceholderData ? first?.metrics.find((metric) => metric.filter?.view === preset.params.view)?.value : undefined;
          return <button key={preset.params.view} type="button" className="sli-ds-chip" aria-pressed={isPresetActive(definition, values, preset.params)} onClick={() => selectPreset(preset.params)}>{preset.label}{typeof count === "number" && count > 0 ? ` ${count}` : ""}</button>;
        })}
      </div> : undefined}/> : null}
    </>}
    tabs={computersScreen ? <div className="sli-ds-header__row">
      {views.length + linkedViews.length > 1 ? <TabList label={t("reports.views.tabs_aria")}/> : null}
      <div className="sli-ds-header__actions">
        <button type="button" className="sli-ds-chip" aria-pressed={compact} onClick={() => setCompact((value) => !value)}>{t("reports.computers.compact")}</button>
        <div ref={setColumnsTarget}/>
        <button type="button" className="sli-ds-chip" aria-pressed={detailsVisible} onClick={() => setDetailsVisible((value) => !value)}>{t("reports.computers.toggle_details")}</button>
      </div>
    </div> : independentUsers ? <div className="sli-ds-report__toolbar">
      <ViewTabs views={displayedViews}/>
      <div className="sli-ds-header__actions">
        <select aria-label={t("reports.ad.users.list.density")} value={userDensity} onChange={(event) => setUserDensity(event.target.value === "comfortable" ? "comfortable" : "compact")}>
          <option value="compact">{t("reports.ad.users.list.compact")}</option>
          <option value="comfortable">{t("reports.ad.users.list.comfortable")}</option>
        </select>
        <span ref={setUserColumnsTarget}/>
        <button type="button" className="sli-ds-button" aria-pressed={!!selected} disabled={!selected && (view.key === "checks" || !rows.length)} onClick={() => selected ? setSelected(null) : selectUser(rows[0])}>{t("reports.ad.users.list.details")}</button>
      </div>
    </div> : <ViewTabs views={displayedViews}/>}
    tabbed={views.length + (computersScreen ? linkedViews.length : 0) > 1}
    // A custom view loads its own data: an empty main table is not its state.
    state={state === "denied" || ((view.kind === "custom" || (view.source ?? "items") !== "items") && state === "empty" && ready) ? "ok" : state === "not_collected" ? "partial" : state}
    stateMessage={first?.state === state ? first.state_message : undefined}
    stateDetail={state === "empty" ? <>{stateDetail}{emptyDetail}</> : stateDetail}
    stateActions={state === "empty" ? emptyActions : vpnTimeoutRetry}
    stateView={independentUsers && (state === "error" || state === "unavailable") ? <div role="alert">{t("reports.ad.users.list.load_error")} <button type="button" className="sli-ds-button" onClick={() => void data.refetch()}>{t("state.retry")}</button></div>
      : independentUsers && state === "empty" ? <p>{t("table.noValue")}</p>
      : eventListFailure ? <EventListError reportKey={definition.key} onRetry={() => void data.refetch()}/>
      : domainEvents && state === "empty" ? domainEventsEmpty
      : computersScreen && state === "empty" ? computerEmptyView
      : (domainEvents || problemQueue || infrastructure || computersScreen || independentUsers) && ["partial", "stale", "processing", "not_collected"].includes(state) ? <></>
      : gpoReport && state === "empty" ? gpoEmpty : gpoReport && ["partial", "stale", "processing", "not_collected"].includes(state) ? <></> : <>{definition.key === "workstations.usb" && state === "not_collected" ? <p role="status">{t("workstations.usb.not_collected")} <a href="/app/agents">{t("agents.title")}</a></p> : null}{workstationFailure ? <p role="status">{workstationFailure}</p> : <ReportState state={state} message={first?.state === state ? first.state_message : undefined} details={{ ...(first?.state_details ?? { reason: "coverage_unknown", observed_at_utc: typeof first?.coverage.observed_at_utc === "string" ? first.coverage.observed_at_utc : null }), limitations: first?.limitations }}
      subject={view.title || definition.title} canDiagnose={access?.capabilities.includes("operations.view") ?? false}
      detail={state === "empty" ? <>{stateDetail}{emptyDetail}</> : definition.key === "workstations.usb" && state === "not_collected" ? undefined : stateDetail} actions={state === "empty" ? emptyActions : vpnTimeoutRetry}
      onRetry={() => void data.refetch()} compact={state === "partial" || state === "stale" || state === "processing"}/>}{vpnTimeoutRetry}</>}
    staleAge={first?.coverage?.observed_at_utc ? formatDateTime(String(first.coverage.observed_at_utc)) : undefined}
    onRetry={() => void data.refetch()}
    busy={ready && data.isFetching && !data.isFetchingNextPage && !data.isLoading}
    sideSize={computerLogons ? "wide" : "standard"}
    side={activeComputer && (logonsNotCollected || !["denied", "loading", "error", "unavailable", "not_collected", "empty"].includes(state)) ? <ComputerPanel key={`${rowKey(activeComputer)}:${baseParams}:${refreshWindow}`} row={activeComputer} logons={computerLogons} logonsNotCollected={logonsNotCollected}
      logonParams={computerLogons ? baseParams : cardLogonParams.toString()} changes={compareView?.columns ?? []}
      canCompare={Boolean(compareView)} onClose={() => setDetailsVisible(false)} timeZone={timeZone}/> : undefined}
    split={independentUsers ? "inline" : undefined}
    drawer={computersScreen ? undefined : independentUsers ? selected ? <UserCard key={`${selected.domain_id}:${selected.entity_id ?? selected.id}:${userDetailTab}`} selected={selected} columns={definition.columns} timeZone={timeZone}
      initialTab={userDetailTab} historical={view.key === "privileged" && Boolean(values.as_of)}
      allowJournal={canLinkReport("events.journal")} allowProblems={canLinkReport("security.problems")} onClose={() => setSelected(null)}/> : undefined
      : <DetailDrawer open={selected !== null} title={selected ? problemQueue ? String(selected.title_text ?? selected.title ?? "") : formatCell(columnValue(definition.columns[0], selected), cellKind(definition.columns[0])) : ""} onClose={() => setSelected(null)}
      footer={selected ? <>
        {canManageProblems && canResolveProblem(selected) ? <ResolveProblem key={String(selected.id)} row={selected} onResolved={() => setSelected(null)}/> : null}
        {definition.row_links.map((link) => {
          const href = fillTemplate(link.href, selected);
          return href ? <a key={link.label} className="sli-ds-button" data-variant="primary" href={withReturnTo(href, `${window.location.pathname}${window.location.search}`)}>{link.label}</a> : null;
        })}
        <CopyFactsButton text={rowFactsText(definition.title, definition.columns, selectedFacts ?? selected, timeZone)}/>
      </> : undefined}>
      {selectedFacts && problemQueue && problemDetailsReady ? definition.columns.filter((column) => problemDescriptionColumns.includes(column.key)).map((column) =>
        <p key={column.key}><strong>{column.label}</strong>{": "}{formatCell(columnValue(column, selectedFacts), cellKind(column))}</p>) : null}
      {selected && problemQueue && problemDetails.isError ? <ReportState state="error" subject={definition.title} onRetry={() => void problemDetails.refetch()}/> : null}
      {selectedFacts && !independentUsers ? <FactList facts={definition.columns.filter((column) => !problemQueue || !problemDescriptionColumns.includes(column.key)).map((column) => ({ label: column.label, value: column.component ? <CellComponent name={column.component} row={selectedFacts}/> : formatCell(columnValue(column, selectedFacts), cellKind(column)) }))}/> : null}
      {selectedFacts && !independentUsers && typeof definition.detail === "object" && (!problemQueue || problemDetailsReady) ? <DetailSection definition={definition} detail={definition.detail} row={selectedFacts} baseParams={baseParams}/> : null}
    </DetailDrawer>}
  >
    {!computersScreen && !independentUsers && !domainEvents && ready && !data.isPlaceholderData && !data.isFetching && !data.error && state !== "denied" ? <PairsWindowState result={first} onShowLatest={showLatest}
      onChangeBaseline={() => { setSelected(null); setValues((current) => ({ ...current, baseline_days: "1" })); }}/> : null}
    {state === "denied" ? <ReportDenied reportKey={definition.key} title={definition.title} reason={stateDetail}/>
      : branch && (branch.state === "error" || branch.state === "denied")
      ? <ReportState state={branch.state} details={{ reason: branch.reason, limitations: branch.limitations }}
        detail={branchDetail} subject={view.title || definition.title} canDiagnose={access?.capabilities.includes("operations.view") ?? false} onRetry={() => void data.refetch()}/>
      : independentUsers && view.key === "checks"
      ? <UserChecks key={baseParams} result={first} baseParams={baseParams} onSelect={selectUser}/>
      : independentUsers && ["changes", "disabled_active"].includes(view.key)
      ? <UserChanges columns={view.columns ?? []} rows={rows} title={view.title ?? view.key} onSelect={selectUser} paging={userTablePaging}/>
      : independentUsers
      ? rows.length ? <DataTable key={view.key} caption={view.title ?? definition.title} columns={userTableColumns(definition.columns.filter((column) => column.key !== "department" || hasDepartment), selectUser, timeZone)}
        rows={rows} rowKey={(row) => String(row[definition.row_key])} sort={sort} onSort={toggleSort} onRowClick={selectUser}
        selectedKey={selected ? String(selected[definition.row_key]) : null} columnsControlTarget={userColumnsTarget} wrapCells="all" {...userTablePaging}/> : <p>{t("table.noValue")}</p>
      : computerReport && view.key === "checks"
      ? <ComputerChecks result={first} onSelect={chooseComputer} onInventory={() => selectView("computers")}/>
      : computersScreen
      ? rows.length ? <DataTable key={view.key} caption={view.title ?? definition.title}
        columns={computerReport && view.key === "changes" ? computerTableColumns(view.columns ?? [], chooseComputer, [], timeZone) : computerTable}
        rows={rows} rowKey={rowKey} onRowClick={chooseComputer} total={first?.filtered_count} selectedKey={activeComputer ? rowKey(activeComputer) : null}
        compact={compact} density={compact ? undefined : "comfortable"} wrapCells="all" pagination={listPagination} sort={activeSort}
        onSort={toggleSort} columnsControlTarget={columnsTarget} footerControls={<div className="sli-ds-header__meta" role="group" aria-label={t("reports.computers.rows_per_page")}>
          <span>{t("reports.computers.rows_per_page")}</span>
          {[25, 50, 100, 200].map((size) => <button key={size} type="button" className="sli-ds-chip" aria-pressed={size === computerPageSize}
            onClick={() => { setSelected(null); setComputerPageSize(size); }}>{size}</button>)}
        </div>}/>
        : computerEmptyView
      : gpoReport && view !== mainView
      ? (first?.collections?.[view.source ?? ""]?.length
        ? <DataTable key={view.key} caption={view.title ?? definition.title} columns={tableColumns(view.columns ?? [], timeZone)} rows={first.collections[view.source ?? ""]} rowKey={(row) => JSON.stringify(row)}/>
        : gpoEmpty)
      : view.kind === "custom"
      ? (() => { const Custom = view.component ? VIEW_COMPONENTS[view.component] : undefined; return Custom ? <Custom params={new URLSearchParams(baseParams)} result={first}/> : <ReportState state="error" detail={t("reports.renderer.view_not_registered")}/>; })()
      : (view.source ?? "items") === "items"
      ? (rows.length === 0 && !data.isLoading && !data.error
        ? (domainEvents ? domainEventsEmpty : gpoReport ? state === "not_collected" ? null : gpoEmpty : state !== "error" ? <ReportState state="empty" detail={<>{definition.key === "workstations.usb" ? t(state === "partial" || state === "stale" ? "workstations.usb.empty_unverified" : "workstations.usb.empty") : reportEmptyText(view, definition.title)}{emptyDetail}</>} actions={emptyActions}/> : null)
        : <><DataTable caption={view.title || definition.title} columns={columns} rows={rows} rowKey={(row) => String(row[definition.row_key] ?? JSON.stringify(row))}
          sort={sort} onSort={toggleSort} onRowClick={definition.detail === "none" ? undefined : setSelected}
          selectedKey={selected ? String(selected[definition.row_key]) : null}
          hasMore={Boolean(data.hasNextPage)} loadingMore={data.isFetchingNextPage} onLoadMore={() => void data.fetchNextPage()}
          total={infrastructure && view.key === "controls" ? null : first?.filtered_count ?? null}/></>)
      : <CollectionView view={definition.key === "vpn.connections" && ["policy_denials", "policy_denials_growth", "policy_denials_events"].includes(view.key)
          && first?.window.nps_period_clamped === true && !data.isPlaceholderData
          ? { ...view, note: t("reports.v2.vpn.connections.nps_period_clamped") } : view}
        reportTitle={definition.title} rows={(first?.collections?.[view.source ?? ""] ?? []) as Row[]} emptyDetail={emptyDetail} emptyActions={emptyActions}
        state={branch?.state === "not_requested" ? state : branch?.state ?? state} stateDetails={first?.state_details}/>}
    {!problemQueue && !gpoReport && !infrastructure && !independentUsers && !domainEvents && !computersScreen && first?.limitations.length && state === "ok" ? <details aria-label={t("reports.renderer.limitations_aria")}>
      <summary>{t("reports.renderer.limitations_title")}</summary>
      <ul className="sli-ds-state__text">{first.limitations.map((item) => <li key={item.code + item.text}>{item.text}</li>)}</ul>
    </details> : null}
  </ReportLayout></Tabs></ResultWindowContext.Provider>;
}

