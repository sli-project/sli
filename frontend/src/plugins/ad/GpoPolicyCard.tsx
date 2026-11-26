import { Select } from "../../design-system/Select";
import { useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto } from "../../api/report-v2-types";
import { DataTable, ReportLayout, TabList, TabPanel, Tabs, type TableColumn } from "../../design-system";
import { Icon } from "../../design-system/Icon";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { plural, t, type MessageKey } from "../../i18n";
import { GpoSnapshotComparison } from "./GpoSnapshotComparison";
import { ReportDenied } from "../../app/report-v2/ReportDenied";

const sides = ["computer", "user"] as const;
type Side = typeof sides[number];
type Versions = Partial<Record<`${Side}_${"directory_version" | "sysvol_version"}`, number>> & { observed_at?: string };
export type PolicyRow = Versions & {
  id: string;
  guid?: string;
  gpo_status?: string;
  display_name: string;
  setting_count?: number | null;
  computer_setting_count?: number | null;
  user_setting_count?: number | null;
  link_count?: number | null;
  unlinked?: boolean;
  owner?: string;
  modification_time?: string;
};
type Setting = { id: string; side: Side; setting_name?: string; category?: string; path?: string; value_display?: string };
type LinkRow = { id: string; scope_name?: string; order?: number; enabled?: boolean; enforced?: boolean };
type Permission = { id: string; trustee_name?: string; permission?: string };
type Change = { id: string; object_id: string; object_type: string; field: string; kind: string; name?: string;
  observed_at?: string; before_value?: string | null; after_value?: string | null };
type CardCollections = { settings?: Setting[]; links?: LinkRow[]; permissions?: Permission[]; versions?: Versions[]; changes?: Change[] };
const tabs = ["settings", "links", "rights", "versions", "changes"] as const;
export type PolicyTab = typeof tabs[number];

export function hasMismatch(row: Versions, component?: Side): boolean {
  return (component ? [component] : sides).some((side) => {
    const ad = row[`${side}_directory_version`];
    const sysvol = row[`${side}_sysvol_version`];
    return ad != null && sysvol != null && ad !== sysvol;
  });
}

export function versionPair(row: Versions, side: Side, domain?: string): ReactNode {
  const ad = row[`${side}_directory_version`];
  const sysvol = row[`${side}_sysvol_version`];
  if (ad == null && sysvol == null) return "—";
  const value = `${ad ?? "—"} / ${sysvol ?? "—"}`;
  return hasMismatch(row, side) ? <strong className="sli-ds-value-mismatch">{domain === undefined ? value :
    <a href={`/app/report/ad.infrastructure${domain ? `?${new URLSearchParams({ domain })}` : ""}`}>{value}</a>}</strong> : value;
}

const permissionLabels: Record<string, MessageKey> = {
  GpoRead: "reports.gpo.permission_read", GpoApply: "reports.gpo.permission_apply", GpoEdit: "reports.gpo.permission_edit",
  GpoEditDeleteModifySecurity: "reports.gpo.permission_manage", GpoCustom: "reports.gpo.permission_custom", GpoNone: "reports.gpo.permission_none",
};
const changeLabels: Record<string, MessageKey> = {
  gpo: "reports.gpo.policy", gpo_setting: "reports.gpo.parameter", gpo_link: "reports.gpo.link",
  display_name: "reports.gpo.policy", modification_time: "reports.gpo.modified",
  "computer.directory_version": "reports.gpo.computer_ad", "computer.sysvol_version": "reports.gpo.computer_sysvol",
  "user.directory_version": "reports.gpo.user_ad", "user.sysvol_version": "reports.gpo.user_sysvol",
};

export function GpoPolicyCard({ definition, domain, initial, backHref }: {
  definition: ReportDefinitionDto; domain: string; initial: URLSearchParams; backHref: string;
}) {
  const policyId = initial.get("policy_id");
  const snapshot = initial.get("snapshot");
  const enabled = Boolean(domain && policyId && snapshot);
  const [tab, setTab] = useState<PolicyTab>(() => tabs.find((key) => key === initial.get("detail_tab")) ?? "settings");
  const [item, setItem] = useState(initial.get("setting"));
  const { formatDateTime } = useDateFormatters();
  const changeLocation = (nextTab: PolicyTab, nextItem: string | null) => {
    const address = new URL(window.location.href);
    address.searchParams.set("detail_tab", nextTab);
    if (nextItem) address.searchParams.set("setting", nextItem);
    else address.searchParams.delete("setting");
    window.history.replaceState(window.history.state, "", address);
    setTab(nextTab);
    setItem(nextItem);
  };
  const snapshotParams = { domain, policy_id: policyId ?? "", snapshot: snapshot ?? "" };
  const detail = useQuery({
    queryKey: ["report-v2", "gpo-policy", domain, policyId, snapshot],
    queryFn: () => api.reportV2Data(definition.key, new URLSearchParams({ tab: "gpos", view: "all", ...snapshotParams })),
    enabled,
    staleTime: 60_000, retry: false, refetchOnWindowFocus: false,
  });
  const policy = detail.data?.items.find((row) => row.id === policyId) as PolicyRow | undefined;
  const exact = detail.data?.coverage.snapshot_id === snapshot && String(detail.data?.coverage.domain_id) === domain;
  const history = useQuery({
    queryKey: ["report-v2", "gpo-policy-history", domain, policyId, snapshot],
    queryFn: () => api.reportV2Data(definition.key, new URLSearchParams({ tab: "changes", period: "90d", ...snapshotParams })),
    enabled: enabled && exact && Boolean(policy),
    staleTime: 60_000, retry: false, refetchOnWindowFocus: false,
  });
  const back = <a className="sli-ds-button" href={backHref}>{t("reports.gpo.back_to_list")}</a>;
  if (detail.data?.state === "denied" || detail.error instanceof ApiResponseError && [401, 403].includes(detail.error.status))
    return <ReportLayout title={t("reports.gpo.title")} domain={domain} actions={back} state="denied"
      stateView={<ReportDenied reportKey={definition.key}/>}/>;
  if (!enabled || detail.error instanceof ApiResponseError && detail.error.status === 404
      || detail.isSuccess && detail.data.state !== "error" && (!policy || !exact))
    return <ReportLayout title={t("reports.gpo.title")} domain={domain} actions={back}>
      <p role="status">{t("reports.gpo.snapshot_unavailable")}</p>
    </ReportLayout>;
  if (detail.isError || detail.data?.state === "error") return <ReportLayout title={t("reports.gpo.title")} domain={domain} actions={back}
    state="error" stateView={<div role="alert">{t("reports.gpo.card_failed")}{" "}
      <button className="sli-ds-button" type="button" onClick={() => void detail.refetch()}>{t("state.retry")}</button>
    </div>}/>;
  if (!policy) return <ReportLayout title={t("reports.gpo.title")} domain={domain} actions={back} state="loading"/>;
  const fields = detail.data?.collections as CardCollections | undefined;
  const matchedHistory = history.data?.coverage.snapshot_id === snapshot && String(history.data?.coverage.domain_id) === domain;
  const changes = matchedHistory ? (history.data?.collections as CardCollections | undefined)?.changes ?? [] : [];
  const historyState = history.data?.coverage.policy_history_state;
  const historyCount = historyState === "ok" || historyState === "empty" || changes.length > 0 ? changes.length : undefined;
  const linkCount = policy.link_count ?? (fields?.links?.length ? fields.links.length : undefined);
  const items = tabs.map((key) => {
    const count = key === "links" ? linkCount : key === "changes" ? historyCount : undefined;
    return { key, label: <>{t(`reports.gpo.${key}`)}{count == null ? null : <> <b>{count}</b></>}</> };
  });
  const content = () => {
    switch (tab) {
      case "settings": return fields?.settings?.length ? <PolicySettings settings={fields.settings} changes={changes} item={item}
        selectItem={(id) => changeLocation("settings", id)}/> : item ? t("reports.gpo.setting_unavailable") : "—";
      case "links": return <CardTable caption={t("reports.gpo.links")} rows={fields?.links ?? []} columns={[
        { key: "scope_name", label: t("reports.gpo.scope") },
        { key: "order", label: t("reports.gpo.order"), kind: "number" },
        { key: "enforced", label: t("reports.gpo.enforced"), kind: "boolean" },
        { key: "enabled", label: t("reports.gpo.enabled"), kind: "boolean" },
      ]}/>;
      case "rights": return <CardTable caption={t("reports.gpo.rights")} rows={fields?.permissions ?? []} columns={[
        { key: "trustee_name", label: t("reports.gpo.trustee") },
        { key: "permission", label: t("reports.gpo.rights"), render: (row: Permission) => {
          const label = row.permission && Object.hasOwn(permissionLabels, row.permission) ? permissionLabels[row.permission] : undefined;
          return label ? t(label) : "—";
        } },
      ]}/>;
      case "versions": return <>
        <PolicyVersions versions={fields?.versions ?? []} domain={domain}/>
        <GpoSnapshotComparison reportKey={definition.key} domain={domain} policyId={policy.id} revision={detail.dataUpdatedAt}/>
      </>;
      case "changes": return history.isPending ? <span role="status">{t("state.loading")}</span> :
        history.isError || !matchedHistory || historyState === "unavailable" || history.data?.state === "error" || history.data?.state === "denied" ?
          <div role="alert">{t("reports.gpo.history_failed")}{" "}
            <button className="sli-ds-button" type="button" onClick={() => void history.refetch()}>{t("state.retry")}</button></div>
          : historyState === "not_collected" ? <p role="status">{t("reports.state.not_collected")}</p>
          : <PolicyChanges changes={changes}/>;
    }
  };
  const observed = detail.data?.coverage.observed_at_utc;
  const sources = detail.data?.coverage.policy_sources as Record<string, string | undefined> | undefined;
  const sourceState = sources?.[tab === "settings" ? "report" : tab === "rights" ? "permissions" : tab === "versions" ? "gpt" : tab];
  const sourceMessage = !sourceState || ["observed", "no_record", "not_applicable"].includes(sourceState) ? null
    : sourceState === "partial" ? t("reports.state.partial")
    : ["failed", "access_denied", "parse_error"].includes(sourceState) ? t("reports.state.unavailable") : t("reports.state.not_collected");
  const status = ["AllSettingsEnabled", "AllSettingsDisabled", "UserSettingsDisabled", "ComputerSettingsDisabled"]
    .find((value) => value === policy.gpo_status);
  return <ReportLayout title={policy.display_name} domain={domain} actions={back}>
    <div className="sli-ds-header__meta">
      {typeof observed === "string" ? <span>{t("reports.gpo.observed")} <time dateTime={observed} title={observed}>{formatDateTime(observed)}</time></span> : null}
      {policy.guid ? <span>GUID <code>{policy.guid}</code></span> : null}
      {status ? <span>{t(`reports.v2.ad.gpo.v2.columns.status.labels.${status}` as MessageKey)}</span> : null}
    </div>
    <Tabs active={tab} items={items} onChange={(key) => changeLocation(key as PolicyTab, item)}>
      <TabList label={policy.display_name}/>
      <TabPanel>
        {sourceMessage ? <p role="status">{sourceMessage}</p> : null}
        {content()}
      </TabPanel>
    </Tabs>
  </ReportLayout>;
}

function CardTable<Row extends { id: string }>({ caption, rows, columns }: { caption: string; rows: Row[]; columns: TableColumn<Row>[] }) {
  return <DataTable caption={caption} rows={rows} columns={columns} rowKey={(row) => row.id} stickyHeader={false} showFooter={false} emptyContent="—"/>;
}

function PolicySettings({ settings, changes, item, selectItem }: {
  settings: Setting[]; changes: Change[]; item: string | null; selectItem: (id: string | null) => void;
}) {
  const { formatDateTime } = useDateFormatters();
  const [side, setSide] = useState<Side>(() => settings.find((row) => row.id === item)?.side
    ?? (settings.some((row) => row.side === "computer") ? "computer" : "user"));
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("");
  const [pageSize, setPageSize] = useState(50);
  const [page, setPage] = useState<number>();
  const matchingSide = settings.filter((row) => row.side === side);
  const categories = [...new Set(matchingSide.map((row) => row.category).filter((value): value is string => Boolean(value)))].sort((left, right) => left.localeCompare(right));
  const text = query.trim().toLocaleLowerCase();
  const rows = matchingSide.filter((row) => (!category || row.category === category) &&
    [row.setting_name, row.path, row.value_display].some((value) => (value ?? "").toLocaleLowerCase().includes(text)))
    .sort((left, right) => (left.category ?? "").localeCompare(right.category ?? "") ||
      (left.setting_name ?? "").localeCompare(right.setting_name ?? "") || (left.path ?? "").localeCompare(right.path ?? ""));
  const itemIndex = rows.findIndex((row) => row.id === item);
  const pageIndex = Math.min(page ?? Math.floor(Math.max(0, itemIndex) / pageSize), Math.max(0, Math.ceil(rows.length / pageSize) - 1));
  const start = pageIndex * pageSize;
  const lastChanges = new Map<string, Change>();
  for (const change of changes) {
    if (change.object_type === "gpo_setting" && change.field === "value_display" && !lastChanges.has(change.object_id)) lastChanges.set(change.object_id, change);
  }
  const open = (row: Setting) => { setPage(pageIndex); selectItem(item === row.id ? null : row.id); };
  const columns: TableColumn<Setting>[] = [
    { key: "setting_name", label: t("reports.gpo.parameter"), width: "40%", render: (row) => <button type="button"
      className="sli-ds-table__disclosure" aria-expanded={item === row.id} onClick={(event) => { event.stopPropagation(); open(row); }}>
      <Icon name={item === row.id ? "chevron-down" : "chevron"}/>{row.setting_name || "—"}
    </button> },
    { key: "value_display", label: t("reports.gpo.value"), width: "27%" },
    { key: "category", label: t("reports.gpo.category") },
    { key: "modified", label: t("reports.gpo.setting_modified"), kind: "datetime", wideOnly: true, value: (row) => lastChanges.get(row.id)?.observed_at },
  ];
  return <>
    <div className="sli-ds-split-report__toolbar">
      <div className="sli-ds-header__meta">
        {sides.map((key) => {
          const count = settings.filter((row) => row.side === key).length;
          return count ? <button type="button" key={key} className="sli-ds-chip" aria-pressed={side === key}
            onClick={() => { setSide(key); setCategory(""); setQuery(""); setPage(0); selectItem(null); }}>{t(`reports.gpo.${key}`)} <b>{count}</b></button> : null;
        })}
      </div>
      <label className="sli-ds-field" data-grow="" data-search=""><Icon name="search"/><input type="search" aria-label={t("reports.gpo.search_settings")} placeholder={t("reports.gpo.search_settings")}
        value={query} onChange={(event) => { setQuery(event.target.value); setPage(0); }}/></label>
      {categories.length ? <div className="sli-ds-field"><Select label={t("reports.gpo.category")} value={category} onChange={(selectedValue) => { setCategory(selectedValue); setPage(0); }}
        options={[{ value: "", label: t("reports.gpo.all_categories") }, ...(categories.map((value) => ({ value: value, label: value })) ?? [])]}/></div> : null}
    </div>
    {item && !settings.some((row) => row.id === item) ? <p role="status">{t("reports.gpo.setting_unavailable")}</p> : null}
    <DataTable caption={t("reports.gpo.settings")} rows={rows.slice(start, start + pageSize)} columns={columns} rowKey={(row) => row.id}
      total={rows.length} pageSize={{ value: pageSize, options: [25, 50, 100, 200], onChange: (size) => { setPageSize(size); setPage(0); } }}
      pagination={{ start: start + 1, onPrevious: pageIndex > 0 ? () => setPage(pageIndex - 1) : undefined,
        onNext: start + pageSize < rows.length ? () => setPage(pageIndex + 1) : undefined }}
      onRowClick={open} emptyContent="—" expandedContent={(row) => {
        if (item !== row.id) return null;
        const change = lastChanges.get(row.id);
        const before = change?.after_value === row.value_display ? change?.before_value : undefined;
        return <div className="sli-ds-table__row-details">
          <dl>
            <dt>{t("reports.gpo.configured_value")}</dt><dd>{row.value_display ?? "—"}{before != null && change?.observed_at
              ? <span className="sli-ds-text-muted"> · {t("reports.gpo.previous", { value: before, time: formatDateTime(change.observed_at) })}</span> : null}</dd>
            {row.path ? <><dt>{t("reports.gpo.path")}</dt><dd>{row.path}</dd></> : null}
          </dl>
          {row.value_display ? <CopyValue value={row.value_display}/> : null}
        </div>;
      }}/>
    <div className="sli-ds-split-report__count" aria-live="polite">{plural(rows.length, {
      one: t("reports.gpo.settings_shown.one", { count: rows.length }),
      few: t("reports.gpo.settings_shown.few", { count: rows.length }),
      many: t("reports.gpo.settings_shown.many", { count: rows.length }),
    })}</div>
  </>;
}

function CopyValue({ value }: { value: string }) {
  const [state, setState] = useState<"ready" | "copied" | "failed">("ready");
  return <button type="button" className="sli-ds-text-button" onClick={async () => {
    try { await navigator.clipboard.writeText(value); setState("copied"); } catch { setState("failed"); }
  }}>{t(state === "copied" ? "reports.gpo.copied" : state === "failed" ? "reports.gpo.copy_failed" : "reports.gpo.copy")}</button>;
}

function PolicyVersions({ versions, domain }: { versions: Versions[]; domain: string }) {
  const current = versions[0];
  const components = current ? sides.map((side) => ({ id: side, row: current })) : [];
  return <div className="sli-ds-split-report__columns">
    <CardTable caption={t("reports.gpo.versions")} rows={components} columns={[
      { key: "component", label: t("reports.gpo.component"), render: ({ id }) => t(`reports.gpo.${id}`) },
      ...(["directory_version", "sysvol_version"] as const).map((source): TableColumn<typeof components[number]> => ({
        key: source, label: t(source === "directory_version" ? "reports.gpo.ad" : "reports.gpo.sysvol"), kind: "number",
        render: ({ id, row }) => hasMismatch(row, id) ? <strong className="sli-ds-value-mismatch">{row[`${id}_${source}`]}</strong> : row[`${id}_${source}`] ?? "—",
      })),
    ]}/>
    <CardTable caption={t("reports.gpo.version_history")} rows={versions.filter((row) => row.observed_at).map((row) => ({ ...row, id: row.observed_at! }))} columns={[
      { key: "observed_at", label: t("reports.gpo.observed"), kind: "datetime" },
      { key: "computer", label: t("reports.gpo.computer_version_pair"), render: (row) => versionPair(row, "computer", domain) },
      { key: "user", label: t("reports.gpo.user_version_pair"), render: (row) => versionPair(row, "user", domain) },
    ]}/>
  </div>;
}

function PolicyChanges({ changes }: { changes: Change[] }) {
  return <CardTable caption={t("reports.gpo.changes")} rows={changes} columns={[
    { key: "observed_at", label: t("reports.gpo.time"), kind: "datetime", width: "13rem" },
    { key: "name", label: t("reports.gpo.parameter"), render: (row) => {
      const key = [row.field, row.object_type].find((value) => Object.hasOwn(changeLabels, value));
      return row.name || (key ? t(changeLabels[key]) : "—");
    } },
    { key: "change", label: t("reports.gpo.change"), render: (row) => row.kind === "object_added" ? t("reports.gpo.added") :
      row.kind === "object_removed" ? t("reports.gpo.removed") :
        row.before_value != null || row.after_value != null ? <>{row.before_value ?? "—"} → <b>{row.after_value ?? "—"}</b></> : t("reports.gpo.changed") },
  ]}/>;
}
