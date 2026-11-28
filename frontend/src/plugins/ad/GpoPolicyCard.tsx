import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto } from "../../api/report-v2-types";
import { Badge, Button, DataTable, FilterChip, ReportLayout, TabList, TabPanel, Tabs, type TableColumn } from "../../design-system";
import { Icon } from "../../design-system/Icon";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { t, type MessageKey } from "../../i18n";
import { auditLeaf, auditLeafLabel, auditLeafValue } from "./gpo-audit-setting";
import { displaySetting, displaySettings, gpoSettingLabel, gpoSettingMetadata, type Setting } from "./gpo-settings";
import { GpoSnapshotComparison, hasMismatch, versionPair, type Versions } from "./GpoSnapshotComparison";
import { ReportDenied } from "../../app/report-v2/ReportDenied";

const sides = ["computer", "user"] as const;
type Side = typeof sides[number];
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
type LinkRow = { id: string; scope_name?: string; order?: number; enabled?: boolean; enforced?: boolean };
type Permission = { id: string; trustee_name?: string; trustee_sid?: string; permission?: string; denied?: boolean };
type Change = { id: string; object_id: string; object_type: string; field: string; kind: string; name?: string;
  observed_at?: string; before_value?: string | null; after_value?: string | null };
type CardCollections = { settings?: Setting[]; links?: LinkRow[]; permissions?: Permission[]; versions?: Versions[]; changes?: Change[] };
const tabs = ["important", "settings", "links", "rights", "versions", "changes"] as const;
export type PolicyTab = typeof tabs[number];

const permissionLabels: Record<string, MessageKey> = {
  GpoRead: "reports.gpo.permission_read", GpoApply: "reports.gpo.permission_apply", GpoEdit: "reports.gpo.permission_edit",
  GpoEditDeleteModifySecurity: "reports.gpo.permission_manage", GpoCustom: "reports.gpo.permission_custom", GpoNone: "reports.gpo.permission_none",
};

function delegatedEdit(row: Permission) {
  return !row.denied && (row.permission === "GpoEdit" || row.permission === "GpoEditDeleteModifySecurity")
    && !!row.trustee_sid && !["S-1-3-0", "S-1-5-18", "S-1-5-32-544"].includes(row.trustee_sid)
    && !/^S-1-5-21-(?:\d+-){3}(512|519)$/i.test(row.trustee_sid);
}
const changeLabels: Record<string, MessageKey> = {
  gpo: "reports.gpo.policy", gpo_setting: "reports.gpo.parameter", gpo_link: "reports.gpo.link",
  display_name: "reports.gpo.policy", modification_time: "reports.gpo.modified",
  "computer.directory_version": "reports.gpo.computer_ad", "computer.sysvol_version": "reports.gpo.computer_sysvol",
  "user.directory_version": "reports.gpo.user_ad", "user.sysvol_version": "reports.gpo.user_sysvol",
};

export function GpoPolicyCard({ definition, domain, initial, backHref }: {
  definition: ReportDefinitionDto; domain: string; initial: URLSearchParams; backHref: string;
}) {
  const guid = initial.get("policy");
  const policyId = guid ?? initial.get("policy_id");
  const snapshot = initial.get("snapshot");
  const enabled = Boolean(domain && policyId && (guid || snapshot));
  const [tab, setTab] = useState<PolicyTab>(() => tabs.find((key) => key === initial.get("detail_tab")) ?? (initial.has("setting") ? "settings" : "important"));
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
  const policyParams = { domain, policy_id: policyId ?? "" };
  const detail = useQuery({
    queryKey: ["report-v2", "gpo-policy", domain, policyId, snapshot],
    queryFn: () => api.reportV2Data(definition.key, new URLSearchParams({ tab: "gpos", view: "all", ...policyParams, ...(snapshot ? { snapshot } : {}) })),
    enabled,
    staleTime: 60_000, retry: false, refetchOnWindowFocus: false,
  });
  const policy = detail.data?.items.find((row) => guid
    ? String(row.guid).replace(/^\{|\}$/g, "").toLowerCase() === guid.replace(/^\{|\}$/g, "").toLowerCase()
    : row.id === policyId) as PolicyRow | undefined;
  const selectedSnapshot = detail.data?.coverage.snapshot_id;
  const exact = typeof selectedSnapshot === "string" && (!snapshot || selectedSnapshot === snapshot)
    && String(detail.data?.coverage.domain_id) === domain;
  const history = useQuery({
    queryKey: ["report-v2", "gpo-policy-history", domain, policyId, selectedSnapshot],
    queryFn: () => api.reportV2Data(definition.key, new URLSearchParams({ tab: "changes", period: "90d", ...policyParams, snapshot: String(selectedSnapshot) })),
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
  const matchedHistory = history.data?.coverage.snapshot_id === selectedSnapshot && String(history.data?.coverage.domain_id) === domain;
  const changes = matchedHistory ? (history.data?.collections as CardCollections | undefined)?.changes ?? [] : [];
  const historyState = history.data?.coverage.policy_history_state;
  const historyCount = historyState === "ok" || historyState === "empty" || changes.length > 0 ? changes.length : undefined;
  const linkCount = policy.link_count ?? (fields?.links?.length ? fields.links.length : undefined);
  const items = tabs.map((key) => {
    const count = key === "settings" ? policy.setting_count : key === "links" ? linkCount : key === "changes" ? historyCount : undefined;
    return { key, label: <>{t(`reports.gpo.${key}`)}{count == null ? null : <> <b>{count}</b></>}</> };
  });
  const content = () => {
    switch (tab) {
      case "important": {
        const findings = sides.filter((side) => hasMismatch(fields?.versions?.[0] ?? {}, side)).map((side) => ({
          id: side, label: t(`reports.gpo.${side}`), fact: versionPair(fields!.versions![0], side), tab: "versions" as const,
        }));
        const checks = [
          ...findings,
          ...(policy.unlinked ? [{ id: "unlinked", label: t("reports.gpo.unlinked"), fact: null, tab: "links" as const }] : []),
          ...(policy.gpo_status === "AllSettingsDisabled" ? [{ id: "disabled", label: t("reports.v2.ad.gpo.v2.columns.status.labels.AllSettingsDisabled"), fact: null, tab: "settings" as const }] : []),
        ];
        return <CardTable caption={t("reports.gpo.important")} rows={checks} columns={[{
          key: "label", label: t("reports.gpo.important"), render: (row) => <Button variant="ghost" onClick={() => changeLocation(row.tab, null)}>
            {row.id === "computer" || row.id === "user" ? t("reports.gpo.component_mismatch", { component: row.label }) : row.label}
            {row.fact && <> · {row.fact}</>}
          </Button>,
        }]}/>;
      }
      case "settings": return fields?.settings?.length ? <PolicySettings settings={fields.settings} changes={changes} item={item}
        selectItem={(id) => changeLocation("settings", id)}/> : item ? t("reports.gpo.setting_unavailable") : "—";
      case "links": return <CardTable caption={t("reports.gpo.links")} rows={fields?.links ?? []} columns={[
        { key: "scope_name", label: t("reports.gpo.scope") },
        { key: "order", label: t("reports.gpo.order"), kind: "number" },
        { key: "enforced", label: t("reports.gpo.enforced"), kind: "boolean" },
        { key: "enabled", label: t("reports.gpo.enabled"), kind: "boolean" },
      ]}/>;
      case "rights": return <CardTable caption={t("reports.gpo.rights")} rows={fields?.permissions ?? []} columns={[
        { key: "trustee_name", label: t("reports.gpo.trustee"), width: "45%", render: (row) => row.trustee_name?.trim() || row.trustee_sid || "—" },
        { key: "permission", label: t("reports.gpo.allowed"), render: (row: Permission) => {
          const label = row.permission && Object.hasOwn(permissionLabels, row.permission) ? permissionLabels[row.permission] : undefined;
          if (!label) return "—";
          const permission = t(label);
          return row.denied ? t("reports.gpo.permission_denied", { permission }) :
            <>{permission}{delegatedEdit(row) && <> <Badge tone="warning">{t("reports.gpo.can_edit")}</Badge></>}</>;
        } },
      ]}/>;
      case "versions": return <>
        <PolicyVersions current={fields?.versions?.[0]} domain={domain}/>
        <GpoSnapshotComparison reportKey={definition.key} domain={domain} policyId={policy.id} revision={detail.dataUpdatedAt}
          observed={typeof detail.data?.coverage.observed_at_utc === "string" ? detail.data.coverage.observed_at_utc : undefined}/>
      </>;
      case "changes": return history.isPending ? <span role="status">{t("state.loading")}</span> :
        history.isError || !matchedHistory || historyState === "unavailable" || history.data?.state === "error" || history.data?.state === "denied" ?
          <div role="alert">{t("reports.gpo.history_failed")}{" "}
            <button className="sli-ds-button" type="button" onClick={() => void history.refetch()}>{t("state.retry")}</button></div>
          : historyState === "not_collected" ? "—"
          : <PolicyChanges changes={changes} settings={fields?.settings ?? []}/>;
    }
  };
  const observed = detail.data?.coverage.observed_at_utc;
  const status = ["AllSettingsEnabled", "AllSettingsDisabled", "UserSettingsDisabled", "ComputerSettingsDisabled"]
    .find((value) => value === policy.gpo_status);
  return <ReportLayout title={policy.display_name} domain={domain} actions={back}>
    <div className="sli-ds-header__meta">
      {typeof observed === "string" ? <span>{t("reports.gpo.observed")} <time dateTime={observed} title={observed}>{formatDateTime(observed)}</time></span> : null}
      {status ? <span>{t(`reports.v2.ad.gpo.v2.columns.status.labels.${status}` as MessageKey)}</span> : null}
    </div>
    <Tabs active={tab} items={items} onChange={(key) => changeLocation(key as PolicyTab, item)}>
      <TabList label={policy.display_name}/>
      <TabPanel>
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
  const display = useMemo(() => displaySettings(settings), [settings]);
  const [side, setSide] = useState<Side | "">("");
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("");
  const [pageSize, setPageSize] = useState(50);
  const [page, setPage] = useState<number>();
  const text = query.trim().toLocaleLowerCase();
  const matching = display.filter((row) => (!side || row.side === side) &&
    [row.setting_name, row.path, row.category, row.value_display].some((value) => (value ?? "").toLocaleLowerCase().includes(text)));
  const categories = [...new Set(matching.map((row) => row.category))].sort((left, right) => left.localeCompare(right));
  const rows = matching.filter((row) => !category || row.category === category)
    .sort((left, right) => (left.category ?? "").localeCompare(right.category ?? "") ||
      (left.setting_name ?? "").localeCompare(right.setting_name ?? "") || (left.path ?? "").localeCompare(right.path ?? ""));
  const itemIndex = rows.findIndex((row) => row.id === item);
  const pageIndex = Math.min(page ?? Math.floor(Math.max(0, itemIndex) / pageSize), Math.max(0, Math.ceil(rows.length / pageSize) - 1));
  const start = pageIndex * pageSize;
  const visibleRows = rows.slice(start, start + pageSize);
  const lastChanges = new Map<string, Change>();
  for (const change of changes) {
    if (change.object_type === "gpo_setting" && change.field === "value_display" && !lastChanges.has(change.object_id)) lastChanges.set(change.object_id, change);
  }
  const open = (row: Setting) => { setPage(pageIndex); selectItem(item === row.id ? null : row.id); };
  const sideCounts = sides.map((key) => ({ key, count: display.filter((row) => row.side === key).length }));
  const showSides = sideCounts.every(({ count }) => count > 0);
  const columns: TableColumn<ReturnType<typeof displaySetting>>[] = [
    { key: "setting_name", label: t("reports.gpo.parameter"), width: "40%", render: (row) => <button type="button"
      className="sli-ds-table__disclosure" aria-expanded={item === row.id} onClick={(event) => { event.stopPropagation(); open(row); }}>
      <Icon name={item === row.id ? "chevron-down" : "chevron"}/>{row.setting_name || "—"}
    </button> },
    { key: "value_display", label: t("reports.gpo.value"), width: "34%", wrap: true,
      renderHeader: rows.some((row) => row.masked) ? () => <span title={t("reports.gpo.value_hidden_reason")}>{t("reports.gpo.value")}</span> : undefined,
      render: (row) => row.value_display ? <span className="sli-ds-table__value-preview">{row.value_display}</span> : "—" },
    ...(!category && categories.length > 1 ? [{ key: "category", label: t("reports.gpo.category") }] : []),
    ...(showSides && !side ? [{ key: "side", label: t("reports.gpo.component"), render: (row: Setting) => t(`reports.gpo.${row.side}`) }] : []),
  ];
  return <>
    <div className="sli-ds-split-report__toolbar">
      {showSides && <div className="sli-ds-header__meta" role="group" aria-label={t("reports.gpo.component")}>
        {[{ key: "" as const, count: display.length }, ...sideCounts].map(({ key, count }) => <FilterChip key={key} count={count} aria-pressed={side === key}
          onClick={() => { setSide(key); setCategory(""); setPage(0); selectItem(null); }}>
          {t(key ? `reports.gpo.${key}` : "reports.gpo.all_settings")}
        </FilterChip>)}
      </div>}
      <label className="sli-ds-field" data-grow="" data-search=""><Icon name="search"/><input type="search" aria-label={t("reports.gpo.search_settings")} placeholder={t("reports.gpo.search_settings")}
        value={query} onChange={(event) => { setQuery(event.target.value); setCategory(""); setPage(0); }}/></label>
    </div>
    {item && !display.some((row) => row.id === item) ? <p role="status">{t("reports.gpo.setting_unavailable")}</p> : null}
    <div className="sli-ds-split-report__columns" data-layout={categories.length > 1 ? "navigation" : "single"}>
    {categories.length > 1 && <div className="sli-ds-split-report__navigation" role="group" aria-label={t("reports.gpo.category")}>
      {["", ...categories].map((name) => <FilterChip key={name} title={name || undefined} aria-pressed={name === category}
        onClick={() => { setCategory(name); setPage(0); selectItem(null); }}>
        {name || t("reports.gpo.all_categories")}
      </FilterChip>)}
    </div>}
    <DataTable caption={t("reports.gpo.settings")} rows={visibleRows} columns={columns} rowKey={(row) => row.id}
      total={rows.length} pageSize={{ value: pageSize, options: [25, 50, 100, 200], onChange: (size) => { setPageSize(size); setPage(0); } }}
      pagination={{ start: start + 1, onPrevious: pageIndex > 0 ? () => setPage(pageIndex - 1) : undefined,
        onNext: start + pageSize < rows.length ? () => setPage(pageIndex + 1) : undefined }}
      onRowClick={open} emptyContent="—" expandedContent={(row) => {
        if (item !== row.id) return null;
        const change = lastChanges.get(row.id);
        const original = settings.find((setting) => setting.id === row.id);
        const before = original && change?.before_value != null && change.after_value === original.value_display
          ? displaySetting({ ...original, value_display: change.before_value }).value_display : undefined;
        return <div className="sli-ds-table__row-details">
          <dl>
            <dt>{t("reports.gpo.configured_value")}</dt><dd>{row.value_display ?? "—"}{typeof before === "string" && change?.observed_at
              ? <span className="sli-ds-text-muted"> · {t("reports.gpo.previous", { value: before, time: formatDateTime(change.observed_at) })}</span> : null}</dd>
            {row.path ? <><dt>{t("reports.gpo.path")}</dt><dd>{row.path}</dd></> : null}
            {row.description ? <><dt>{t("reports.gpo.purpose")}</dt><dd>{row.description}</dd></> : null}
          </dl>
          {row.value_display && !row.masked ? <CopyValue value={row.value_display}/> : null}
        </div>;
      }}/>
    </div>
  </>;
}

function CopyValue({ value }: { value: string }) {
  const [state, setState] = useState<"ready" | "copied" | "failed">("ready");
  return <button type="button" className="sli-ds-text-button" onClick={async () => {
    try { await navigator.clipboard.writeText(value); setState("copied"); } catch { setState("failed"); }
  }}>{t(state === "copied" ? "reports.gpo.copied" : state === "failed" ? "reports.gpo.copy_failed" : "reports.gpo.copy")}</button>;
}

function PolicyVersions({ current, domain }: { current?: Versions; domain: string }) {
  const components = current ? sides
    .filter((side) => current[`${side}_directory_version`] != null || current[`${side}_sysvol_version`] != null)
    .map((side) => ({ id: side, row: current })) : [];
  return <CardTable caption={t("reports.gpo.versions")} rows={components} columns={[
      { key: "component", label: t("reports.gpo.component"), render: ({ id }) => t(`reports.gpo.${id}`) },
      ...(["directory_version", "sysvol_version"] as const).map((source): TableColumn<typeof components[number]> => ({
        key: source, label: t(source === "directory_version" ? "reports.gpo.ad" : "reports.gpo.sysvol"), kind: "number",
        render: ({ id, row }) => hasMismatch(row, id) ? <strong className="sli-ds-value-mismatch">{row[`${id}_${source}`]}</strong> : row[`${id}_${source}`] ?? "—",
      })),
    ]}/>;
}

function PolicyChanges({ changes, settings }: { changes: Change[]; settings: Setting[] }) {
  const byId = new Map(settings.map((setting) => [setting.id, setting]));
  const display = new Map(displaySettings(settings).map((setting) => [setting.id, setting]));
  const displayed = changes.filter((change) => change.object_type !== "gpo_setting" || !gpoSettingMetadata(change.name)).map((change) => {
    const setting = change.object_type === "gpo_setting" ? byId.get(change.object_id) : undefined;
    const leaf = auditLeaf(setting?.setting_name, setting?.path, setting?.category, setting?.extension);
    if (!leaf) return { ...change, name: display.get(change.object_id)?.setting_name ??
      (change.name === "KeyPath" ? t("reports.gpo.path") : change.object_type === "gpo_setting" ? gpoSettingLabel(change.name) : change.name) };
    const name = auditLeafLabel(leaf, setting?.value_display);
    if (change.field !== "value_display") return { ...change, name, before_value: undefined, after_value: undefined };
    const before = auditLeafValue(leaf, change.before_value, setting?.side);
    const after = auditLeafValue(leaf, change.after_value, setting?.side);
    return { ...change, name, before_value: typeof before === "string" ? before : undefined,
      after_value: typeof after === "string" ? after : undefined };
  });
  if (displayed.length === 0) return <p role="status">{t("reports.gpo.changes_empty")}</p>;
  return <CardTable caption={t("reports.gpo.changes")} rows={displayed} columns={[
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
