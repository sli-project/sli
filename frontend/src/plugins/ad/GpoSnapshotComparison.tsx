import { useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import { Button, DataTable, Select, type TableColumn } from "../../design-system";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { t } from "../../i18n";
import { displaySetting, maskedValue, type Setting } from "./gpo-settings";

const sides = ["computer", "user"] as const;
type Side = typeof sides[number];
export type Versions = Partial<Record<`${Side}_${"directory_version" | "sysvol_version"}`, number | null>>;
type SnapshotChoice = Versions & { id: string; observed_at: string };
type SnapshotPair = { before: string; after: string };
type Difference = Setting & {
  id: string;
  kind: "added" | "changed" | "removed";
  before_value?: string;
  after_value?: string;
};

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

export function GpoSnapshotComparison({ reportKey, domain, policyId, revision, observed }: {
  reportKey: string; domain: string; policyId: string; revision: number; observed?: string;
}) {
  const { formatDateTime } = useDateFormatters();
  const [selection, setSelection] = useState<SnapshotPair>();
  const queryKey = ["report-v2", "gpo-snapshots", reportKey, domain, policyId, revision];
  const base = { tab: "gpos", policy_id: policyId, domain };
  const queryOptions = { staleTime: 60_000, retry: false, refetchOnWindowFocus: false };
  const choices = useQuery({
    ...queryOptions, queryKey,
    queryFn: () => api.reportV2Data(reportKey, new URLSearchParams({ ...base, snapshots: "1" })),
  });
  const snapshots = ((choices.data?.collections?.snapshots ?? []) as SnapshotChoice[])
    .filter((snapshot) => !observed || Date.parse(snapshot.observed_at) <= Date.parse(observed));
  const versions = new Map(snapshots.map((snapshot, index) => [snapshot.id, { snapshot, previous: snapshots[index + 1] }]));
  const active = selection && versions.has(selection.after) && versions.has(selection.before) ? selection : undefined;
  const comparison = useQuery({
    ...queryOptions, queryKey: [...queryKey, active?.before, active?.after], enabled: Boolean(active),
    queryFn: () => api.reportV2Data(reportKey, new URLSearchParams({
      ...base, before_snapshot: active!.before, after_snapshot: active!.after,
    })),
  });

  if (choices.isPending) return <div role="status">{t("state.loading")}</div>;
  if (choices.isError || choices.data?.state === "error" || choices.data?.state === "denied") return <div role="alert">
    {t("reports.gpo.snapshots_failed")} <Button onClick={() => void choices.refetch()}>{t("state.retry")}</Button>
  </div>;

  const differences = comparison.data?.collections?.snapshot_comparison as Difference[] | undefined;
  const columns: TableColumn<Difference>[] = [
    { key: "setting_name", label: t("reports.gpo.parameter"), width: "49%", render: (row) => {
      const setting = displaySetting(row);
      return <>{setting.setting_name}{setting.path && <div className="sli-ds-text-muted">{setting.category} · {setting.path}</div>}</>;
    } },
    { key: "side", label: t("reports.gpo.component"), render: (row) => t(`reports.gpo.${row.side}`) },
    { key: "difference", label: t("reports.gpo.change"), width: "41%",
      renderHeader: differences?.some((row) => row.before_value === maskedValue || row.after_value === maskedValue) ?
        () => <span title={t("reports.gpo.value_hidden_reason")}>{t("reports.gpo.change")}</span> : undefined,
      render: (row) => {
        const before = displaySetting({ ...row, value_display: row.before_value }).value_display;
        const after = displaySetting({ ...row, value_display: row.after_value }).value_display;
        return <><span className="sli-ds-text-muted">{t(`reports.gpo.${row.kind}`)} · </span>{before ?? "—"} → <b>{after ?? "—"}</b></>;
      },
    },
  ];
  const earlier = active ? snapshots.slice(snapshots.findIndex((snapshot) => snapshot.id === active.after) + 1) : [];
  return <>
    <DataTable caption={t("reports.gpo.version_history")} rows={snapshots} rowKey={(row) => row.id} selectedKey={active?.after}
      stickyHeader={false} showFooter={false} emptyContent="—" columns={[
        { key: "observed_at", label: t("reports.gpo.observed"), kind: "datetime" },
        { key: "computer", label: t("reports.gpo.computer_version_pair"), render: (row) => versionPair(row, "computer", domain) },
        { key: "user", label: t("reports.gpo.user_version_pair"), render: (row) => versionPair(row, "user", domain) },
        { key: "compare", label: t("reports.gpo.snapshot_comparison"), render: (row) => {
          const previous = versions.get(row.id)?.previous;
          return previous && <Button variant="ghost" aria-pressed={active?.after === row.id} onClick={() => setSelection({ before: previous.id, after: row.id })}>
            {t("reports.gpo.compare_snapshots")}
          </Button>;
        } },
      ]}/>
    {active && <div className="sli-ds-split-report__toolbar">
      {earlier.length > 1 ? <Select label={t("reports.gpo.version_before")} value={active.before}
        onChange={(before) => setSelection({ ...active, before })}
        options={earlier.map((snapshot) => ({ value: snapshot.id, label: formatDateTime(snapshot.observed_at) }))}/> :
        <time dateTime={versions.get(active.before)!.snapshot.observed_at}>{formatDateTime(versions.get(active.before)!.snapshot.observed_at)}</time>}
      <span aria-hidden="true">→</span>
      <time dateTime={versions.get(active.after)!.snapshot.observed_at}>{formatDateTime(versions.get(active.after)!.snapshot.observed_at)}</time>
    </div>}
    {active && (comparison.isPending ? <div role="status">{t("state.loading")}</div> :
      comparison.isError || !differences ? <div role="alert">
        {t("reports.gpo.snapshot_comparison_failed")} <Button onClick={() => void comparison.refetch()}>{t("state.retry")}</Button>
      </div> : differences.length === 0 ? <div role="status">{t("reports.gpo.snapshot_comparison_equal")}</div> :
        <DataTable caption={t("reports.gpo.snapshot_comparison")} rows={differences} columns={columns} rowKey={(row) => String(row.id)}
          stickyHeader={false} showFooter={false} wrapCells="all"/>)}
  </>;
}
