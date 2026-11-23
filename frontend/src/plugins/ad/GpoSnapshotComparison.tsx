import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import { DataTable, type TableColumn } from "../../design-system";
import { t } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
import { useTimeZone } from "../../shared/time-zone";

type SnapshotChoice = { id: string; observed_at: string };
type SnapshotPair = { before: string; after: string };
type Difference = {
  id: number;
  side: "computer" | "user";
  setting_name: string;
  path: string;
  kind: "added" | "changed" | "removed";
  before_value: unknown;
  after_value: unknown;
};

export function GpoSnapshotComparison({ reportKey, domain, policyId, revision }: {
  reportKey: string; domain: string; policyId: string; revision: number;
}) {
  const { timeZone } = useTimeZone();
  const [selection, setSelection] = useState<Partial<SnapshotPair>>({});
  const [submitted, setSubmitted] = useState<SnapshotPair>();
  const queryKey = ["report-v2", "gpo-snapshots", reportKey, domain, policyId, revision];
  const base = { tab: "gpos", policy_id: policyId, domain };
  const queryOptions = { staleTime: 60_000, retry: false, refetchOnWindowFocus: false };
  const choices = useQuery({
    ...queryOptions, queryKey,
    queryFn: () => api.reportV2Data(reportKey, new URLSearchParams({ ...base, snapshots: "1" })),
  });
  const snapshots = (choices.data?.collections?.snapshots ?? []) as SnapshotChoice[];
  const selected = {
    before: snapshots.find((snapshot) => snapshot.id === selection.before)?.id ?? snapshots[1]?.id,
    after: snapshots.find((snapshot) => snapshot.id === selection.after)?.id ?? snapshots[0]?.id,
  };
  const active = submitted && submitted.before === selected.before && submitted.after === selected.after ? submitted : undefined;
  const comparison = useQuery({
    ...queryOptions, queryKey: [...queryKey, active?.before, active?.after], enabled: Boolean(active),
    queryFn: () => api.reportV2Data(reportKey, new URLSearchParams({
      ...base, before_snapshot: active!.before, after_snapshot: active!.after,
    })),
  });

  if (choices.isPending) return <div role="status">{t("state.loading")}</div>;
  if (choices.isError || choices.data?.state === "error" || choices.data?.state === "denied") return <div role="alert">
    {t("reports.gpo.snapshots_failed")} <button className="sli-ds-button" type="button" onClick={() => void choices.refetch()}>{t("state.retry")}</button>
  </div>;
  if (snapshots.length < 2) return <div role="status">{t("reports.gpo.snapshots_required")}</div>;

  const differences = comparison.data?.collections?.snapshot_comparison as Difference[] | undefined;
  const columns: TableColumn<Difference>[] = [
    { key: "setting_name", label: t("reports.gpo.parameter"), width: "27%", render: (row) => <>
      {row.setting_name || "—"}{row.path ? <div className="sli-ds-text-muted">{row.path}</div> : null}
    </> },
    { key: "side", label: t("reports.gpo.component"), render: (row) => t(`reports.gpo.${row.side}`) },
    { key: "kind", label: t("reports.gpo.change"), render: (row) => t(`reports.gpo.${row.kind}`) },
    { key: "before_value", label: t("reports.gpo.snapshot_before"), width: "25%", wrap: true },
    { key: "after_value", label: t("reports.gpo.snapshot_after"), width: "25%", wrap: true },
  ];
  const canCompare = selected.before && selected.after && selected.before !== selected.after;
  return <>
    <form className="sli-ds-filters__fields" onSubmit={(event) => {
      event.preventDefault();
      if (selected.before && selected.after && canCompare) setSubmitted({ before: selected.before, after: selected.after });
    }}>
      {(["before", "after"] as const).map((side) => <label className="sli-ds-field" key={side}>
        <span>{t(`reports.gpo.snapshot_${side}`)}</span>
        <select value={selected[side]} onChange={(event) => {
          setSelection({ ...selected, [side]: event.target.value });
          setSubmitted(undefined);
        }}>
          {snapshots.map((snapshot) => <option key={snapshot.id} value={snapshot.id}>
            {formatDateTime(snapshot.observed_at, timeZone, { seconds: true })}
          </option>)}
        </select>
      </label>)}
      <button className="sli-ds-button" data-variant="primary" type="submit" disabled={!canCompare}>{t("reports.gpo.compare_snapshots")}</button>
    </form>
    {active && (comparison.isPending ? <div role="status">{t("state.loading")}</div> :
      comparison.isError || !differences ? <div role="alert">
        {t("reports.gpo.snapshot_comparison_failed")} <button className="sli-ds-button" type="button" onClick={() => {
          void choices.refetch();
          void comparison.refetch();
        }}>{t("state.retry")}</button>
      </div> : differences.length === 0 ? <div role="status">{t("reports.gpo.snapshot_comparison_equal")}</div> :
        <DataTable caption={t("reports.gpo.snapshot_comparison")} rows={differences} columns={columns} rowKey={(row) => String(row.id)}
          stickyHeader={false} showFooter={false} wrapCells="all"/>)}
  </>;
}
