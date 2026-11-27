import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiResponseError } from "../api/client";
import type { SigmaLiveRule } from "../api/sigma-types";
import { Button, DataTable, SeverityBadge, StateView, type TableColumn } from "../design-system";
import { Checkbox } from "../design-system/Checkbox";
import { t } from "../i18n";

const queryKey = ["sigma-live-rules"];

export function SigmaLiveRules({ sourceAction }: { sourceAction?: string }) {
  const client = useQueryClient();
  const rules = useQuery({ queryKey, queryFn: api.sigmaLiveRules, retry: false });
  const change = useMutation({
    mutationFn: (row: SigmaLiveRule) => api.setSigmaLiveRule(row.rule_id, !row.enabled),
    onMutate: () => client.cancelQueries({ queryKey }),
    onSuccess: (result) => client.setQueryData(queryKey, result),
    onError: () => void client.invalidateQueries({ queryKey }),
  });
  if (rules.isPending) return <StateView state="loading"/>;
  if (rules.isError) {
    const denied = rules.error instanceof ApiResponseError && [401, 403].includes(rules.error.status);
    if (denied) return <p role="status">{t("state.denied.title")}</p>;
    return <p role="alert">{t("security.sigma.live.read_failed")} <Button onClick={() => void rules.refetch()}>{t("state.retry")}</Button></p>;
  }
  if (!rules.data.rules.length) return <p role="status">{sourceAction ?? t("security.sigma.live.catalog_empty")}</p>;
  const columns: TableColumn<SigmaLiveRule>[] = [
    { key: "rule", label: t("security.sigma.live.rule"), render: (row) => <>
      <a href={row.source_uri} target="_blank" rel="noreferrer">{row.title}</a>
      <div>{row.author} · {row.license}</div>
    </> },
    { key: "level", label: t("security.sigma.live.level"), render: (row) => <SeverityBadge severity={row.level}
      label={row.level === "informational" ? t("security.sigma.live.informational") : undefined}/> },
    { key: "enabled", label: t("security.sigma.live.enabled"), render: (row) => <>
      <Checkbox role="switch" aria-label={row.title} checked={row.enabled} disabled={change.isPending}
        onChange={() => change.mutate(row)}/>
      {change.isError && change.variables?.rule_id === row.rule_id
        ? <div role="alert">{t("security.sigma.live.save_failed")}</div> : null}
    </> },
    { key: "matches", label: t("security.sigma.live.matches"), render: (row) => row.matches_24h },
  ];
  return <DataTable columns={columns} rows={rules.data.rules} rowKey={(row) => row.rule_id}
    caption={t("security.sigma.list.title")}/>;
}
