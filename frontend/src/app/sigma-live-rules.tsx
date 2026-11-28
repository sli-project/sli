import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiResponseError } from "../api/client";
import type { SigmaLiveRule } from "../api/sigma-types";
import { Button, DataTable, DetailDrawer, FactList, SeverityBadge, StateView, type TableColumn } from "../design-system";
import { Checkbox } from "../design-system/Checkbox";
import { t, type MessageKey } from "../i18n";

const queryKey = ["sigma-live-rules"];

const ruleTitleKeys: Record<string, MessageKey> = {
  "d99b79d2-0a6f-4f46-ad8b-260b6e17f982": "security.sigma.live.title.auditCleared",
  "14c71865-6cd3-44ae-adaa-1db923fae5f2": "security.sigma.live.title.defenderTamper",
  "7b449a5e-1db5-4dd0-a2dc-4e3a67282538": "security.sigma.live.title.hiddenUser",
  "cfeed607-6aa4-4bbd-9627-b637deb723c8": "security.sigma.live.title.dollarAccount",
  "192a0330-c20b-4356-90b6-7b7049ae0b87": "security.sigma.live.title.overpassTheHash",
  "8eef149c-bd26-49f2-9e5a-9b00e3af499b": "security.sigma.live.title.passTheHash",
  "749c9f5e-b353-4b90-a9c1-05243357ca4b": "security.sigma.live.title.kerberosRelay",
  "c265cf08-3f99-46c1-8d59-328247057d57": "security.sigma.live.title.localAdmin",
  "3a734d25-df5c-4b99-8034-af1ddb5883a4": "security.sigma.live.title.scheduledTask",
  "1d61f71d-59d2-479e-9562-4ff5f4ead16b": "security.sigma.live.title.serviceInstall",
  "42c575ea-e41e-41f1-b248-8093c3e82a28": "security.sigma.live.title.psExec",
};
const ruleTitle = (row: SigmaLiveRule) => Object.hasOwn(ruleTitleKeys, row.rule_id) ? t(ruleTitleKeys[row.rule_id]) : row.title;

export function SigmaLiveRules() {
  const [selectedRuleId, setSelectedRuleId] = useState<string>();
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
  if (!rules.data.rules.length) return <p role="status">{t("security.sigma.live.catalog_empty")}</p>;
  const selected = rules.data.rules.find(row => row.rule_id === selectedRuleId);
  const columns: TableColumn<SigmaLiveRule>[] = [
    { key: "rule", label: t("security.sigma.live.rule"), render: (row) => <>
      <Checkbox role="switch" aria-label={t("security.sigma.live.toggle", { rule: ruleTitle(row) })} checked={row.enabled} disabled={change.isPending}
        onChange={() => {
          if (!row.enabled || window.confirm(t("pluginPage.confirmDisable", { name: ruleTitle(row) }))) change.mutate(row);
        }}/>
      <Button variant="ghost" onClick={() => setSelectedRuleId(row.rule_id)}>{ruleTitle(row)}</Button>
      {change.isError && change.variables?.rule_id === row.rule_id
        ? <div role="alert">{t("security.sigma.live.save_failed")}</div> : null}
    </> },
    { key: "level", label: t("security.sigma.live.level"), render: (row) => <SeverityBadge severity={row.level}
      label={row.level === "informational" ? t("security.sigma.live.informational") : undefined}/> },
  ];
  if (rules.data.rules.some(row => row.matches_24h > 0)) {
    columns.push({ key: "matches", label: t("security.sigma.live.matches"), render: row => row.matches_24h });
  }
  return <>
    <DataTable columns={columns} rows={rules.data.rules} rowKey={row => row.rule_id} caption={t("security.sigma.list.title")}/>
    {selected ? <DetailDrawer open title={ruleTitle(selected)} onClose={() => setSelectedRuleId(undefined)}>
      <FactList facts={[
        { label: t("security.sigma.live.originalTitle"), value: <a href={selected.source_uri} target="_blank" rel="noreferrer">{selected.title}</a> },
        { label: t("security.sigma.live.author"), value: selected.author },
        { label: t("security.sigma.live.license"), value: selected.license },
      ]}/>
    </DetailDrawer> : null}
  </>;
}
