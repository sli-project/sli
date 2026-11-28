import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { PluginSettings } from "../../api/plugin-settings-types";
import { Button, DataTable } from "../../design-system";
import { Checkbox } from "../../design-system/Checkbox";
import { t } from "../../i18n";
import { workstationLogonPolicy, workstationLogonPolicyKey } from "./plugin-settings-model";

export function WorkstationRule({ data, canEdit, openSettings }: {
  data: PluginSettings; canEdit: boolean; openSettings: () => void;
}) {
  const client = useQueryClient();
  const queryKey = ["plugin-settings", data.plugin_id];
  const key = workstationLogonPolicyKey;
  const policy = workstationLogonPolicy(data.values[key]);
  const configured = !!policy?.policies.length;
  const enabled = configured && policy.enabled !== false;
  const name = t("plugins.sli.workstations.rules.C07.name");
  const change = useMutation({
    mutationFn: ({ policy, enabled }: { policy: NonNullable<ReturnType<typeof workstationLogonPolicy>>; enabled: boolean }) =>
      api.savePluginSetting(data.plugin_id, key, { ...policy, enabled, version: policy.version + 1 }),
    onMutate: () => client.cancelQueries({ queryKey }),
    onSuccess: result => client.setQueryData<PluginSettings>(queryKey, current =>
      current ? { ...current, values: { ...current.values, [key]: result.value } } : current),
    onError: () => void client.invalidateQueries({ queryKey }),
  });
  return <>
    <DataTable rows={[name]} rowKey={() => "C07"} caption={t("pluginPage.tab.rules")} columns={[
      { key: "rule", label: t("pluginPage.rule"), render: rule => rule },
      { key: "state", label: t("pluginPage.ruleState"), render: () =>
        <Checkbox role="switch" aria-label={name} checked={enabled} disabled={!canEdit || !configured || change.isPending}
          onChange={event => {
            const enabled = event.target.checked;
            if (policy && (enabled || window.confirm(t("pluginPage.confirmDisable", { name })))) change.mutate({ policy, enabled });
          }}>
          {t(!configured ? "pluginPage.conditionNotSet" : enabled ? "plugins.enabled" : "plugins.status.disabled")}
        </Checkbox> },
      { key: "settings", label: t("pluginPage.tab.settings"), render: () =>
        <Button onClick={openSettings}>{t("pluginPage.ruleSettings")}</Button> },
    ]}/>
    {change.isError ? <p role="alert">{t("pluginPage.saveFailed", { label: name })}</p> : null}
  </>;
}
