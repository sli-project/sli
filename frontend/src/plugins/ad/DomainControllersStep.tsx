import { Select } from "../../design-system/Select";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiResponseError, api, type SetupDomain, type SetupDomainController, type SetupSourceInstance } from "../../api/client";
import { useEffectiveAccess } from "../../app/App";
import { FieldError } from "../../app/admin/gate";
import { t, type MessageKey } from "../../i18n";

const CONTROLLER_ERRORS: Record<string, MessageKey> = {
  domain_controller_already_exists: "setup.dc.error.domain_controller_already_exists",
  domain_controller_not_found: "setup.dc.error.domain_controller_not_found",
  domain_not_found: "setup.dc.error.domain_not_found",
  connect_address_must_be_fqdn: "setup.dc.error.connect_address_must_be_fqdn",
  value_must_be_dns_name: "setup.dc.error.value_must_be_dns_name",
  domain_controllers_file_invalid: "setup.dc.error.domain_controllers_file_invalid",
};

const SOURCE_LABELS = { db: "setup.dc.source.db", file: "setup.dc.source.file" } as const;

function controllerError(error: unknown): Error | null {
  if (!error) return null;
  const code = error instanceof ApiResponseError ? error.code : undefined;
  return new Error((code && Object.hasOwn(CONTROLLER_ERRORS, code) ? t(CONTROLLER_ERRORS[code]) : (error as Error).message));
}

/** Контроллеры домена: таблица с источником (база/файл), включение и отключение, форма добавления — только для access.manage. */
export function DomainControllersStep({ controllers, domains, agentInstances }: { controllers: SetupDomainController[]; domains: SetupDomain[]; agentInstances?: SetupSourceInstance[] }) {
  const access = useEffectiveAccess();
  const canManage = Boolean(access?.capabilities.includes("access.manage"));
  const queryClient = useQueryClient();
  const refresh = () => void queryClient.invalidateQueries({ queryKey: ["setup-status"] });
  const [hostname, setHostname] = useState("");
  const [domain, setDomain] = useState("");
  const registeredDomain = domains.length === 1 ? domains[0].fqdn : domains.find((item) => item.fqdn === domain)?.fqdn ?? "";
  const add = useMutation({
    mutationFn: () => api.addSetupDomainController({ hostname: hostname.trim(), domain: registeredDomain }),
    onSuccess: () => { setHostname(""); refresh(); },
  });
  const toggle = useMutation({
    mutationFn: (item: SetupDomainController) => api.setSetupDomainControllerEnabled(item.hostname, !item.enabled),
    onSuccess: refresh,
  });
  const fromFile = controllers.some((item) => item.source === "file");
  // Exact source binding only: never match short hostnames or infer a target.
  const rows = agentInstances === undefined
    ? controllers.map((target) => ({ name: target.hostname, target }))
    : agentInstances.map((observation) => ({ name: observation.source_instance_id,
      target: controllers.find((target) => target.hostname.toLocaleLowerCase("en-US") === observation.source_instance_id.toLocaleLowerCase("en-US")) }));
  if (agentInstances !== undefined) {
    for (const target of controllers) {
      if (!rows.some((row) => row.name.toLocaleLowerCase("en-US") === target.hostname.toLocaleLowerCase("en-US"))) {
        rows.push({ name: target.hostname, target });
      }
    }
  }
  return <>
    {rows.length ? <table>
      <caption>{t("setup.dc.tableCaption")}</caption>
      <thead><tr><th scope="col">{t("setup.dc.colController")}</th><th scope="col">{t("setup.dc.colDomain")}</th><th scope="col">{t("setup.dc.colSource")}</th><th scope="col">{t("setup.dc.colDnsCheck")}</th>{agentInstances === undefined ? <th scope="col">{t("setup.dc.colState")}</th> : null}{canManage ? <th scope="col">{t("setup.dc.colAction")}</th> : null}</tr></thead>
      <tbody>{rows.map(({ name, target }) => <tr key={name}>
        <td>{target?.connect_address ?? name}</td><td>{target?.domain ?? t("table.noValue")}</td><td>{target ? t(SOURCE_LABELS[target.source]) : t("setup.controllers.agentSource")}</td>
        <td>{target ? target.dns_readback ? t("setup.dc.dnsEnabled") : t("setup.dc.dnsNo") : t("table.noValue")}</td>
        {agentInstances === undefined ? <td>{target?.enabled ? t("setup.dc.enabled") : t("setup.dc.disabled")}</td> : null}
        {canManage ? <td>{target?.source === "db" ?
          <button type="button" className="sli-ds-button" disabled={toggle.isPending} onClick={() => toggle.mutate(target)}>{target.enabled ? t("setup.dc.actionDisable") : t("setup.dc.actionEnable")}</button>
        : null}</td> : null}
      </tr>)}</tbody>
    </table> : null}
    {fromFile ? <p className="sli-ds-header__subtitle">{t("setup.dc.fileWarning")}</p> : null}
    <FieldError error={controllerError(toggle.error)}/>
    {canManage ? <form onSubmit={(event) => { event.preventDefault(); if (hostname.trim() && registeredDomain) add.mutate(); }}>
      <div className="sli-ds-field"><label htmlFor="setup-dc-hostname">{t("setup.dc.labelHostname")}</label>
        <input id="setup-dc-hostname" value={hostname} onChange={(event) => setHostname(event.target.value)} autoComplete="off" spellCheck={false} placeholder={t("setup.dc.hostnamePlaceholder")}/></div>
      <div className="sli-ds-field"><label htmlFor="setup-dc-domain">{t("setup.dc.labelDomain")}</label>
        {domains.length === 1 ? <input id="setup-dc-domain" value={registeredDomain} readOnly/> : <Select label={t("setup.dc.labelDomain")} id="setup-dc-domain" value={registeredDomain} onChange={(selectedValue) => setDomain(selectedValue)} disabled={!domains.length}
          options={[{ value: "", label: t("setup.dc.selectDomain") }, ...(domains.map((item) => ({ value: item.fqdn, label: item.fqdn })) ?? [])]}/>}</div>
      <FieldError error={controllerError(add.error)}/>
      {add.isSuccess ? <p className="sli-ds-header__subtitle" role="status">{t("setup.dc.added")}</p> : null}
      <div className="sli-ds-filters__actions">
        <button type="submit" className="sli-ds-button" disabled={!hostname.trim() || !registeredDomain || add.isPending}>{add.isPending ? t("setup.dc.adding") : t("setup.dc.add")}</button>
      </div>
    </form> : null}
  </>;
}

