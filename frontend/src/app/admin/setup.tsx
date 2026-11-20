import { agentCollectionDetail, agentCollectionHistory, agentCollectionLabel, agentCollectionName, agentCollectionSummary } from "../agent-collection-view";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { DomainControllersStep } from "../../plugins/ad/DomainControllersStep";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { ApiResponseError, api, type SetupDomain, type SetupSource, type SetupSourceInstance, type SetupStatus, type SetupStep } from "../../api/client";
import { Badge, FactList, PageHeader, StateView, useOverlays, type Tone } from "../../design-system";
import { useEffectiveAccess } from "../App";
import { FieldError } from "./gate";
import { t, type MessageKey } from "../../i18n";
import { setupSourceName } from "./setup-source-labels";
import { setupDestinationLabel, setupSourceAction, setupSourceAnchor, setupStepPresentation } from "./setup-presentation";
import { useTimeZone } from "../App";
import { formatDateTime as formatDateTimeTz } from "../../shared/date-time";

const STATE_TONES: Record<SetupStep["state"], Tone> = {
  done: "success",
  todo: "warning",
  unavailable: "neutral",
};

/** Мастер первичной настройки: домены AD добавляются здесь, запуск сбора — нет. */
export function SetupPage() {
  const status = useQuery({ queryKey: ["setup-status"], queryFn: api.setupStatus });
  return <section className="sli-ds-report">
    <PageHeader title={t("setup.page.title")} subtitle={t("setup.page.subtitle")}/>
    {status.isLoading ? <StateView state="loading"/> : status.error ? <StateView state="unavailable" compact detail={status.error.message} onRetry={() => void status.refetch()}/> : null}
    {status.data ? <SetupSteps status={status.data}/> : null}
  </section>;
}

function SetupSteps({ status }: { status: SetupStatus }) {
  const next = status.next_step;
  const nextPack = status.sources.find((pack) => pack.pack_id === next?.pack_id);
  return <>
    {next && nextPack ? <p className="sli-ds-header__subtitle">{t("setup.source.nextStep")} <a href={`#${encodeURIComponent(setupSourceAnchor(next.pack_id, next.source_instance_id))}`}>
      {setupSourceName(nextPack)}{next.source_instance_id ? `: ${next.source_instance_id}` : ""} — {setupSourceAction(next.action, nextPack.pack_id, nextPack.collection_basis === "agents" || nextPack.instances?.some((item) => item.collection_state !== undefined))}
    </a></p> : null}
    <ol className="sli-ds-setup-steps">
    {status.steps.map((item, index) => { const step = setupStepPresentation(item, status); return <li key={step.id} id={`setup-${step.id}`} className="sli-ds-filters">
      <h2 className="sli-ds-section-title">{index + 1}. {step.title} <Badge tone={STATE_TONES[step.state]}>{t(`setup.state.${step.state}`)}</Badge></h2>
      <p className="sli-ds-header__subtitle">{step.summary}</p>
      <StepDetails id={step.id} state={step.state} status={status}/>
      {step.manual || step.doc ? <details><summary>{t("setup.step.manualDetails")}</summary><p className="sli-ds-header__subtitle">{step.manual}{step.doc ? <> {t("setup.step.docPrefix")} <code>{step.doc}</code>.</> : null}</p></details> : null}
      {step.link ? <p><a href={`/app${step.link}`}>{setupDestinationLabel(step.link)}</a></p> : null}
    </li>; })}
  </ol></>;
}

const DOMAIN_ERRORS: Record<string, MessageKey> = {
  domain_already_exists: "setup.domain.error.domain_already_exists",
  netbios_already_exists: "setup.domain.error.netbios_already_exists",
  value_must_be_dns_name: "setup.domain.error.value_must_be_dns_name",
  netbios_must_be_up_to_15_letters_digits_hyphen: "setup.domain.error.netbios_must_be_up_to_15_letters_digits_hyphen",
};

/** Таблица доменов; форму добавления видит только тот, кто управляет доступом (сервер проверяет это снова). */
function DomainsStep({ domains, state }: { domains: SetupDomain[]; state: SetupStep["state"] }) {
  const overlays = useOverlays();
  const archiveBusy = useRef(false);
  useEffect(() => () => overlays.closeModal(), [overlays.closeModal]);
  const { timeZone } = useTimeZone();
  const access = useEffectiveAccess();
  const canManage = Boolean(access?.capabilities.includes("access.manage"));
  const queryClient = useQueryClient();
  const [fqdn, setFqdn] = useState("");
  const [netbios, setNetbios] = useState("");
  const add = useMutation({
    mutationFn: () => api.addSetupDomain({ fqdn: fqdn.trim(), ...(netbios.trim() ? { netbios_name: netbios.trim() } : {}) }),
    onSuccess: () => {
      setFqdn("");
      setNetbios("");
      void queryClient.invalidateQueries({ queryKey: ["setup-status"] });
    },
  });
  const archive = useMutation({
    mutationFn: ({ fqdn, archived }: { fqdn: string; archived: boolean }) => api.setSetupDomainArchived(fqdn, archived),
    onSuccess: () => {
      return Promise.all(["setup-status", "setup-domains", "platform-settings", "domains", "report-v2"].map((key) => queryClient.invalidateQueries({ queryKey: [key] })));
    },
    onSettled: () => { archiveBusy.current = false; },
  });
  const confirmArchive = (domain: SetupDomain) => {
    if (!canManage || archiveBusy.current) return;
    overlays.openModal({
      title: t(domain.is_archived ? "domain.archive.confirmRestoreTitle" : "domain.archive.confirmArchiveTitle", { domain: domain.fqdn }),
      body: <p>{t("domain.archive.explanation")}</p>,
      footer: <>
        <button type="button" className="sli-ds-button" onClick={overlays.closeModal}>{t("domain.archive.cancel")}</button>
        <button type="button" className="sli-ds-button" onClick={() => {
          if (archiveBusy.current) return;
          archiveBusy.current = true;
          overlays.closeModal();
          archive.mutate({ fqdn: domain.fqdn, archived: !domain.is_archived });
        }}>{t("domain.archive.confirm")}</button>
      </>,
    });
  };
  const code = add.error instanceof ApiResponseError ? add.error.code : undefined;
  const error = add.error ? new Error((code && Object.hasOwn(DOMAIN_ERRORS, code) ? t(DOMAIN_ERRORS[code]) : add.error.message)) : null;
  const form = canManage ? <form onSubmit={(event) => { event.preventDefault(); add.mutate(); }}>
      <div className="sli-ds-field"><label htmlFor="setup-domain-fqdn">{t("setup.domain.labelFqdn")}</label>
        <input id="setup-domain-fqdn" value={fqdn} onChange={(event) => setFqdn(event.target.value)} autoComplete="off" spellCheck={false} placeholder={t("setup.domain.fqdnPlaceholder")}/></div>
      <div className="sli-ds-field"><label htmlFor="setup-domain-netbios">{t("setup.domain.labelNetbios")}</label>
        <input id="setup-domain-netbios" value={netbios} onChange={(event) => setNetbios(event.target.value)} autoComplete="off" spellCheck={false} maxLength={15} placeholder={t("setup.domain.netbiosPlaceholder")}/></div>
      <FieldError error={error}/>
      {add.isSuccess ? <p className="sli-ds-header__subtitle" role="status">{t("setup.domain.added")}</p> : null}
      <div className="sli-ds-filters__actions">
        <button type="submit" className="sli-ds-button" disabled={!fqdn.trim() || add.isPending}>{add.isPending ? t("setup.domain.adding") : t("setup.domain.add")}</button>
      </div>
    </form> : null;
  return <>
    <p className="sli-ds-header__subtitle">{t("domain.archive.explanation")}</p>
    {archive.isError ? <p role="alert">{t("domain.archive.error")}</p> : null}
    {domains.length ? <table>
      <caption>{t("setup.domain.tableCaption")}</caption>
      <thead><tr><th scope="col">{t("setup.domain.colDomain")}</th><th scope="col">{t("setup.domain.colNetbios")}</th><th scope="col">{t("setup.domain.colForest")}</th><th scope="col">{t("setup.domain.colServers")}</th></tr></thead>
      <tbody>{domains.map((domain) => <tr key={domain.fqdn}>
        <td>{domain.fqdn}{domain.is_archived ? <span> · {t("domain.archive.label")} · {domain.observed_at_utc ? t("domain.archive.asOf", { date: formatDateTimeTz(domain.observed_at_utc, timeZone) }) : t("domain.archive.unknownDate")}</span> : null}{canManage ? <button type="button" role="switch" aria-checked={Boolean(domain.is_archived)} aria-label={t("domain.archive.toggleFor", { domain: domain.fqdn })} className="sli-ds-button" disabled={archive.isPending} onClick={() => confirmArchive(domain)}>{t(domain.is_archived ? "domain.archive.restore" : "domain.archive.archive")}</button> : null}</td><td>{domain.netbios_name ?? t("table.noValue")}</td><td>{domain.forest ?? t("table.noValue")}</td><td>{domain.server_count}</td>
      </tr>)}</tbody>
    </table> : null}
    {form && state === "done" ? <details><summary>{t("setup.domain.add")}</summary>{form}</details> : form}
  </>;
}

function SourceStates({ pack, instance }: { pack: SetupSource; instance?: SetupSourceInstance }) {
  const { formatDateTime } = useDateFormatters();
  const configured = instance ? instance.configured : pack.configured;
  const enabled = instance ? instance.enabled : pack.activation_state === undefined || pack.activation_state === "unavailable" ? null : pack.activation_state === "enabled";
  const dataState = instance ? instance.data_state : pack.data_state ?? "unavailable";
  const action = instance ? instance.next_action : pack.instances !== undefined ? pack.configured === false ? "configure" : "check_configuration" : null;
  const agentBacked = pack.collection_basis === "agents" || instance?.collection_state !== undefined;
  const destination = agentBacked ? "/agents" : pack.pack_id === "sli.windows.ad-dc" && action && ["enable", "configure", "check_configuration"].includes(action) ? "#setup-domain-controllers" : action && ["configure", "check_configuration", "enable"].includes(action) ? "/plugins" : "/operations";
  const name = `${setupSourceName(pack)}${instance ? `: ${instance.source_instance_id}` : ""}`;
  return <div role="group" aria-label={name} id={setupSourceAnchor(pack.pack_id, instance?.source_instance_id ?? null)}>
    {instance ? <h3 className="sli-ds-section-title">{name}</h3> : null}
    <FactList facts={[
      { label: t("setup.source.installation"), value: pack.installed === false ? t("setup.source.notInstalled") : t("setup.source.installed") },
      { label: t("setup.source.configuration"), value: configured == null ? t("setup.source.unknown") : configured ? t("setup.source.configured") : t("setup.source.notConfigured") },
      { label: t("setup.source.activation"), value: enabled == null ? t("setup.source.unknown") : enabled ? t("setup.source.enabled") : t("setup.source.disabled") },
      { label: t("setup.source.data"), value: instance?.collection_state ? instance.collection_state === "disabled" ? t("setup.agentSource.disabled") : agentCollectionLabel(instance.collection_state) : t(`setup.source.data.${dataState}`) },
      ...(instance?.last_data_utc && !agentBacked ? [{ label: t("setup.source.lastData"), value: formatDateTime(instance.last_data_utc) }] : []),
    ]}/>
    {agentBacked && instance?.last_data_utc ? <details><summary>{t("setup.source.technicalDetails")}</summary>
      <p>{t("setup.source.lastData")}: {formatDateTime(instance.last_data_utc)}</p>
    </details> : null}
    {action ? <p className="sli-ds-header__subtitle">{setupSourceAction(action, pack.pack_id, agentBacked)} <a href={destination.startsWith("#") ? destination : `/app${destination}`}>{setupDestinationLabel(destination)}</a></p> : null}
  </div>;
}

function SourcesStep({ sources }: { sources: SetupSource[] }) {
  return <>{sources.map((pack) => <div key={pack.pack_id}>
    <h3 className="sli-ds-section-title">{setupSourceName(pack)}</h3>
    <details><summary>{t("setup.source.technicalDetails")}</summary><code>{pack.pack_id} {pack.version}</code></details>
    {pack.instances?.length ? pack.instances.map((instance) => <SourceStates key={instance.source_instance_id} pack={pack} instance={instance}/>) : <SourceStates pack={pack}/>}
  </div>)}</>;
}

function ReportDomainStep({ domain }: { domain: NonNullable<SetupStatus["report_domain"]> }) {
  const access = useEffectiveAccess();
  const canManage = Boolean(access?.capabilities.includes("access.manage"));
  const queryClient = useQueryClient();
  const saving = useRef(false);
  const save = useMutation({
    mutationFn: (fqdn: string) => api.updatePlatformSetting("reports.domain_fqdn", fqdn),
    onSuccess: () => {
      return Promise.all(["setup-status", "platform-settings", "domains", "report-v2"].map((key) => queryClient.invalidateQueries({ queryKey: [key] })));
    },
    onSettled: () => { saving.current = false; },
  });
  const suggested = domain.suggested_value;
  return <>
    <FactList facts={[
      { label: t("setup.details.reportDomain"), value: domain.value || t("setup.details.notSet") },
      ...(domain.configured_value ? [{ label: t("domain.archive.configured"), value: domain.configured_value }] : []),
    ]}/>
    {canManage && suggested ? <button type="button" className="sli-ds-button" disabled={save.isPending || (save.isSuccess && save.variables === suggested)} onClick={() => {
      if (saving.current || (save.isSuccess && save.variables === suggested)) return;
      saving.current = true;
      save.mutate(suggested);
    }}>{t("domain.archive.useSuggested", { domain: suggested })}</button> : null}
    {save.isError ? <p role="alert">{t("domain.archive.saveError")}</p> : null}
    {save.isSuccess ? <p role="status">{t("platformSettings.saved")}</p> : null}
  </>;
}

function StepDetails({ id, state, status }: { id: string; state: SetupStep["state"]; status: SetupStatus }) {
  const { formatDateTime } = useDateFormatters();
  if (id === "report-domain" && status.report_domain) {
    return <ReportDomainStep domain={status.report_domain}/>;
  }
  if (id === "domains") return <DomainsStep domains={status.domains} state={state}/>;
  if (id === "domain-controllers") return <DomainControllersStep controllers={status.domain_controllers} domains={status.domains} agentInstances={status.agent_collection ? status.sources.find((pack) => pack.pack_id === "sli.windows.ad-dc")?.instances ?? [] : undefined}/>;
  if (id === "sources" && status.sources.length) {
    return <SourcesStep sources={status.sources}/>;
  }
  if (id === "first-collection" && status.agent_collection) {
    return <AgentCollectionDetails status={status}/>;
  }
  if (id === "first-collection" && status.collection) {
    return <><FactList facts={[
      { label: t("setup.details.collectionAllowed"), value: t(status.collection.collection_enabled == null ? "setup.source.unknown" : status.collection.collection_enabled ? "setup.details.yes" : "setup.details.no") },
      { label: t("setup.details.channels"), value: String(status.collection.channels) },
      ...(status.collection.last_success_utc ? [{ label: t("setup.details.lastSuccess"), value: formatDateTime(status.collection.last_success_utc) }] : []),
    ]}/>
      {!status.collection.collection_enabled ? <>
        <p>{t(status.collection.block_reason === "windows_event_log_access_denied" ? "setup.collectionBlock.accessDenied"
          : status.collection.block_reason === "windows_security_context_invalid" ? "setup.collectionBlock.securityContext" : "setup.collectionBlock.unknown")}</p>
        {status.collection.block_reason ? <details><summary>{t("setup.source.technicalDetails")}</summary><code>{status.collection.block_reason}</code></details> : null}
      </> : null}
    </>;
  }
  return null;
}


function AgentCollectionDetails({ status }: { status: SetupStatus }) {
  const { timeZone } = useTimeZone();
  const health = status.agent_collection!;
  return <>
    <p>{t("operations.agent_collection.count", { current: health.current_agents, total: health.active_agents })}</p>
    {health.items.map((agent) => <div key={agent.id}>
      <a href={agent.href}>{agentCollectionName(agent)}</a> — {agentCollectionSummary(agent, health.diagnostics)}
      <details><summary>{t("setup.source.technicalDetails")}</summary>
        <p>{agentCollectionDetail(agent, timeZone)}</p>
        {agentCollectionHistory(agent, timeZone).map((text, index) => <p key={index}>{text}</p>)}
      </details>
    </div>)}
    {health.completeness?.state === "known_gaps" ? <details><summary>{t("setup.source.technicalDetails")}</summary><p>{t("operations.agent_collection.accepted_loss")}</p></details> : null}
    <a href="/app/agents">{setupDestinationLabel("/agents")}</a>
  </>;
}

