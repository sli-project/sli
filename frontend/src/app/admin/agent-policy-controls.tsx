import { isValidTimeZone } from "../../shared/date-time";
import { useEffect, useState, type FormEvent } from "react";
import type { AgentItem } from "../../api/client";
import { t } from "../../i18n";

type ModulePolicy = Exclude<AgentItem["assigned_modules"][number], string>;
type Change = (kind: "modules" | "policy", body: Record<string, unknown>) => void;
const FAMILIES = ["logons", "processes", "usb", "local_admins", "protection"] as const;
const CHANNELS = ["Security", "System", "Directory Service"] as const;
const DEFAULTS = { state: "active" as const, interval_seconds: 60, batch_size: 32, rate_limit_per_minute: 120, spool_max_bytes: 67108864 };
const object = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const lines = (value: unknown) => Array.isArray(value) ? value.join("\n") : "";
const idsText = (value: unknown) => Array.isArray(value) ? value.join(", ") : "";
function ids(value: string) {
  if (!value.trim()) return [];
  const parts = value.split(",").map((part) => part.trim());
  if (parts.some((part) => !/^\d+$/.test(part) || Number(part) > 65535)) throw new Error("invalid");
  return [...new Set(parts.map(Number))];
}

export function AgentCollectionControls({ agent, busy, change }: { agent: AgentItem; busy: boolean; change: Change }) {
  const current = { ...DEFAULTS, ...agent.collection_policy };
  const [interval, setInterval] = useState(current.interval_seconds);
  const [batch, setBatch] = useState(current.batch_size);
  const [rate, setRate] = useState(current.rate_limit_per_minute);
  const [spool, setSpool] = useState(current.spool_max_bytes);
  const disabled = busy || agent.status !== "active";
  const stateText = (state: string) => t(state === "active" ? "agents.active" : state === "paused" ? "agents.paused" : state === "drain" ? "agents.draining" : "agents.noData");
  const save = (event: FormEvent) => {
    event.preventDefault();
    change("policy", { agent_id: agent.id, expected_revision: agent.policy_revision, collection_policy: {
      interval_seconds: interval, batch_size: batch, rate_limit_per_minute: rate, spool_max_bytes: spool } });
  };
  return <>
    <p>{t("agents.collectionStates", { desired: stateText(current.state === "drain" && agent.applied_policy_revision === agent.policy_revision && agent.applied_collection_state === "paused" ? "paused" : current.state), applied: stateText(agent.applied_collection_state ?? "unknown") })}</p>
    <details><summary>{t("agents.limits")}</summary><form onSubmit={save}><fieldset disabled={disabled}>
      <label>{t("agents.interval")}<input type="number" required min={1} max={86400} value={interval} onChange={(event) => setInterval(Number(event.target.value))}/></label>
      <label>{t("agents.batch")}<input type="number" required min={1} max={128} value={batch} onChange={(event) => setBatch(Number(event.target.value))}/></label>
      <label>{t("agents.rate")}<input type="number" required min={1} max={10000} value={rate} onChange={(event) => setRate(Number(event.target.value))}/></label>
      <label>{t("agents.spool")}<input type="number" required min={65536} max={1073741824} value={spool} onChange={(event) => setSpool(Number(event.target.value))}/></label>
      <button className="sli-ds-button" type="submit">{t("agents.saveLimits")}</button>
    </fieldset></form></details>
  </>;
}

function FilterControls({ settings, process, disabled, save, showDeny = true }: { settings: Record<string, unknown>; process: boolean; disabled: boolean; save: (settings: Record<string, unknown>) => void; showDeny?: boolean }) {
  const [allow, setAllow] = useState(idsText(settings.allow_event_ids));
  const [deny, setDeny] = useState(idsText(settings.deny_event_ids));
  const [allowPaths, setAllowPaths] = useState(lines(settings.allow_process_paths));
  const [denyPaths, setDenyPaths] = useState(lines(settings.deny_process_paths));
  const [error, setError] = useState(false);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    try {
      const paths = (value: string) => value.split("\n").map((part) => part.trim()).filter(Boolean);
      save({ allow_event_ids: allow.trim() ? ids(allow) : null, deny_event_ids: ids(deny),
        ...(process ? { allow_process_paths: paths(allowPaths), deny_process_paths: paths(denyPaths) } : {}) });
      setError(false);
    } catch { setError(true); }
  };
  return <form onSubmit={submit}><fieldset disabled={disabled}>
    <label>{t("agents.allowIds")}<input value={allow} onChange={(event) => setAllow(event.target.value)}/></label>
    {showDeny ? <label>{t("agents.denyIds")}<input value={deny} onChange={(event) => setDeny(event.target.value)}/></label> : null}
    {process ? <>
      <label>{t("agents.allowPaths")}<textarea value={allowPaths} onChange={(event) => setAllowPaths(event.target.value)}/></label>
      <label>{t("agents.denyPaths")}<textarea value={denyPaths} onChange={(event) => setDenyPaths(event.target.value)}/></label>
    </> : null}
    <p>{t("agents.filterHint")}</p>
    <button className="sli-ds-button" type="submit">{t("agents.saveFilters")}</button>
    {error ? <p role="alert">{t("agents.invalidPolicy")}</p> : null}
  </fieldset></form>;
}

function EventRateControls({ module, disabled, save }: { module: ModulePolicy; disabled: boolean; save: (settings: Record<string, unknown>) => void }) {
  const [rates, setRates] = useState(Object.entries(object(module.config.rate_limits)).map(([id, n]) => `${id}=${n}`).join(", "));
  const [window, setWindow] = useState(Number(module.config.rate_window_seconds ?? 60));
  const [error, setError] = useState(false);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    try {
      const result: Record<string, number> = {};
      for (const part of rates.trim() ? rates.split(",") : []) {
        const match = /^(\d+)\s*=\s*(\d+)$/.exec(part.trim());
        if (!match || Number(match[1]) > 65535 || Number(match[2]) > 1000000) throw new Error("invalid");
        result[String(Number(match[1]))] = Number(match[2]);
      }
      save({ rate_limits: result, rate_window_seconds: window }); setError(false);
    } catch { setError(true); }
  };
  return <form onSubmit={submit}><fieldset disabled={disabled}>
    <label>{t("agents.eventRates")}<input value={rates} onChange={(event) => setRates(event.target.value)}/></label>
    <label>{t("agents.rateWindow")}<input type="number" required min={1} max={86400} value={window} onChange={(event) => setWindow(Number(event.target.value))}/></label>
    <button className="sli-ds-button" type="submit">{t("agents.saveLimits")}</button>
    {error ? <p role="alert">{t("agents.invalidPolicy")}</p> : null}
  </fieldset></form>;
}

function SnapshotScheduleControls({ settings, disabled, save }: { settings: Record<string, unknown>; disabled: boolean; save: (settings: Record<string, unknown>) => void }) {
  const schedule = object(settings.schedule);
  const [timeZone, setTimeZone] = useState(String(schedule.timezone ?? "Asia/Novosibirsk"));
  const [hours, setHours] = useState(idsText(schedule.hours ?? [6, 18]));
  const [error, setError] = useState(false);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    try {
      const timezone = timeZone.trim();
      if (!isValidTimeZone(timezone)) throw new Error("invalid");
      const selected = ids(hours).sort((a, b) => a - b);
      if (!selected.length || selected.some((hour) => hour > 23)) throw new Error("invalid");
      save({ schedule: { timezone, hours: selected } });
      setError(false);
    } catch { setError(true); }
  };
  return <details><summary>{t("agents.snapshotSchedule")}</summary><form onSubmit={submit}><fieldset disabled={disabled}>
    <label>{t("agents.scheduleTimezone")}<input required value={timeZone} onChange={(event) => setTimeZone(event.target.value)}/></label>
    <label>{t("agents.scheduleHours")}<input required value={hours} onChange={(event) => setHours(event.target.value)}/></label>
    <p>{t("agents.scheduleHint")}</p>
    <button className="sli-ds-button" type="submit">{t("agents.saveSchedule")}</button>
    {error ? <p role="alert">{t("agents.invalidSchedule")}</p> : null}
  </fieldset></form></details>;
}

function DCInitialReadControls({ settings, disabled, save, backfill }: { settings: Record<string, unknown>; disabled: boolean; save: (settings: Record<string, unknown>) => void; backfill: () => void }) {
  const [all, setAll] = useState(settings.initial_read_hours === "all");
  const [hours, setHours] = useState(Number(settings.initial_read_hours === "all" ? 24 : settings.initial_read_hours ?? 24));
  return <>
    <form onSubmit={(event) => { event.preventDefault(); save({ initial_read_hours: all ? "all" : hours }); }}><fieldset disabled={disabled}>
      <label><input type="checkbox" checked={all} onChange={(event) => setAll(event.target.checked)}/>{t("agents.initialReadAll")}</label>
      <label>{t("agents.initialReadHours")}<input type="number" required min={0} max={876000} step={1} disabled={all} value={hours} onChange={(event) => setHours(Number(event.target.value))}/></label>
      <p>{t("agents.initialReadHint")}</p>
      <button className="sli-ds-button" type="submit">{t("agents.saveInitialRead")}</button>
    </fieldset></form>
    <button className="sli-ds-button" type="button" disabled={disabled} onClick={backfill}>{t("agents.backfillDc")}</button>
    <p>{t("agents.backfillDcHint")}</p>
  </>;
}

function PasswordDetectionDomainControls({ agent, disabled, change }: { agent: AgentItem; disabled: boolean; change: Change }) {
  const mapping = agent.password_detection_domain;
  const [fqdn, setFqdn] = useState(mapping?.domain_fqdn ?? "");
  const bound = mapping?.domain_id != null;
  const available = Boolean(mapping && (mapping.status === "unconfigured" && mapping.domain_id === null && mapping.domain_fqdn === null
    || mapping.status === "configured" && Number.isSafeInteger(mapping.domain_id) && Number(mapping.domain_id) > 0
      && typeof mapping.domain_fqdn === "string" && mapping.domain_fqdn.length > 0));
  useEffect(() => { setFqdn(mapping?.domain_fqdn ?? ""); },
    [agent.id, agent.policy_revision, mapping?.status, mapping?.domain_id, mapping?.domain_fqdn]);
  const blocked = disabled || !available;
  return <form onSubmit={(event) => {
    event.preventDefault();
    if (blocked || !fqdn.trim() || bound && fqdn !== mapping?.domain_fqdn) return;
    change("modules", { agent_id: agent.id, module_id: "sli.windows.ad-dc", expected_revision: agent.policy_revision,
      password_detection_domain: { fqdn: fqdn.trim(), expected_domain_id: mapping!.domain_id } });
  }}><fieldset disabled={blocked}>
    <label>{t("agents.passwordDomain.fqdn")}<input required maxLength={253} value={fqdn} readOnly={bound}
      onChange={(event) => setFqdn(event.target.value)}/></label>
    <p>{t(!available ? "agents.passwordDomain.unavailable" : bound ? "agents.passwordDomain.configured" : "agents.passwordDomain.unconfigured")}</p>
    <button className="sli-ds-button" type="submit" disabled={blocked || !fqdn.trim()}>{t("agents.passwordDomain.save")}</button>
  </fieldset></form>;
}

export function AgentModuleControls({ agent, module, busy, change }: { agent: AgentItem; module: ModulePolicy; busy: boolean; change: Change }) {
  const disabled = busy || agent.status !== "active" || !module.enabled;
  const save = (settings: Record<string, unknown>) => change("modules", { agent_id: agent.id, module_id: module.module_id, enabled: module.enabled,
    config: { ...module.config, ...settings }, expected_revision: agent.policy_revision });
  if (module.module_id === "sli.ad-snapshot" || module.module_id === "sli.gpo-snapshot") {
    return <SnapshotScheduleControls settings={module.config} disabled={busy || agent.status !== "active"} save={save}/>;
  }
  if (module.module_id === "sli.workstations") {
    const families = object(module.config.families);
    const filters = object(module.config.family_filters);
    return <details><summary>{t("agents.familySettings")}</summary>
      {FAMILIES.map((family) => <fieldset key={family}><legend>{t(`agents.family.${family}`)}</legend>
        <label><input type="checkbox" checked={families[family] !== false} disabled={disabled} onChange={() => save({ families: { ...families, [family]: families[family] === false } })}/>{t(`agents.family.${family}`)}</label>
        <FilterControls settings={object(filters[family])} process={family === "processes"} disabled={disabled} save={(settings) => save({ family_filters: { ...filters, [family]: settings } })}/>
      </fieldset>)}
      <EventRateControls module={module} disabled={disabled} save={save}/>
    </details>;
  }
  if (module.module_id === "sli.windows.ad-dc") {
    const channels = object(module.config.channels);
    return <details><summary>{t("agents.channelSettings")}</summary>
      <PasswordDetectionDomainControls agent={agent} disabled={disabled} change={change}/>
      {CHANNELS.map((channel) => <label key={channel}><input type="checkbox" checked={channels[channel] !== false} disabled={disabled} onChange={() => save({ channels: { ...channels, [channel]: channels[channel] === false } })}/>{channel}</label>)}
      <DCInitialReadControls settings={module.config} disabled={disabled} save={save} backfill={() => {
        const generation = crypto.randomUUID();
        change("modules", { agent_id: agent.id, module_id: "sli.windows.ad-dc-history", enabled: true, expected_revision: agent.policy_revision,
          config: { ...module.config, initial_read_hours: "all", batch_size: 4, history_before_utc: new Date().toISOString(),
            channel_generations: Object.fromEntries(CHANNELS.map((channel) => [channel, generation])) } });
      }}/>
      <FilterControls settings={module.config} process={false} disabled={disabled} showDeny={false} save={({ allow_event_ids }) => save({ allow_event_ids })}/>
      <p>{t("agents.dcPackHint")}</p>
    </details>;
  }
  return null;
}
