import { formatDateTime } from "../shared/date-time";
import { useMemo, useState } from "react";
import type { V4ObjectDetail } from "../api/client";
import { Badge, Callout, EmptyState } from "../design-system";
import { stateTone } from "../shared/state-tone";
import { t } from "../i18n";
import { useTimeZone } from "./App";

type EntityCardTab = "overview" | "relations" | "states" | "findings" | "technical";

const typeLabels = (): Record<string, string> => ({
  ad_user: t("entities.overlay.typeLabel.adUser"),
  ad_computer: t("entities.overlay.typeLabel.adComputer"),
  ad_group: t("entities.overlay.typeLabel.adGroup"),
  gpo: t("entities.overlay.typeLabel.gpo"),
  person: t("entities.overlay.typeLabel.person"),
});

const fieldLabels = (): Record<string, string> => ({
  distinguished_name: t("entities.overlay.fieldLabel.distinguishedName"),
  sam_account_name: t("entities.overlay.fieldLabel.samAccountName"),
  user_principal_name: t("entities.overlay.fieldLabel.userPrincipalName"),
  display_name: t("entities.overlay.fieldLabel.displayName"),
  department: t("entities.overlay.fieldLabel.department"),
  title: t("entities.overlay.fieldLabel.title"),
  mail: t("entities.overlay.fieldLabel.mail"),
  enabled: t("entities.overlay.fieldLabel.enabled"),
  locked: t("entities.overlay.fieldLabel.locked"),
  locked_out: t("entities.overlay.fieldLabel.lockedOut"),
  password_never_expires: t("entities.overlay.fieldLabel.passwordNeverExpires"),
  password_last_set_utc: t("entities.overlay.fieldLabel.passwordLastSetUtc"),
  account_expiration_utc: t("entities.overlay.fieldLabel.accountExpirationUtc"),
  inactive_threshold_days: t("entities.overlay.fieldLabel.inactiveThresholdDays"),
  last_logon_utc: t("entities.overlay.fieldLabel.lastLogonUtc"),
  is_inactive: t("entities.overlay.fieldLabel.isInactive"),
  object_class: t("entities.overlay.fieldLabel.objectClass"),
  dns_host_name: t("entities.overlay.fieldLabel.dnsHostName"),
  operating_system: t("entities.overlay.fieldLabel.operatingSystem"),
  operating_system_version: t("entities.overlay.fieldLabel.operatingSystemVersion"),
  owner: t("entities.overlay.fieldLabel.owner"),
  purpose: t("entities.overlay.fieldLabel.purpose"),
});

const formatValue = (value: unknown): string => {
  if (value === null || value === undefined || value === "") return t("entities.overlay.undefined");
  if (typeof value === "boolean") return value ? t("entities.overlay.yes") : t("entities.overlay.no");
  if (Array.isArray(value)) return value.map(formatValue).join(" · ");
  if (typeof value === "object") {
    return Object.entries(value as Record<string, unknown>)
      .map(([key, item]) => `${fieldLabels()[key] ?? key.replaceAll("_", " ")}: ${formatValue(item)}`)
      .join(" · ");
  }
  return String(value);
};

const dateTime = (value: string | null | undefined, timeZone: string): string => {
  return formatDateTime(value, timeZone, { seconds: true });
};

export function availableEntityCardTabs(data: V4ObjectDetail): EntityCardTab[] {
  const allowed = new Set(data.tabs.filter((item) => item.available).map((item) => item.id));
  const tabs: EntityCardTab[] = ["overview"];
  if (allowed.has("groups") || allowed.has("privileges")) tabs.push("relations");
  if (allowed.has("states")) tabs.push("states");
  if (allowed.has("findings")) tabs.push("findings");
  if (allowed.has("technical")) tabs.push("technical");
  return tabs;
}

function ProfileFields({ data }: { data: V4ObjectDetail }) {
  const profile = Object.assign(
    {},
    ...(data.directory_context.items ?? [])
      .filter((item) => item.context_kind === "entity")
      .map((item) => typeof item.attributes === "object" && item.attributes ? item.attributes : {}),
  ) as Record<string, unknown>;
  const fields = Object.entries(profile)
    .filter(([key, value]) => !["record_key", "inactive_threshold_days"].includes(key) && value !== null && value !== undefined && value !== "")
    .slice(0, 16);
  return <div className="sli-ds-entity__fields">
    <div><dt>{t("entities.overlay.type")}</dt><dd>{typeLabels()[data.object.object_type] ?? data.object.object_type.replaceAll("_", " ")}</dd></div>
    <div><dt>{t("entities.overlay.internalId")}</dt><dd className="sli-ds-mono">{data.object.object_id}</dd></div>
    {fields.map(([key, value]) => <div key={key}><dt>{fieldLabels()[key] ?? key.replaceAll("_", " ")}</dt><dd>{formatValue(value)}</dd></div>)}
  </div>;
}

export function EntityCardView({ data }: { data: V4ObjectDetail }) {
  const { timeZone } = useTimeZone();
  const tabs = useMemo(() => availableEntityCardTabs(data), [data]);
  const [tab, setTab] = useState<EntityCardTab>("overview");
  const context = data.directory_context.items ?? [];
  const relations = [
    ...data.identity_links,
    ...context.filter((item) => item.context_kind === "relation"),
  ];
  return <div className="sli-ds-entity">
    <section className="sli-ds-entity__summary">
      <div>
        <div className="sli-ds-list__actions">
          <Badge tone="accent">{typeLabels()[data.object.object_type] ?? data.object.object_type.replaceAll("_", " ")}</Badge>
          <Badge tone={stateTone(data.object.latest_state?.status)}>{formatValue(data.object.latest_state?.status ?? data.state)}</Badge>
        </div>
        {data.object.natural_key ? <div className="sli-ds-mono">{data.object.natural_key}</div> : null}
      </div>
      <dl>
        <div><dt>{t("entities.overlay.firstSeen")}</dt><dd>{dateTime(data.object.first_seen_utc, timeZone)}</dd></div>
        <div><dt>{t("entities.overlay.lastSeen")}</dt><dd>{dateTime(data.object.last_seen_utc, timeZone)}</dd></div>
      </dl>
    </section>
    {data.provenance.length ? <section className="sli-ds-entity__provenance" aria-label={t("entities.overlay.provenanceAria")}>
      {data.provenance.map((item) => <article key={`${item.source}:${item.observed_at_utc ?? ""}`}>
        <strong>{item.source}</strong>
        <span>{dateTime(item.observed_at_utc, timeZone)}</span>
        <Badge tone={stateTone(item.freshness)}>{item.freshness}</Badge>
      </article>)}
    </section> : null}
    <div className="sli-ds-tabs" role="tablist" aria-label={t("entities.overlay.tabsAria")}>
      {tabs.map((item) => <button type="button" role="tab" aria-selected={tab === item} key={item} onClick={() => setTab(item)}>
        {item === "overview" ? t("entities.overlay.tab.overview") : item === "relations" ? t("entities.overlay.tab.relations") : item === "states" ? t("entities.overlay.tab.states") : item === "findings" ? t("entities.overlay.tab.findings") : t("entities.overlay.tab.technical")}
      </button>)}
    </div>
    {tab === "overview" ? <section><h3>{t("entities.overlay.profileTitle")}</h3><ProfileFields data={data}/></section> : null}
    {tab === "relations" ? <section><h3>{t("entities.overlay.relationsTitle")}</h3>{relations.length
      ? <div className="sli-ds-entity__list">{relations.map((item, index) => <article key={String(item.context_evidence_id ?? item.source_entity_id ?? index)}><strong>{formatValue(item.relation_type ?? item.source_section ?? t("entities.overlay.relationFallback"))}</strong><span>{formatValue(item.target_object_id ?? item.related_entity_id ?? item.target_entity_id)}</span><small>{formatValue(item.source_name ?? item.source_pack_id ?? item.observed_at_utc)}</small></article>)}</div>
      : <EmptyState title={t("entities.overlay.relationsEmptyTitle")} copy={t("entities.overlay.relationsEmptyCopy")} icon="link"/>}</section> : null}
    {tab === "states" ? <section><h3>{t("entities.overlay.statesTitle")}</h3>{data.current_states.length
      ? <div className="sli-ds-entity__list">{data.current_states.map((item, index) => <article key={String(item.id ?? index)}><div className="sli-ds-list__actions"><strong>{formatValue(item.state_type ?? item.summary ?? t("entities.overlay.stateFallback"))}</strong><Badge tone={stateTone(item.status)}>{formatValue(item.status)}</Badge></div><span>{formatValue(item.summary)}</span><small>{dateTime(String(item.observed_at_utc ?? ""), timeZone)}</small></article>)}</div>
      : <EmptyState title={t("entities.overlay.statesEmptyTitle")} copy={t("entities.overlay.statesEmptyCopy")} icon="layers"/>}</section> : null}
    {tab === "findings" ? <section><h3>{t("entities.overlay.findingsTitle")}</h3>{data.findings.length
      ? <div className="sli-ds-entity__list">{data.findings.map((item, index) => <article key={String(item.id ?? index)}><div className="sli-ds-list__actions"><strong>{formatValue(item.title ?? t("entities.overlay.findingFallback"))}</strong><Badge tone={stateTone(item.severity)}>{formatValue(item.severity)}</Badge></div><span>{formatValue(item.summary)}</span><small>{formatValue(item.status)}</small></article>)}</div>
      : <EmptyState title={t("entities.overlay.findingsEmptyTitle")} copy={t("entities.overlay.findingsEmptyCopy")} icon="warning"/>}</section> : null}
    {tab === "technical" ? <section><h3>{t("entities.overlay.technicalTitle")}</h3>{context.length
      ? <div className="sli-ds-entity__list">{context.map((item, index) => <article key={String(item.context_evidence_id ?? index)}><strong>{formatValue(item.source_section ?? item.context_kind)}</strong><span>{formatValue(item.attributes)}</span><small>{formatValue(item.source_pack_id)} · evidence {formatValue(item.context_evidence_id)}</small></article>)}</div>
      : <EmptyState title={t("entities.overlay.technicalEmptyTitle")} copy={t("entities.overlay.technicalEmptyCopy")} icon="code"/>}</section> : null}
    {data.limitations.length ? <Callout title={t("entities.overlay.limitationsTitle")}>{data.limitations.join(" · ")}</Callout> : null}
  </div>;
}
