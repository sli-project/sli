import { t } from "../i18n";
import type { VpnSessionEvidence } from "../api/client";
import { Badge, Callout, EmptyState } from "../design-system";
import { vpnSessionDurationText, vpnSessionLifecycleText } from "./vpn-session-text";

/** Drill-down of one VPN Accounting session: lifecycle and source observations. */
export function VpnSessionEvidenceView({ evidence, formatTime }: {
  evidence: VpnSessionEvidence;
  formatTime: (value: string | null | undefined) => string;
}) {
  if (evidence.state === "not_authorized") {
    return <Callout icon="lock" title={t("vpn.evidence.unauthorized.title")}>{evidence.branch.reason || t("vpn.evidence.unauthorized.text")}</Callout>;
  }
  const lifecycle = evidence.lifecycle;
  if (!lifecycle) return <EmptyState title={t("vpn.evidence.notFound.title")} copy={t("vpn.evidence.notFound.text")} icon="warning"/>;
  const stopped = Boolean(lifecycle.stopped_at_utc) && lifecycle.stop_evidence.length > 0;
  return <div className="sli-ds-entity">
    <dl className="sli-ds-facts">
      <div><dt>{t("vpn.evidence.fact.state")}</dt><dd><Badge tone={lifecycle.lifecycle_state === "closed" ? "success" : "warning"}>{vpnSessionLifecycleText(lifecycle.lifecycle_state)}</Badge></dd></div>
      <div><dt>{t("vpn.evidence.fact.completeness")}</dt><dd>{lifecycle.completeness}{lifecycle.incomplete_reason ? ` · ${lifecycle.incomplete_reason}` : ""}</dd></div>
      <div><dt>Start</dt><dd>{formatTime(lifecycle.started_at_utc)}</dd></div>
      <div><dt>{t("vpn.evidence.fact.lastObserved")}</dt><dd>{formatTime(lifecycle.last_observed_at_utc)}</dd></div>
      <div><dt>Stop</dt><dd>{stopped ? formatTime(lifecycle.stopped_at_utc) : t("vpn.evidence.fact.unconfirmedStop")}</dd></div>
      {stopped ? <div><dt>{t("vpn.evidence.fact.duration")}</dt><dd>{vpnSessionDurationText(lifecycle.duration_seconds)}</dd></div> : null}
      {lifecycle.anomalies.length ? <div><dt>{t("vpn.evidence.fact.anomalies")}</dt><dd>{lifecycle.anomalies.join(", ")}</dd></div> : null}
    </dl>
    {!stopped ? <Callout icon="warning" title={t("vpn.evidence.noStop.title")}>{t("vpn.evidence.noStop.text")}</Callout> : null}
    <section>
      <h3 className="sli-ds-section-title">{t("vpn.evidence.observations.title")}</h3>
      {evidence.observations.length ? <div className="sli-ds-list">{evidence.observations.map((obs) => <div className="sli-ds-list__item" key={obs.observation_id}><div><div className="sli-ds-list__title">{obs.lifecycle_event}</div><div className="sli-ds-list__copy">{formatTime(obs.observed_at_utc)}</div><div className="sli-ds-list__meta"><span className="sli-ds-mono">{obs.evidence.source_instance_id}</span><span className="sli-ds-mono">{obs.evidence.stream_id}</span></div></div><div className="sli-ds-list__meta sli-ds-mono">{obs.evidence.object_reference}<br/>{obs.evidence.object_sha256.slice(0, 16)}…</div></div>)}</div> : <div className="sli-ds-note">{t("vpn.evidence.observations.empty")}</div>}
    </section>
    {evidence.limits?.bounded ? <p className="sli-ds-note">{t("vpn.evidence.observations.limit", { limit: evidence.limits.observation_limit })}</p> : null}
  </div>;
}
