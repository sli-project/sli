import { useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type AgentSequenceGap, type AgentSequenceRecoveryPreview } from "../../api/client";
import { t } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
import { agentModuleName } from "./agent-actions";
import { recoveryRange, validRecoveryPreview } from "./agent-sequence-recovery-model";

type Props = { agentId: string; hostName: string; canRecover: boolean; active: boolean; timeZone: string };
export function AgentSequenceRecovery(props: Props) {
  return props.canRecover ? <RecoveryDisclosure key={props.agentId} {...props}/> : null;
}
function RecoveryDisclosure(props: Props) {
  const [open, setOpen] = useState(false);
  const [locked, setLocked] = useState(false);
  const id = `agent-sequence-recovery-${props.agentId}`;
  return <div id={id}>
    <button type="button" className="sli-ds-button" disabled={locked} aria-expanded={open} aria-controls={`${id}-content`} onClick={() => setOpen(!open)}>{t("agents.sequenceRecovery.title")}</button>
    {open ? <div id={`${id}-content`}><RecoveryRecords {...props} locked={locked} setLocked={setLocked}/></div> : null}
  </div>;
}
function RecoveryRecords({ agentId, hostName, active, timeZone, locked, setLocked }: Props & { locked: boolean; setLocked: (value: boolean) => void }) {
  const [revision, setRevision] = useState(0);
  const query = useQuery({ queryKey: ["agent-sequence-recovery", agentId], queryFn: () => api.agentSequenceRecovery(agentId), retry: false, refetchOnWindowFocus: false, refetchOnReconnect: false });
  const gaps = query.data?.gaps;
  const preview = query.data?.recovery_preview;
  const valid = Array.isArray(gaps) && new Set(gaps.map((gap) => gap?.id)).size === gaps.length && gaps.every((gap) => gap && gap.agent_id === agentId && typeof gap.id === "string" && gap.id.length > 0
    && typeof gap.module_id === "string" && ["pending", "authorized", "accepted"].includes(gap.status) && recoveryRange(gap)) && validRecoveryPreview(preview, agentId);
  const reload = () => { setRevision((value) => value + 1); void query.refetch(); };
  if (query.isFetching) return <p role="status">{t("agents.sequenceRecovery.loading")}</p>;
  if (query.isError || !gaps || !preview || !valid) return <><p role="alert">{t("agents.sequenceRecovery.unavailable")}</p><button type="button" className="sli-ds-button" disabled={locked} onClick={reload}>{t("agents.sequenceRecovery.reload")}</button></>;
  const previewIds = new Set(preview.observation_ids);
  return <>
    <button type="button" className="sli-ds-button" disabled={locked} onClick={reload}>{t("agents.sequenceRecovery.reload")}</button>
    {query.data?.truncated ? <p role="status">{t("agents.sequenceRecovery.truncated")}</p> : null}
    <RecoveryBatch key={`${revision}:${JSON.stringify(preview)}`} preview={preview} hostName={hostName} active={active} timeZone={timeZone} locked={locked} setLocked={setLocked}/>
    {gaps.filter((gap) => !previewIds.has(gap.id)).map((gap) => <RecoveryRecord key={gap.id} gap={gap} timeZone={timeZone}/>)}
  </>;
}
function RecoveryBatch({ preview, hostName, active, timeZone, locked, setLocked }: { preview: AgentSequenceRecoveryPreview; hostName: string; active: boolean; timeZone: string; locked: boolean; setLocked: (value: boolean) => void }) {
  const client = useQueryClient();
  const [review, setReview] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [failed, setFailed] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const submitting = useRef(false);
  if (!preview.streams.length) return <p>{t("agents.sequenceRecovery.noEligible")}</p>;
  const submit = async () => {
    if (locked || failed || !confirmed || !active || authorized || submitting.current) return;
    submitting.current = true; setLocked(true);
    try {
      const result = await api.acceptAgentSequenceGap(preview.agent_id, [...preview.observation_ids], preview.preview_token);
      if (result.status !== "authorized" || result.preview_token !== preview.preview_token || result.agent_id !== preview.agent_id || !Array.isArray(result.observation_ids)
        || result.observation_ids.length !== preview.observation_ids.length || new Set(result.observation_ids).size !== preview.observation_ids.length
        || result.observation_ids.some((id) => !preview.observation_ids.includes(id))) throw new Error("unconfirmed_recovery");
      setAuthorized(true); setReview(false); setConfirmed(false);
      void client.invalidateQueries({ queryKey: ["admin-agents"] });
    } catch { setFailed(true); setConfirmed(false); }
    finally { submitting.current = false; setLocked(false); }
  };
  return <section aria-label={t("agents.sequenceRecovery.batchTitle")}>
    <h4>{t("agents.sequenceRecovery.batchTitle")}</h4>
    {preview.streams.map((gap) => <RecoveryRecord key={gap.id} gap={gap} timeZone={timeZone}/>)}
    {authorized ? <p role="status">{t("agents.sequenceRecovery.authorized")}</p> : !active ? <p>{t("agents.sequenceRecovery.inactive")}</p>
      : review ? <form onSubmit={(event) => { event.preventDefault(); void submit(); }}>
        <p>{t("agents.sequenceRecovery.confirm", { host: hostName })}</p>
        <label><input type="checkbox" checked={confirmed} disabled={locked || failed} onChange={(event) => setConfirmed(event.target.checked)}/>{t("agents.sequenceRecovery.consent")}</label>
        <button type="submit" className="sli-ds-button" disabled={!confirmed || locked || failed}>{t("agents.sequenceRecovery.accept")}</button>
        <button type="button" className="sli-ds-button" disabled={locked} onClick={() => { setReview(false); setConfirmed(false); }}>{t("agents.cancel")}</button>
      </form> : <button type="button" className="sli-ds-button" disabled={locked || failed} onClick={() => setReview(true)}>{t("agents.sequenceRecovery.review")}</button>}
    {failed ? <p role="alert">{t("agents.sequenceRecovery.failed")}</p> : null}
  </section>;
}
function RecoveryRecord({ gap, timeZone }: { gap: AgentSequenceGap; timeZone: string }) {
  const date = (value: string | null) => formatDateTime(value, timeZone);
  return <section aria-label={agentModuleName(gap.module_id)}>
    <h4>{agentModuleName(gap.module_id)}</h4>
    <p>{t("agents.sequenceRecovery.range", recoveryRange(gap)!)}</p>
    <p>{t("agents.sequenceRecovery.observed", { date: date(gap.observed_at) })}</p>
    <p>{t("agents.sequenceRecovery.unknown")}</p>
    <details><summary>{t("agents.sequenceRecovery.details")}</summary><p>{t("agents.sequenceRecovery.boundaries", { before: date(gap.previous_observed_at), after: date(gap.packet_observed_at) })}</p><p>{t("agents.sequenceRecovery.identifiers", { observation: gap.id, module: gap.module_id })}</p></details>
    {gap.status === "authorized" ? <p>{t("agents.sequenceRecovery.streamAuthorized")}</p> : gap.status === "accepted" ? <p>{t("agents.sequenceRecovery.accepted")}</p> : null}
  </section>;
}
