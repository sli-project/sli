import { EMPTY_VALUE } from "../shared/format";
import { useMemo, useState, type FormEvent } from "react";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ApiResponseError, api, type CompletenessSnapshot, type SemanticAction, type SemanticCalibrationWorkspace, type SemanticScenario, type SemanticScenarioReview } from "../api/client";
import { ConfidenceBadge, RiskBadge } from "../components/badges/Badges";
import { formatDateTime } from "../shared/date-time";
import { DateTime } from "../components/date-time/DateTime";
import { DataTable, FactList, PageHeader, StateView, type ResultState, type TableColumn } from "../design-system";
import { useTimeZone } from "./App";
import { подписьВывода, причинаНеполноты, разборПолноты, type СостояниеВывода } from "./conclusion-state";
import { представлениеОпознания } from "./identity-resolution";
import { statusLabel } from "./status-labels";
import { t } from "../i18n";
import { SigmaRulesPanel } from "./sigma-rules";

type SemanticView = "scenarios" | "actions" | "calibration" | "sigma";
type Tone = "success" | "warning" | "danger" | "accent" | undefined;
type QueryLike = { isError: boolean; error: unknown; refetch: () => unknown };

/** Минимальная длина обоснования оценки: совпадает с ограничением поля и серверной проверкой. */
export const MIN_REVIEW_RATIONALE_LENGTH = 5;

function getReviewVerdicts() {
  return [
    { value: "confirmed_security" as const, label: t("security.scenarios.verdict.confirmed"), optionLabel: t("security.scenarios.verdict.confirmed.option") },
    { value: "false_positive" as const, label: t("security.scenarios.verdict.false_positive"), optionLabel: t("security.scenarios.verdict.false_positive.option") },
    { value: "benign_expected" as const, label: t("security.scenarios.verdict.benign"), optionLabel: t("security.scenarios.verdict.benign.option") },
    { value: "insufficient_evidence" as const, label: t("security.scenarios.verdict.insufficient"), optionLabel: t("security.scenarios.verdict.insufficient.option") },
  ];
}

function reviewVerdictLabel(value: SemanticScenarioReview["verdict"]) {
  return getReviewVerdicts().find((item) => item.value === value)?.label ?? value;
}

export function scenarioResultLabel(value: SemanticScenario["result_class"]) {
  if (value === "security_incident") return t("security.scenarios.result.incident");
  if (value === "security_exposure") return t("security.scenarios.result.exposure");
  return t("security.scenarios.result.gap");
}

export function coverageLabel(value: SemanticScenario["coverage_status"]) {
  if (value === "complete") return t("security.scenarios.coverage.complete");
  if (value === "partial") return t("security.scenarios.coverage.partial");
  if (value === "unavailable") return t("security.scenarios.coverage.unavailable");
  return t("security.scenarios.coverage.unknown");
}

export function scenarioExecutionLabel(value: string) {
  if (value === "active") return t("security.scenarios.execution.active");
  if (value === "enabled_without_worker") return t("security.scenarios.execution.enabled_no_worker");
  if (value === "partially_enabled") return t("security.scenarios.execution.partially_enabled");
  return t("security.scenarios.execution.disabled");
}

export function actionStatusLabel(value: SemanticAction["status"]) {
  const labels: Record<SemanticAction["status"], import("../i18n").MessageKey> = {
    observed: "security.scenarios.action.observed", partially_confirmed: "security.scenarios.action.partially_confirmed",
    state_confirmed: "security.scenarios.action.state_confirmed", multi_source_confirmed: "security.scenarios.action.multi_source_confirmed",
    contradicted: "security.scenarios.action.contradicted", superseded: "security.scenarios.action.superseded", quarantined: "security.scenarios.action.quarantined",
  };
  return t(labels[value]);
}

/** Ошибка чтения: отказ в правах и недоступность различаются, пустым срез не считается. */
function readFailureState(error: unknown): ResultState {
  return error instanceof ApiResponseError && (error.status === 401 || error.status === 403) ? "denied" : "unavailable";
}

const CONCLUSION_TONE: Record<"good" | "bad" | "warn", Tone> = { good: "success", bad: "warning", warn: undefined };
const IDENTITY_TONE: Record<"good" | "warn" | "bad", Tone> = { good: "success", warn: "warning", bad: "danger" };

function ConclusionBadge({ value }: { value: СостояниеВывода | undefined }) {
  const подпись = подписьВывода(value);
  return <span className="sli-ds-badge" data-tone={CONCLUSION_TONE[подпись.тон]} title={подпись.пояснение}>{подпись.заголовок}</span>;
}

function IdentityResolutionBadge({ factors }: { factors: Record<string, unknown> | undefined }) {
  const view = представлениеОпознания(factors);
  return <span className="sli-ds-badge" data-tone={IDENTITY_TONE[view.тон]} title={view.пояснение}>{view.подпись}</span>;
}

/**
 * Четыре измерения полноты в уже принятом на карточке события шаблоне
 * раскрытия. Раскрытие, а не постоянный блок: подробность нужна, когда вывод
 * не состоялся, и мешает, когда состоялся.
 */
function CompletenessDisclosure({ state, snapshot }: { state: СостояниеВывода | undefined; snapshot: CompletenessSnapshot | undefined }) {
  const { timeZone } = useTimeZone();
  const измерения = разборПолноты(snapshot);
  const неполные = измерения.filter((измерение) => измерение.состояние !== "полно").length;
  return <details open={state === "not_checked"}>
    <summary>{t("security.scenarios.completeness.summary")} <small>{неполные ? t("security.scenarios.completeness.title.partial", { count: неполные }) : t("security.scenarios.completeness.title.all")}</small></summary>
    <p className="sli-ds-header__subtitle">{причинаНеполноты(snapshot)}</p>
    <FactList facts={измерения.map((измерение) => ({
      label: измерение.название,
      value: <><span className="sli-ds-badge" data-tone={измерение.состояние === "полно" ? "success" : измерение.состояние === "неполно" ? "warning" : undefined}>{измерение.состояние === "полно" ? t("security.scenarios.completeness.complete") : измерение.состояние === "неполно" ? t("security.scenarios.completeness.incomplete") : t("security.scenarios.completeness.unmeasured")}</span> <small>{измерение.подробность}</small></>,
    }))}/>
    {snapshot?.captured_at_utc ? <p className="sli-ds-header__subtitle">{t("security.scenarios.completeness.snapshot", { time: formatDateTime(snapshot.captured_at_utc, timeZone) })}</p> : null}
  </details>;
}

function ScenarioReviewPanel({ scenario, schemaReady }: { scenario: SemanticScenario; schemaReady: boolean }) {
  const queryClient = useQueryClient();
  const [verdict, setVerdict] = useState<SemanticScenarioReview["verdict"]>("insufficient_evidence");
  const [confidence, setConfidence] = useState<SemanticScenarioReview["review_confidence"]>("medium");
  const [rationale, setRationale] = useState("");
  const [validation, setValidation] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const review = useMutation({
    mutationFn: () => api.reviewSemanticScenario(scenario.scenario_id, {
      review_request_id: crypto.randomUUID(), verdict, review_confidence: confidence, rationale,
    }),
    onMutate: () => setSaved(false),
    onSuccess: async () => {
      setRationale("");
      // Список перечитывается, чтобы «последняя оценка» пришла с сервера, а не из формы.
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["semantic-scenarios"] }),
        queryClient.invalidateQueries({ queryKey: ["semantic-calibration"] }),
      ]);
      setSaved(true);
    },
  });
  const disabled = !schemaReady || review.isPending;
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!schemaReady || review.isPending) return;
    if (rationale.trim().length < MIN_REVIEW_RATIONALE_LENGTH) {
      setValidation(t("security.scenarios.review.rationale_length", { min: MIN_REVIEW_RATIONALE_LENGTH }));
      return;
    }
    setValidation(null);
    review.mutate();
  };
  const id = `review-${scenario.scenario_id}`;
  return <section className="sli-ds-widget" aria-label={t("security.scenarios.review.aria_label", { title: scenario.title })}>
    <div className="sli-ds-widget__head">
      <h3 className="sli-ds-widget__title">{scenario.title}</h3>
      <span><IdentityResolutionBadge factors={scenario.confidence_factors}/> <span className="sli-ds-badge">{t("security.scenarios.review.count", { count: scenario.review_count })}</span></span>
    </div>
    <p className="sli-ds-header__subtitle">{scenario.latest_review ? `${reviewVerdictLabel(scenario.latest_review.verdict)} · ${scenario.latest_review.reviewed_by}` : t("security.scenarios.review.unreviewed")}</p>
    {scenario.latest_review ? <p className="sli-ds-header__subtitle">{t("security.scenarios.review.latest", { rationale: scenario.latest_review.rationale })}</p> : null}
    <form className="sli-ds-filters" onSubmit={submit}>
      <div className="sli-ds-filters__fields">
        <div className="sli-ds-field"><label htmlFor={`${id}-verdict`}>{t("security.scenarios.review.field.verdict")}</label>
          <select id={`${id}-verdict`} value={verdict} onChange={(event) => setVerdict(event.target.value as SemanticScenarioReview["verdict"])} disabled={disabled}>
            {getReviewVerdicts().map((item) => <option key={item.value} value={item.value}>{item.optionLabel}</option>)}
          </select></div>
        <div className="sli-ds-field"><label htmlFor={`${id}-confidence`}>{t("security.scenarios.review.field.confidence")}</label>
          <select id={`${id}-confidence`} value={confidence} onChange={(event) => setConfidence(event.target.value as SemanticScenarioReview["review_confidence"])} disabled={disabled}>
            <option value="high">{t("security.scenarios.review.confidence.high")}</option><option value="medium">{t("security.scenarios.review.confidence.medium")}</option><option value="low">{t("security.scenarios.review.confidence.low")}</option>
          </select></div>
        <div className="sli-ds-field"><label htmlFor={`${id}-rationale`}>{t("security.scenarios.review.field.rationale")}</label>
          <input id={`${id}-rationale`} value={rationale} onChange={(event) => setRationale(event.target.value)} minLength={MIN_REVIEW_RATIONALE_LENGTH} maxLength={2000} required disabled={disabled} placeholder={t("security.scenarios.review.rationale_placeholder")}/></div>
      </div>
      <div className="sli-ds-filters__actions">
        <button className="sli-ds-button" data-variant="primary" type="submit" disabled={disabled || rationale.trim().length < MIN_REVIEW_RATIONALE_LENGTH}>{review.isPending ? t("security.scenarios.review.saving") : t("security.scenarios.review.save")}</button>
      </div>
    </form>
    {validation ? <p role="alert" className="sli-ds-field__error">{validation}</p> : null}
    {!schemaReady ? <StateView state="unavailable" compact detail={t("security.scenarios.review.migration_error")}/> : null}
    {review.isError ? <p role="alert" className="sli-ds-field__error">{t("security.scenarios.review.error")}</p> : null}
    {saved ? <p role="status" className="sli-ds-header__subtitle">{t("security.scenarios.review.success")}</p> : null}
  </section>;
}

function EvidenceList({ items, empty }: { items: Array<{ key: string; eventDbId: number; note: string }>; empty: string }) {
  return <>
    <h3>{t("security.scenarios.evidence.exact")}</h3>
    {items.length
      ? <ul>{items.map((item) => <li key={item.key}><Link to="/events/$eventId" params={{ eventId: String(item.eventDbId) }}>{t("security.scenarios.evidence.db_event", { id: item.eventDbId })}</Link> <small>{item.note}</small></li>)}</ul>
      : <p className="sli-ds-header__subtitle">{empty}</p>}
  </>;
}

function ScenarioCard({ scenario, timeZone }: { scenario: SemanticScenario; timeZone: string }) {
  const evidencePages = useInfiniteQuery({
    queryKey: ["scenario-evidence", scenario.scenario_id, scenario.updated_at, scenario.evidence_next_cursor],
    initialPageParam: scenario.evidence_next_cursor ?? null,
    queryFn: async ({ pageParam }) => {
      const params = new URLSearchParams({ scenario_id: scenario.scenario_id });
      if (pageParam) params.set("evidence_cursor", pageParam);
      params.set("limit", "1");
      const page = await api.semanticScenarios(params);
      if (page.state === "unavailable" || page.state === "schema_unavailable") throw new Error("unavailable");
      return page.items[0] ?? null;
    },
    getNextPageParam: (lastPage) => lastPage?.evidence_next_cursor ?? undefined,
    enabled: false,
    retry: false,
  });
  const evidence = [...new Map([scenario, ...(evidencePages.data?.pages ?? [])].flatMap((page) => page?.evidence ?? []).map((item) => [item.normalized_event_id, item])).values()];
  const hasMoreEvidence = evidencePages.data ? evidencePages.hasNextPage : Boolean(scenario.evidence_next_cursor);
  return <article className="sli-ds-widget">
    <div className="sli-ds-widget__head">
      <div>
        <span className="sli-ds-widget__section">{scenarioResultLabel(scenario.result_class)} · {scenario.scenario_kind}</span>
        <h2 className="sli-ds-widget__title">{scenario.title}</h2>
      </div>
      <span><ConclusionBadge value={scenario.conclusion_state}/> <span className="sli-ds-badge">{statusLabel(scenario.status)}</span></span>
    </div>
    <p>{scenario.explanation}</p>
    <FactList facts={[
      { label: t("security.scenarios.metric.risk"), value: <><RiskBadge value={scenario.risk_class}/> {scenario.display_score}/100{scenario.hard_critical ? ` · ${t("security.scenarios.metric.hardCritical")}` : ""}</> },
      { label: t("security.scenarios.metric.confidence"), value: <><ConfidenceBadge value={scenario.confidence}/> {scenario.confidence_score}/100</> },
      { label: t("security.scenarios.metric.coverage"), value: <>{coverageLabel(scenario.coverage_status)} · {scenario.coverage_status === "unknown" ? t("security.scenarios.card.coverage.none") : t("security.scenarios.card.coverage.received")}</> },
      { label: t("security.scenarios.card.period"), value: <><DateTime value={scenario.first_seen_utc} timeZone={timeZone}/> — <DateTime value={scenario.last_seen_utc} timeZone={timeZone} showZone/></> },
      { label: t("security.scenarios.card.partition"), value: <code>{scenario.partition_key}</code> },
      { label: t("security.scenarios.card.composition"), value: t("security.scenarios.card.composition_details", { steps: scenario.step_count, evidence: scenario.evidence_count, contributions: scenario.contribution_count }) },
    ]}/>
    <CompletenessDisclosure state={scenario.conclusion_state} snapshot={scenario.completeness_snapshot}/>
    <EvidenceList
      items={evidence.map((item) => ({ key: item.normalized_event_id, eventDbId: item.event_db_id, note: t("security.scenarios.evidence.note", { order: item.evidence_order, id: item.normalized_event_id.slice(0, 8) }) }))}
      empty={t("security.scenarios.card.no_evidence")}/>
    {scenario.evidence_count > evidence.length ? <p className="sli-ds-header__subtitle">{t("security.scenarios.card.evidence_partial", { shown: evidence.length, total: scenario.evidence_count })}</p> : null}
    {evidencePages.isError ? <p role="alert">{t("security.scenarios.continuation.error")}</p> : null}
    {hasMoreEvidence ? <button type="button" className="sli-ds-button" disabled={evidencePages.isFetching} onClick={() => void evidencePages.fetchNextPage()}>
      {evidencePages.isFetching ? t("security.scenarios.continuation.loading") : t("security.scenarios.continuation.evidence")}
    </button> : null}
  </article>;
}

function ActionCard({ action, timeZone }: { action: SemanticAction; timeZone: string }) {
  return <article className="sli-ds-widget">
    <div className="sli-ds-widget__head">
      <div>
        <span className="sli-ds-widget__section">{t("security.scenarios.action_card.section", { version: action.semantic_contract_version })}</span>
        <h2 className="sli-ds-widget__title">{action.action_kind}</h2>
      </div>
      <span className="sli-ds-badge" data-tone={action.status === "contradicted" || action.status === "quarantined" ? "warning" : undefined}>{actionStatusLabel(action.status)}</span>
    </div>
    <FactList facts={[
      { label: t("security.scenarios.action_card.observation"), value: <DateTime value={action.occurred_at_utc} timeZone={timeZone} showZone/> },
      { label: t("security.scenarios.action_card.assembler"), value: `${action.assembler_id} · ${action.assembler_version}` },
      { label: t("security.scenarios.action_card.attributes"), value: <code>{JSON.stringify(action.attributes)}</code> },
    ]}/>
    <EvidenceList
      items={action.evidence.map((item) => ({ key: `${item.normalized_event_id}-${item.evidence_role}`, eventDbId: item.event_db_id, note: `${item.evidence_role}${item.entity_role ? ` · ${item.entity_role}` : ""} · confidence ${item.relation_confidence.toFixed(3)}` }))}
      empty={t("security.scenarios.action_card.no_evidence")}/>
  </article>;
}

type CalibrationJob = SemanticCalibrationWorkspace["jobs"][number];
type CalibrationResult = SemanticCalibrationWorkspace["results"][number];
type CalibrationPolicy = SemanticCalibrationWorkspace["policies"][number];

function getJobColumns(): TableColumn<CalibrationJob>[] {
  return [
    { key: "evaluation_mode", label: t("security.scenarios.calibration.mode") }, { key: "evaluation_status", label: t("security.scenarios.calibration.status") },
    { key: "job_count", label: t("security.scenarios.calibration.jobs"), kind: "number" }, { key: "attempts", label: t("security.scenarios.calibration.attempts"), kind: "number" }, { key: "errors", label: t("security.scenarios.calibration.errors"), kind: "number" },
  ];
}
function getResultColumns(): TableColumn<CalibrationResult>[] {
  return [
    { key: "evaluation_mode", label: t("security.scenarios.calibration.mode") },
    { key: "risk", label: t("security.scenarios.metric.risk"), render: (row) => `${row.risk_class} · ${row.average_risk_score}` },
    { key: "confidence", label: t("security.scenarios.metric.confidence"), render: (row) => `${row.confidence} · ${row.average_confidence_score}` },
    { key: "coverage_status", label: t("security.scenarios.metric.coverage") },
    { key: "counts", label: t("security.scenarios.calibration.results_scenarios"), render: (row) => `${row.result_count} / ${row.scenario_count}` },
    { key: "average_evaluation_ms", label: t("security.scenarios.calibration.avg_ms"), kind: "number" },
  ];
}
function getPolicyColumns(): TableColumn<CalibrationPolicy>[] {
  return [
    { key: "lifecycle_status", label: t("security.scenarios.calibration.state") }, { key: "source_kind", label: t("security.scenarios.calibration.source") }, { key: "policy_count", label: t("security.scenarios.calibration.versions"), kind: "number" },
  ];
}

function CalibrationView({ data }: { data: SemanticCalibrationWorkspace }) {
  const readiness = data.calibration_readiness;
  const falsePositive = readiness?.false_positive_rate;
  return <>
    {data.state === "available" ? <>
      <section className="sli-ds-report__views" aria-label={t("security.scenarios.calibration.queue_title")}>
        <h2>{t("security.scenarios.calibration.queue_title")}</h2>
        {data.jobs.length ? <DataTable columns={getJobColumns()} rows={data.jobs} rowKey={(row) => `${row.evaluation_mode}-${row.evaluation_status}`} caption={t("security.scenarios.calibration.queue_title")}/> : <p className="sli-ds-header__subtitle">{t("security.scenarios.calibration.no_jobs")}</p>}
      </section>
      <section className="sli-ds-report__views" aria-label={t("security.scenarios.calibration.policies_title")}>
        <h2>{t("security.scenarios.calibration.policies_title")}</h2>
        {data.policies.length ? <DataTable columns={getPolicyColumns()} rows={data.policies} rowKey={(row) => `${row.lifecycle_status}-${row.source_kind}`} caption={t("security.scenarios.calibration.policies_title")}/> : <p className="sli-ds-header__subtitle">{t("security.scenarios.calibration.no_policies")}</p>}
      </section>
      <section className="sli-ds-report__views" aria-label={t("security.scenarios.calibration.results_title")}>
        <h2>{t("security.scenarios.calibration.results_title")}</h2>
        {data.results.length ? <DataTable columns={getResultColumns()} rows={data.results} rowKey={(row) => `${row.evaluation_mode}-${row.risk_class}-${row.confidence}-${row.coverage_status}`} caption={t("security.scenarios.calibration.results_title")}/> : <p className="sli-ds-header__subtitle">{t("security.scenarios.calibration.no_results")}</p>}
      </section>
    </> : null}
    {readiness && falsePositive ? <section className="sli-ds-report__views" aria-label={t("security.scenarios.readiness.title")}>
      <h2>{t("security.scenarios.readiness.title")}</h2>
      <FactList facts={[
        { label: t("security.scenarios.readiness.controlHealth"), value: readiness.control_health.total },
        { label: t("security.scenarios.metric.coverage"), value: t("security.scenarios.readiness.assessments", { count: readiness.coverage.total }) },
        { label: t("security.scenarios.readiness.channels"), value: `${readiness.source_coverage_integrity.channels.total} · ${readiness.source_coverage_integrity.state}` },
        { label: t("security.scenarios.readiness.cursorRollback"), value: t("security.scenarios.readiness.cursorSummary", { actionable: readiness.source_coverage_integrity.cursor_integrity.actionable_rollbacks ?? 0, total: readiness.source_coverage_integrity.cursor_integrity.rejected_rollbacks ?? 0, gap: readiness.source_coverage_integrity.gap_detection.state ?? "unknown" }) },
        { label: t("security.scenarios.readiness.retryQuarantine"), value: `${readiness.execution_reliability.retries} / ${readiness.execution_reliability.quarantined}` },
        { label: t("security.scenarios.readiness.quality"), value: t("security.scenarios.readiness.normalized", { count: readiness.source_quality.normalized }) },
        { label: t("security.scenarios.readiness.timeProvenance"), value: t("security.scenarios.readiness.timeSummary", { skew: readiness.time_provenance.future_clock_skew, delayed: readiness.time_provenance.delayed_ingest }) },
        { label: t("security.scenarios.readiness.falsePositiveRate"), value: falsePositive.rate_percent == null ? t("security.scenarios.readiness.fpr_not_measured", { decisive: falsePositive.decisive_labels, min: falsePositive.minimum_decisive_sample }) : `${falsePositive.rate_percent}% · ${falsePositive.state}` },
      ]}/>
      <p className="sli-ds-header__subtitle">{t("security.scenarios.readiness.gap_note")}</p>
    </section> : null}
  </>;
}

function getPrinciples() {
  return [
    { label: t("security.scenarios.principles.risk.label"), value: t("security.scenarios.principles.risk.value") },
    { label: t("security.scenarios.principles.confidence.label"), value: t("security.scenarios.principles.confidence.value") },
    { label: t("security.scenarios.principles.coverage.label"), value: t("security.scenarios.principles.coverage.value") },
    { label: t("security.scenarios.principles.conclusion.label"), value: t("security.scenarios.principles.conclusion.value") },
  ];
}

function getEmptyTitle(view: SemanticView): string {
  const map: Record<SemanticView, import("../i18n").MessageKey> = {
    scenarios: "security.scenarios.empty.scenarios",
    actions: "security.scenarios.empty.actions",
    calibration: "security.scenarios.empty.calibration",
    sigma: "security.sigma.title",
  };
  return t(map[view]);
}

export function ScenariosPage() {
  const queryClient = useQueryClient();
  const { timeZone } = useTimeZone();
  const [semanticView, setSemanticView] = useState<SemanticView>("scenarios");
  const [scenarioStatus, setScenarioStatus] = useState("");
  const [resultClass, setResultClass] = useState("");
  const [riskClass, setRiskClass] = useState("");
  const [actionStatus, setActionStatus] = useState("");
  const [actionKind, setActionKind] = useState("");
  const [calibrationWindow, setCalibrationWindow] = useState(24);
  const params = useMemo(() => {
    const value = new URLSearchParams();
    if (scenarioStatus) value.set("status", scenarioStatus);
    if (resultClass) value.set("result_class", resultClass);
    if (riskClass) value.set("risk_class", riskClass);
    value.set("limit", "30");
    return value;
  }, [scenarioStatus, resultClass, riskClass]);
  const scenarioQueryKey = ["semantic-scenarios", params.toString(), "pages"];
  const scenarioPages = useInfiniteQuery({
    queryKey: scenarioQueryKey,
    initialPageParam: null as string | null,
    queryFn: async ({ pageParam }) => {
      const next = new URLSearchParams(params);
      if (pageParam) next.set("cursor", pageParam);
      try {
        const page = await api.semanticScenarios(next);
        if (pageParam && (page.state === "unavailable" || page.state === "schema_unavailable")) throw new Error("unavailable");
        return page;
      } catch (error) {
        if (error instanceof ApiResponseError && (error.status === 401 || error.status === 403)) {
          // Do not retain revoked pages for a later 503 or a filter/back navigation.
          queryClient.getQueryCache().find({ queryKey: scenarioQueryKey, exact: true })?.setState({ data: undefined });
        }
        throw error;
      }
    },
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
    retry: false,
    staleTime: 30_000,
    refetchOnWindowFocus: false,
    enabled: semanticView === "scenarios",
  });
  const actionParams = useMemo(() => {
    const value = new URLSearchParams({ limit: "30" });
    if (actionStatus) value.set("status", actionStatus);
    if (actionKind.trim()) value.set("action_kind", actionKind.trim());
    return value;
  }, [actionStatus, actionKind]);
  const actions = useQuery({
    queryKey: ["semantic-actions", actionParams.toString()],
    queryFn: () => api.semanticActions(actionParams),
    staleTime: 30_000,
    refetchOnWindowFocus: false,
    enabled: semanticView === "actions",
  });
  const calibration = useQuery({
    queryKey: ["semantic-calibration", calibrationWindow],
    queryFn: () => api.semanticCalibration(calibrationWindow),
    staleTime: 30_000,
    refetchOnWindowFocus: false,
    enabled: semanticView === "calibration",
  });
  const workspace = { ...scenarioPages, data: scenarioPages.data?.pages[0], isError: scenarioPages.isError };
  const active: QueryLike & { isLoading: boolean; data?: { state: string; execution: SemanticCalibrationWorkspace["execution"] } } =
    semanticView === "scenarios" ? workspace : semanticView === "actions" ? actions : calibration;
  const denied = active.isError && readFailureState(active.error) === "denied";
  const data = semanticView === "sigma" || denied ? undefined : active.data;
  const continuationError = semanticView === "scenarios" && scenarioPages.isFetchNextPageError && !denied;
  const stale = active.isError && Boolean(data) && !denied && !continuationError;
  const execution = data?.execution;
  const executionState = execution?.state ?? "disabled";
  const scenarioItems = denied ? [] : [...new Map((scenarioPages.data?.pages ?? []).flatMap((page) => page.items).map((item) => [item.scenario_id, item])).values()];
  const hasMore = semanticView === "scenarios" ? scenarioPages.hasNextPage : semanticView === "actions" && Boolean(actions.data?.has_more);

  return <section className="sli-ds-report">
    <PageHeader
      title={t("security.scenarios.page.title")}
      subtitle={t("security.scenarios.page.subtitle")}
      actions={semanticView !== "sigma" && !denied ? <span className="sli-ds-badge" data-tone={executionState === "active" ? "success" : "warning"}>{scenarioExecutionLabel(executionState)}</span> : undefined}/>
    <section className="sli-ds-report__views" aria-label={t("security.scenarios.markup.title")}><FactList facts={getPrinciples()}/></section>

    <div role="group" aria-label={t("security.scenarios.semantic_layer")}>
      <button type="button" className="sli-ds-chip" aria-pressed={semanticView === "scenarios"} onClick={() => setSemanticView("scenarios")}>{t("security.scenarios.tabs.scenarios")}</button>{" "}
      <button type="button" className="sli-ds-chip" aria-pressed={semanticView === "actions"} onClick={() => setSemanticView("actions")}>{t("security.scenarios.tabs.actions")}</button>{" "}
      <button type="button" className="sli-ds-chip" aria-pressed={semanticView === "calibration"} onClick={() => setSemanticView("calibration")}>{t("security.scenarios.tabs.calibration")}</button>
      {" "}<button type="button" className="sli-ds-chip" aria-pressed={semanticView === "sigma"} onClick={() => setSemanticView("sigma")}>{t("security.sigma.title")}</button>
    </div>
    {semanticView === "sigma" ? <SigmaRulesPanel/> : <>
    {semanticView === "scenarios" ? <div className="sli-ds-filters"><div className="sli-ds-filters__fields">
      <div className="sli-ds-field"><label htmlFor="scenario-status">{t("security.scenarios.filters.status")}</label>
        <select id="scenario-status" value={scenarioStatus} onChange={(event) => setScenarioStatus(event.target.value)}>
          <option value="">{t("security.scenarios.filters.all")}</option><option value="open">{t("security.scenarios.filters.status.open")}</option><option value="under_review">{t("security.scenarios.filters.status.under_review")}</option><option value="resolved">{t("security.scenarios.filters.status.resolved")}</option><option value="dismissed">{t("security.scenarios.filters.status.dismissed")}</option>
        </select></div>
      <div className="sli-ds-field"><label htmlFor="scenario-result-class">{t("security.scenarios.filters.result_class")}</label>
        <select id="scenario-result-class" value={resultClass} onChange={(event) => setResultClass(event.target.value)}>
          <option value="">{t("security.scenarios.filters.all")}</option><option value="security_incident">{scenarioResultLabel("security_incident")}</option><option value="security_exposure">{scenarioResultLabel("security_exposure")}</option><option value="control_gap">{scenarioResultLabel("control_gap")}</option>
        </select></div>
      <div className="sli-ds-field"><label htmlFor="scenario-risk-class">{t("security.scenarios.filters.risk")}</label>
        <select id="scenario-risk-class" value={riskClass} onChange={(event) => setRiskClass(event.target.value)}>
          <option value="">{t("security.scenarios.filters.all")}</option><option value="critical">{t("security.scenarios.filters.risk.critical")}</option><option value="high">{t("security.scenarios.filters.risk.high")}</option><option value="medium">{t("security.scenarios.filters.risk.medium")}</option><option value="low">{t("security.scenarios.filters.risk.low")}</option><option value="info">{t("security.scenarios.filters.risk.info")}</option><option value="unknown">{t("security.scenarios.filters.risk.unknown")}</option>
        </select></div>
    </div></div>
      : semanticView === "actions" ? <div className="sli-ds-filters"><div className="sli-ds-filters__fields">
        <div className="sli-ds-field"><label htmlFor="action-status">{t("security.scenarios.filters.action_status")}</label>
          <select id="action-status" value={actionStatus} onChange={(event) => setActionStatus(event.target.value)}>
            <option value="">{t("security.scenarios.filters.all")}</option><option value="observed">{t("security.scenarios.action.observed")}</option><option value="partially_confirmed">{t("security.scenarios.action.partially_confirmed")}</option><option value="state_confirmed">{t("security.scenarios.action.state_confirmed")}</option><option value="multi_source_confirmed">{t("security.scenarios.action.multi_source_confirmed")}</option><option value="contradicted">{t("security.scenarios.action.contradicted")}</option><option value="quarantined">{t("security.scenarios.action.quarantined")}</option>
          </select></div>
        <div className="sli-ds-field"><label htmlFor="action-kind">{t("security.scenarios.filters.action_kind")}</label>
          <input id="action-kind" value={actionKind} onChange={(event) => setActionKind(event.target.value)} maxLength={160} placeholder={t("security.scenarios.filters.action_kind_placeholder")}/></div>
      </div></div>
        : <div className="sli-ds-filters"><div className="sli-ds-filters__fields">
          <div className="sli-ds-field"><label htmlFor="calibration-window">{t("security.scenarios.filters.calibration_window")}</label>
            <select id="calibration-window" value={calibrationWindow} onChange={(event) => setCalibrationWindow(Number(event.target.value))}>
              <option value={24}>{t("security.scenarios.filters.window.24h")}</option><option value={72}>{t("security.scenarios.filters.window.72h")}</option><option value={168}>{t("security.scenarios.filters.window.168h")}</option>
            </select></div>
        </div><p className="sli-ds-header__subtitle">{t("security.scenarios.filters.test_shadow_note")}</p></div>}

    {active.isLoading ? <StateView state="loading" detail={t("security.scenarios.state.loading")}/> : null}
    {active.isError && !continuationError ? <StateView state={stale ? "stale" : readFailureState(active.error)} compact={stale}
      detail={t(stale ? "security.scenarios.state.refreshFailed" : "security.scenarios.state.error")}
      actions={stale ? <button type="button" className="sli-ds-button" onClick={() => void active.refetch()}>{t("state.retry")}</button> : undefined}
      onRetry={() => void active.refetch()}/> : null}
    {data?.state === "schema_unavailable" ? <StateView state="unavailable" detail={t("security.scenarios.state.schema_unavailable")}/> : null}
    {data?.state === "unavailable" ? <StateView state="unavailable" detail={t("security.scenarios.state.unavailable")}/> : null}
    {data?.state === "empty" ? <StateView state="empty" detail={<><strong>{getEmptyTitle(semanticView)}.</strong> {execution?.state === "disabled" ? t("security.scenarios.state.empty_disabled") : t("security.scenarios.state.empty_active")}</>}/> : null}

    {semanticView === "scenarios" && scenarioItems.length ? <>
      <div className="sli-ds-widgets">{scenarioItems.map((scenario) => <ScenarioCard key={scenario.scenario_id} scenario={scenario} timeZone={timeZone}/>)}</div>
      {scenarioPages.isFetchNextPageError ? <p role="alert">{t("security.scenarios.continuation.error")}</p> : null}
      {scenarioPages.hasNextPage ? <button type="button" className="sli-ds-button" disabled={scenarioPages.isFetching} onClick={() => void scenarioPages.fetchNextPage()}>
        {scenarioPages.isFetchingNextPage ? t("security.scenarios.continuation.loading") : t("security.scenarios.continuation.scenarios")}
      </button> : null}
      <section className="sli-ds-report__views" aria-label={t("security.scenarios.markup.title")}>
        <div><h2>{t("security.scenarios.markup.title")}</h2><p className="sli-ds-header__subtitle">{t("security.scenarios.markup.subtitle")}</p></div>
        {scenarioItems.map((scenario) => <ScenarioReviewPanel key={scenario.scenario_id} scenario={scenario} schemaReady={Boolean(workspace.data?.execution.analyst_review_schema_ready)}/>)}
      </section>
    </> : null}
    {!denied && semanticView === "actions" && actions.data?.items.length ? <div className="sli-ds-widgets">{actions.data.items.map((action) => <ActionCard key={action.canonical_action_id} action={action} timeZone={timeZone}/>)}</div> : null}
    {!denied && semanticView === "calibration" && calibration.data ? <CalibrationView data={calibration.data}/> : null}
    {execution ? <details className="sli-ds-report__views">
      <summary>{t("security.scenarios.technical.title")}</summary>
      <FactList facts={[
        { label: t("security.scenarios.technical.runtime"), value: execution.runtime_marker ?? EMPTY_VALUE },
        { label: t("security.scenarios.technical.semantic"), value: execution.semantic_schema_marker ?? EMPTY_VALUE },
        { label: t("security.scenarios.technical.worker"), value: statusLabel(execution.worker.state) },
        { label: t("security.scenarios.technical.path"), value: execution.finding_path_live ? t("security.scenarios.execution_state.path_active") : t("security.scenarios.execution_state.path_disabled") },
      ]}/>
      <p>{execution.state === "disabled" ? t("security.scenarios.execution_state.disabled_detail") : t("security.scenarios.execution_state.active_detail")}</p>
    </details> : null}
    {!denied && hasMore ? <StateView state="partial" compact detail={t("security.scenarios.state.partial")}/> : null}
    </>}
  </section>;
}
