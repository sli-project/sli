"""Pydantic contracts for the incremental React workspace API."""
from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    AliasChoices,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    computed_field,
)

from server.sli.core.time_format import parse_event_time
from server.sli.semantic.event_semantic_contract import (
    Confidence,
    EventCategory,
    MachineRisk,
    NoiseClass,
    PurposeTier,
)


def _utc_iso_string(value: Any) -> Any:
    """Normalize database timestamps to the public UTC string contract."""
    if value is None:
        return None
    parsed = parse_event_time(value)
    if parsed is None:
        return value
    return parsed.isoformat().replace("+00:00", "Z")


UtcIsoString = Annotated[str, BeforeValidator(_utc_iso_string)]


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    api_version: Literal["v1"] = "v1"


class SemanticWorkerState(BaseModel):
    state: str
    status: str
    heartbeat_at: UtcIsoString | None = None
    runtime_mode: str | None = None


class SemanticExecutionState(BaseModel):
    state: Literal["disabled", "partially_enabled", "enabled_without_worker", "active"]
    schema_state: Literal["ready", "unavailable"]
    runtime_mode: Literal["facts-v1", "investigation-v1", "findings-v1"] | None = None
    runtime_marker: int | None = None
    semantic_schema_marker: int | None = None
    feature_chain: dict[str, bool]
    worker: SemanticWorkerState
    finding_path_live: bool
    analyst_review_schema_ready: bool = False
    conclusion_completeness_schema_ready: bool = False


class SemanticScenarioEvidence(BaseModel):
    normalized_event_id: UUID
    event_db_id: int = Field(gt=0)
    evidence_order: int = Field(ge=0)


class SemanticScenarioReview(BaseModel):
    review_id: UUID
    review_request_id: UUID
    scenario_id: UUID
    supersedes_review_id: UUID | None = None
    verdict: Literal[
        "confirmed_security", "false_positive", "benign_expected", "insufficient_evidence",
    ]
    review_confidence: Literal["high", "medium", "low"]
    rationale: str
    scenario_snapshot_sha256: str
    reviewed_by: str
    reviewer_role: Literal["viewer", "operator", "admin"]
    reviewed_at: UtcIsoString


class SemanticScenarioItem(BaseModel):
    scenario_id: UUID
    scenario_kind: str
    result_class: Literal["security_incident", "security_exposure", "control_gap"]
    status: Literal["open", "under_review", "resolved", "dismissed"]
    partition_key: str
    strict_keys: dict[str, Any]
    title: str
    explanation: str
    first_seen_utc: UtcIsoString
    last_seen_utc: UtcIsoString
    risk_class: MachineRisk
    raw_score: float = Field(ge=0)
    display_score: int = Field(ge=0, le=100)
    hard_critical: bool
    confidence: Confidence
    confidence_score: int = Field(ge=0, le=100)
    confidence_factors: dict[str, Any]
    coverage_status: Literal["complete", "partial", "unavailable", "unknown"]
    conclusion_state: Literal["observed", "not_found", "not_checked"]
    completeness_snapshot: dict[str, Any]
    step_count: int = Field(ge=0)
    evidence_count: int = Field(ge=0)
    contribution_count: int = Field(ge=0)
    updated_at: UtcIsoString
    evidence: list[SemanticScenarioEvidence]
    evidence_has_more: bool = False
    evidence_next_cursor: str | None = None
    review_count: int = Field(default=0, ge=0)
    latest_review: SemanticScenarioReview | None = None
    payload_state: Literal["available", "metadata_only"] = "available"


class SemanticScenariosResponse(ApiModel):
    next_cursor: str | None = None
    generated_at_utc: UtcIsoString
    read_only: Literal[True] = True
    execution: SemanticExecutionState
    state: Literal["available", "empty", "schema_unavailable", "unavailable"]
    items: list[SemanticScenarioItem]
    has_more: bool
    filters: dict[str, str | None]
    limits: dict[str, Any]


class SemanticActionEvidence(BaseModel):
    normalized_event_id: UUID
    event_db_id: int = Field(gt=0)
    evidence_role: Literal["primary", "supporting", "state_confirmation", "context"]
    entity_role: str | None = None
    evidence_order: int = Field(ge=0)
    relation_confidence: float = Field(ge=0, le=1)


class SemanticActionItem(BaseModel):
    canonical_action_id: UUID
    action_kind: str
    status: Literal[
        "observed", "partially_confirmed", "state_confirmed", "multi_source_confirmed",
        "contradicted", "superseded", "quarantined",
    ]
    semantic_contract_version: int = Field(gt=0)
    assembler_id: str
    assembler_version: str
    occurred_at_utc: UtcIsoString
    attributes: dict[str, Any]
    created_at: UtcIsoString
    updated_at: UtcIsoString
    evidence: list[SemanticActionEvidence]
    payload_state: Literal["available", "metadata_only"] = "available"


class SemanticActionsResponse(ApiModel):
    generated_at_utc: UtcIsoString
    read_only: Literal[True] = True
    execution: SemanticExecutionState
    state: Literal["available", "empty", "schema_unavailable", "unavailable"]
    items: list[SemanticActionItem]
    has_more: bool
    filters: dict[str, str | None]
    limits: dict[str, Any]


class SemanticCalibrationResponse(ApiModel):
    generated_at_utc: UtcIsoString
    read_only: Literal[True] = True
    execution: SemanticExecutionState
    window_hours: int = Field(ge=1, le=168)
    state: Literal["available", "empty", "schema_unavailable"]
    jobs: list[dict[str, Any]]
    results: list[dict[str, Any]]
    policies: list[dict[str, Any]]
    calibration_readiness: dict[str, Any]
    limits: dict[str, Any]


class SemanticScenarioReviewResponse(ApiModel):
    item: SemanticScenarioReview
    replayed: bool


class EventListItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_db_id: int = Field(validation_alias=AliasChoices("event_db_id", "id"))
    event_id: int
    event_record_id: int | None = None
    time_created_utc: UtcIsoString | None = None
    server: str | None = None
    channel: str | None = None
    provider_name: str | None = None
    label: str = "Событие журнала"
    summary: str = "Сводка события; точные данные доступны в карточке доказательства."
    category: str | None = None
    severity: str | None = None
    tier: str | None = None
    purpose_tier: str | None = None
    base_risk: str | None = None
    final_risk: str | None = None
    final_security_severity: str | None = None
    confidence: str | None = None
    noise_class: str | None = None
    assessment_confidence: str | None = None
    catalog_match: bool | None = None
    reasons: list[str] = Field(default_factory=list)
    evidence_fields: list[str] = Field(default_factory=list)
    display_labels: dict[str, str] = Field(default_factory=dict)
    time_created_utc_display: str | None = None
    time_created_local_display: str | None = None
    relation_count: int | None = None
    relation_count_status: str | None = None
    source_payload_state: Literal["expired"] | None = None


class EventListResponse(ApiModel):
    items: list[EventListItem]
    next_cursor: str | None = None
    has_more: bool = False
    query_status: Literal["ok", "timeout", "empty"] = "ok"
    warning: str | None = None
    category_counts: dict[str, int] | None = None


class EventSemanticDisplayLabels(BaseModel):
    """Localized presentation; never used as an API filter or sort key."""
    model_config = ConfigDict(extra="forbid")
    risk: str
    confidence: str


class EventSemanticsContract(BaseModel):
    """Canonical machine semantics shared by event detail consumers.

    ``extra=allow`` intentionally preserves the richer transitional event-card
    fields while the six typed machine fields remain mandatory.
    """
    model_config = ConfigDict(extra="allow")
    category: EventCategory
    purpose_tier: PurposeTier
    base_risk: MachineRisk
    final_security_severity: MachineRisk
    assessment_confidence: Confidence
    classification_origin: Literal["catalog_base", "contextual_rule", "unavailable"] = "unavailable"
    card_completeness: Literal["complete", "partial", "not_applicable"] = "not_applicable"
    catalog_match: bool
    reasons: list[str] = Field(default_factory=list)
    evidence_fields: list[str] = Field(default_factory=list)
    # Additive compatibility aliases for existing API consumers.
    final_risk: MachineRisk
    confidence: Confidence
    noise_class: NoiseClass
    display_labels: EventSemanticDisplayLabels


class UiBootstrapResponse(ApiModel):
    principal: dict[str, Any] | None = None
    effective_role: Literal["viewer", "operator", "admin"]
    api_time_contract: str = "UTC ISO-8601; browser renders the selected local timezone"
    navigation: list[dict[str, str]]
    access_model: Literal["composite_v4"] = "composite_v4"
    capabilities: list[str] = Field(default_factory=list)
    packages: list[dict[str, Any]] = Field(default_factory=list)
    allowed_report_count: int = 0


class V4AccessResponse(ApiModel):
    api_version: Literal["v4"]
    evaluated_at_utc: Any
    preview: bool
    platform_owner: bool = False
    owner_policy: dict[str, Any] = Field(default_factory=dict)
    subject: dict[str, Any]
    groups: list[dict[str, Any]]
    packages: list[dict[str, Any]]
    package_explain: list[dict[str, Any]]
    capabilities: list[str]
    resource_bound_capabilities: list[str] = Field(default_factory=list)
    capability_explain: dict[str, list[dict[str, Any]]]
    capability_policies: list[dict[str, Any]] = Field(default_factory=list)
    quarantined_capability_assignments: list[dict[str, Any]] = Field(default_factory=list)
    resource_bound_capability_assignments: list[dict[str, Any]] = Field(default_factory=list)
    reports: list[dict[str, Any]]
    allowed_report_count: int
    navigation: list[dict[str, str]]
    explicit_denies: dict[str, list[str]]
    ignored_denies: dict[str, list[str]] = Field(default_factory=dict)


class V4ReportAccessTraceResponse(ApiModel):
    api_version: Literal["v4"]
    evaluated_at_utc: Any
    subject: dict[str, str]
    report: dict[str, Any]
    decision: Literal["allowed", "denied"]
    explanation: str
    platform_owner: bool = False
    owner_policy: dict[str, bool] = Field(default_factory=dict)
    exact_deny: bool = False
    ignored_deny: bool = False
    missing_capabilities: list[str] = Field(default_factory=list)
    assignment_version_state: str
    grants: list[dict[str, Any]] = Field(default_factory=list)


class V4WorkspaceResponse(ApiModel):
    api_version: Literal["v4"]
    state: str
    subject: dict[str, Any]
    packages: list[dict[str, Any]]
    groups: list[dict[str, Any]]
    capabilities: list[str]
    reports: list[dict[str, Any]]
    focus_metrics: list[dict[str, Any]] = Field(default_factory=list)
    recent_objects: list[dict[str, Any]]
    # Distinguishes "no recent objects" from "the bounded read timed out".
    # Without it a timeout was indistinguishable from an empty result, and the
    # unhandled QueryTimeoutError turned the whole workspace into HTTP 500.
    recent_objects_state: str = "available"
    composition: dict[str, int]
    limits: dict[str, int]


class V4ReportCatalogResponse(ApiModel):
    api_version: Literal["v4"]
    state: str
    items: list[dict[str, Any]]
    allowed_count: int
    total_count: int
    explain_contract: str


class V4ObjectSearchResponse(ApiModel):
    api_version: Literal["v4"]
    query: str
    object_type: str | None = None
    state: str
    items: list[dict[str, Any]]
    has_more: bool
    scope_filtered: bool = False
    limits: dict[str, Any]


class V4ObjectDetailResponse(ApiModel):
    api_version: Literal["v4"]
    state: str
    object: dict[str, Any]
    identity_links: list[dict[str, Any]]
    identity_contract: str
    tabs: list[dict[str, Any]]
    current_states: list[dict[str, Any]]
    directory_context: dict[str, Any]
    findings: list[dict[str, Any]]
    events: list[dict[str, Any]]
    events_state: Literal["available", "temporarily_unavailable", "forbidden"] = "available"
    has_more_events: bool
    actions: list[str]
    provenance: list[dict[str, Any]]
    limitations: list[str]


class SourcePackDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pack_id: str
    version: str
    display_name: str
    source_kind: Literal["event", "context"]
    channels: list[str]
    sections: list[str]
    adapters: list[str]
    entity_contract: str
    analysis_contract: str
    manifest_sha256: str


class SourcePacksResponse(ApiModel):
    items: list[SourcePackDescriptor]


class SourceAdapterDescriptor(ApiModel):
    adapter_id: str
    display_name: str
    transport: str
    output_contract: str


class SourceAdaptersResponse(ApiModel):
    items: list[SourceAdapterDescriptor]


class OverviewDataState(BaseModel):
    cache: str
    stale: bool
    failures: list[str]


class OverviewMetrics(BaseModel):
    events_total: int
    events_estimated: bool
    entities_total: int
    entities_estimated: bool
    important_recent: int
    sources_total: int


class OverviewAlert(BaseModel):
    id: int
    title: str
    severity: str
    status: str
    actor: str | None = None
    target: str | None = None
    source: str | None = None
    last_seen_utc: UtcIsoString | None = None
    evidence_count: int
    assigned_to: str | None = None
    updated_at: UtcIsoString | None = None
    event_db_id: int | None = None


class OverviewCollectorChannel(BaseModel):
    server: str | None = None
    channel: str | None = None
    collection_state: str | None = None
    last_status: str | None = None
    failure_reason: str | None = None
    last_successful_collection_utc: UtcIsoString | None = None
    last_event_time_utc: UtcIsoString | None = None


class OverviewSource(BaseModel):
    hostname: str
    fqdn: str | None = None
    role: str | None = None
    active: bool | None = None
    registered: bool = False
    site: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    disk_state: str = "not_collected"
    disks: list[dict[str, Any]] = Field(default_factory=list)
    inventory_observed_at_utc: UtcIsoString | None = None
    inventory_source: str | None = None
    collection_state: Literal["error", "partial", "stale", "lagging", "current"] | None = None
    collection_label: str | None = None
    last_successful_collection_utc: UtcIsoString | None = None
    last_event_time_utc: UtcIsoString | None = None
    channels_total: int = 0
    channels: list[OverviewCollectorChannel] = Field(default_factory=list)


class OverviewCollectionFreshness(BaseModel):
    state: Literal["error", "partial", "stale", "lagging", "current"]
    label: str
    worst_lag_minutes: float | None = None
    checked_at_utc: UtcIsoString | None = None
    latest_event_utc: UtcIsoString | None = None
    worst_event_lag_minutes: float | None = None
    collection_error: bool = False
    channels_failed: int = 0
    channels_total: int = 0
    channels_checked: int = 0
    basis: str = "last_successful_collection"


class OverviewActivityBucket(BaseModel):
    index: int
    bucket_start_utc: UtcIsoString | None = None
    bucket_end_utc: UtcIsoString | None = None
    critical: int
    important: int
    informational: int


class OverviewActivity(BaseModel):
    period_label: str
    time_from_utc: UtcIsoString
    time_to_utc: UtcIsoString
    selected_source: str | None = None
    available: bool
    exact: bool
    reason: str | None = None
    items: list[OverviewActivityBucket]


class OverviewWorkspaceResponse(ApiModel):
    generated_at_utc: UtcIsoString | None = None
    status: str
    data_state: OverviewDataState
    metrics: OverviewMetrics
    alerts: list[OverviewAlert]
    sources: list[OverviewSource]
    collection_freshness: OverviewCollectionFreshness
    collection_progress: dict[str, Any]
    activity: OverviewActivity
    limits: dict[str, Any]


class InvestigationContext(BaseModel):
    event_db_id: int | None = None
    entity_id: int | None = Field(default=None, gt=0)
    time_from_utc: UtcIsoString | None = None
    time_to_utc_exclusive: UtcIsoString | None = None
    timezone: str = "UTC"
    anchor_in_window: bool | None = None


class InvestigationsWorkspaceResponse(ApiModel):
    next_cursor: str | None = None
    query: str
    anchor_event_db_id: int | None = None
    context: InvestigationContext | None = None
    scope: str
    state: Literal["query_required", "empty", "ok"]
    summary: InvestigationSummary
    timeline: list[InvestigationTimelineItem]
    findings: list[InvestigationFinding]
    next_checks: list[str]
    next_check_codes: list[str] = Field(default_factory=list)
    limits: dict[str, Any]


class InvestigationCaseResponse(ApiModel):
    @computed_field
    @property
    def case_number(self) -> str:
        return f"INV-{self.id:07d}"

    id: int
    public_id: UUID | None = None
    title: str
    status: str
    owner: str | None = None
    created_by: str
    created_at: UtcIsoString
    updated_at: UtcIsoString
    closed_at: UtcIsoString | None = None
    events: list[dict[str, Any]] = Field(default_factory=list)
    evidence_refs: list[dict[str, Any]] = Field(default_factory=list)
    evidence_refs_state: Literal["available", "partially_authorized"] = "available"
    evidence_page_size: int | None = None
    events_total: int | None = None
    events_next_cursor: int | None = None
    evidence_refs_total: int | None = None
    evidence_refs_next_cursor: str | None = None
    anchor_event: dict[str, Any] | None = None
    notes: list[dict[str, Any]] = Field(default_factory=list)
    audit: list[dict[str, Any]] = Field(default_factory=list)


class EntityTypeCount(BaseModel):
    entity_type: str
    count: int = Field(ge=0)


class EntitiesWorkspaceResponse(ApiModel):
    query: str
    state: Literal["empty", "ok"]
    items: list[EntityWorkspaceItem]
    has_more: bool
    filters: dict[str, list[str]] = Field(default_factory=dict)
    type_counts: list[EntityTypeCount] = Field(default_factory=list)
    type_counts_scope: Literal["all_entities"] = "all_entities"
    total_entities: int = Field(default=0, ge=0)
    limits: dict[str, Any]


class EntityEventCursor(BaseModel):
    time_utc: UtcIsoString | None = None
    event_db_id: int = Field(gt=0)


class EntityAdContextEvidenceItem(BaseModel):
    context_evidence_id: int | None = Field(default=None, gt=0)
    evidence_type: str
    source_pack_id: str
    source_run_id: str | None = None
    observed_at_utc: UtcIsoString | None = None
    integrity_sha256: str | None = None
    context_kind: Literal["entity", "relation"]
    subject_entity_id: int | None = Field(default=None, gt=0)
    subject_display_name: str | None = None
    related_entity_id: int | None = Field(default=None, gt=0)
    related_display_name: str | None = None
    valid_from_utc: UtcIsoString | None = None
    valid_to_utc: UtcIsoString | None = None
    current: bool
    source_section: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    supplemental_context_only: Literal[True]
    changes_entity_state: Literal[False]


class EntityAdContextEvidence(BaseModel):
    entity_id: int = Field(gt=0)
    ad_context_entity_id: int | None = Field(default=None, gt=0)
    resolution: Literal[
        "shared_entity_id",
        "exact_alias",
        "not_observed",
        "no_exact_alias",
        "ambiguous",
        "not_found",
        "temporarily_unavailable",
    ]
    items: list[EntityAdContextEvidenceItem]
    returned_count: int = Field(ge=0)
    bounded: bool
    limit: int | None = Field(default=None, gt=0)
    source_pack_optional: bool | None = None
    absence_closes_state: bool | None = None


class EntityWorkspaceEvent(BaseModel):
    event_db_id: int = Field(gt=0)
    event_id: int | None = None
    label: str | None = None
    time_utc: UtcIsoString | None = None
    server: str | None = None
    channel: str | None = None
    provider_name: str | None = None
    link_role: str | None = None
    confidence: float | None = None
    actor: str | None = None
    target: str | None = None


class EntityWorkspaceDetailResponse(ApiModel):
    """Exact entity detail with a bounded evidence-event slice."""
    entity: EntityWorkspaceItem
    current_states: list[EntityCurrentState]
    current_states_state: Literal["available", "temporarily_unavailable"] = "available"
    ad_context: EntityAdContextEvidence
    ad_context_state: Literal["available", "temporarily_unavailable"] = "available"
    events: list[EntityWorkspaceEvent]
    events_state: Literal["available", "temporarily_unavailable", "forbidden"] = "available"
    events_scope_filtered: bool = False
    security_actions_state: str = "time_bounds_required"
    security_actions: list[dict[str, Any]] = Field(default_factory=list)
    semantic_relations_state: str = "time_bounds_required"
    semantic_relations: list[dict[str, Any]] = Field(default_factory=list)
    has_more: bool
    next_cursor: EntityEventCursor | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    limits: dict[str, Any]


class InvestigationSummary(BaseModel):
    events_returned: int
    has_more: bool
    attention_level: str
    anchor_classification: dict[str, str] | None = None
    story: str
    story_code: str | None = None
    why_it_matters: str
    why_it_matters_code: str | None = None


class InvestigationTimelineItem(BaseModel):
    event_db_id: int
    time_utc: UtcIsoString | None = None
    server: str | None = None
    channel: str | None = None
    event_id: int
    title: str
    title_code: str | None = None
    summary_code: str | None = None
    category: EventCategory
    severity: MachineRisk
    purpose_tier: PurposeTier = PurposeTier.TECHNICAL
    base_risk: MachineRisk = MachineRisk.UNKNOWN
    confidence: Confidence = Confidence.UNKNOWN
    noise_class: NoiseClass = NoiseClass.UNKNOWN
    assessment_confidence: Confidence = Confidence.UNKNOWN
    classification_origin: Literal["catalog_base", "contextual_rule", "unavailable"] = "unavailable"
    card_completeness: Literal["complete", "partial", "not_applicable"] = "not_applicable"
    inclusion_reason: str | None = None
    actor: str | None = None
    target: str | None = None
    source: str | None = None
    summary: str | None = None
    catalogued: bool = False


class EventRelationItem(BaseModel):
    """Evidence relation with its provenance kept explicit for the UI."""
    relation_type: Literal["explicit_event_link", "computed_correlation"]
    relation_origin: Literal["stored", "computed"]
    confidence_kind: Literal["stored_link_value", "rule_policy_score"]
    related_event_db_id: int = Field(gt=0)
    source_event_db_id: int = Field(gt=0)
    target_event_db_id: int = Field(gt=0)
    rule_id: str
    related_event_id: int | None = None
    related_time_utc: UtcIsoString | None = None
    confidence: float
    reason: str
    explanation: str | None = None
    relation_strength: Literal["strong", "medium"] | None = None
    relation_rule: str | None = None
    time_delta_seconds: int | None = None
    evidence_fields: list[str] = Field(default_factory=list)
    entity: str | None = None
    entity_type: str | None = None
    source_role: str | None = None
    related_role: str | None = None


class EventRelationsResponse(ApiModel):
    event_db_id: int = Field(gt=0)
    items: list[EventRelationItem]
    contract: Literal["explicit_event_link_or_rule_based_correlation"]
    confidence_contract: dict[str, str]


class EventEntityItem(BaseModel):
    id: int = Field(gt=0)
    type: str
    natural_key: str
    display_name: str | None = None
    link_role: str
    confidence: float


class EventEntitiesResponse(ApiModel):
    event_db_id: int = Field(gt=0)
    event_found: bool | None
    evidence_status: Literal["present", "zero_extracted", "event_not_found", "timeout"]
    items: list[EventEntityItem]
    limit: int
    warning: str | None = None


class InvestigationFinding(BaseModel):
    id: int
    title: str
    severity: str
    status: str
    target: str | None = None
    last_seen_utc: UtcIsoString | None = None
    recommended_action: str | None = None
    assigned_to: str | None = None
    status_reason: str | None = None
    updated_at: UtcIsoString | None = None
    status_history: list[dict[str, Any]] = Field(default_factory=list)


class EntityLatestState(BaseModel):
    status: str
    summary: str | None = None
    observed_at_utc: UtcIsoString | None = None
    evidence_event_db_id: int


class EntityCurrentState(BaseModel):
    """Current evidence-backed value for one entity state type."""
    state_type: str
    status: str
    projection_status: Literal["normal", "unknown", "conflict"]
    observed_at_utc: UtcIsoString | None = None
    evidence_event_db_id: int = Field(gt=0)
    rule_id: str | None = None
    rule_version: str | None = None
    summary: str | None = None


class EntityWorkspaceItem(BaseModel):
    id: int
    type: str
    natural_key: str
    display_name: str | None = None
    first_seen_utc: UtcIsoString | None = None
    last_seen_utc: UtcIsoString | None = None
    latest_state: EntityLatestState | None = None
