import type { ApiMessage } from "../i18n/messages";

/** Wire types of /api/v2/reports (ADR 0010). */

export type ReportParamKind = "text" | "choice" | "multichoice" | "period" | "int" | "domain";
export type ReportColumnKind = "text" | "number" | "datetime" | "date" | "boolean" | "code" | "list" | "state";
export type ReportResultState = "ok" | "empty" | "denied" | "not_collected" | "partial" | "processing" | "stale" | "error";

export type ReportStateDetails = {
  reason: string;
  source?: string | Record<string, unknown> | null;
  stage?: string;
  limitations?: Array<{ code: string; text: string }>;
  missing_sources?: string[];
  missing_domains?: Array<string | number>;
  observed_at_utc?: string | null;
  stale_since_utc?: string | null;
  source_issues?: Array<{ source: string; source_name?: string; reason: string; since_utc?: string | null }>;
};

export type ReportOption = { value: string; label: string; count?: number; important?: boolean };

/** Optional additive access metadata; older report servers omit it. */
export type ReportAccessDto = { allowed: boolean; reason?: string | null; hidden_categories?: string[] };

export type ReportParamDto = {
  key: string;
  label: string;
  kind: ReportParamKind;
  options?: ReportOption[];
  options_from?: string;
  default?: string | number;
  required?: boolean;
  hidden?: boolean;
  presets?: Array<"2h" | "24h" | "7d" | "30d" | "90d" | "custom">;
  max_days?: number;
  max_length?: number;
};

export type ReportColumnDto = {
  key: string;
  label: string;
  kind: ReportColumnKind;
  path: string;
  sortable?: boolean;
  hidden_by_default?: boolean;
  labels?: Record<string, string>;
  link?: string;
  component?: string;
};

export type ReportViewDto = {
  access?: ReportAccessDto;
  kind: "table" | "chart" | "custom";
  key: string;
  source?: string;
  title?: string;
  note?: string;
  columns?: ReportColumnDto[];
  chart?: "timeseries" | "bar" | "heatmap";
  x?: string;
  /** Heatmap: row path of the y category (the first series is the cell value). */
  y?: string;
  series?: Array<{ label: string; path: string }>;
  stacked?: boolean;
  component?: string;
};

export type ReportDetailDto = {
  access?: ReportAccessDto;
  kind: "sub" | "inline";
  title: string;
  key: string;
  inline?: string | null;
  row_component?: string | null;
  actions?: string | null;
  query_available?: boolean;
  columns: ReportColumnDto[];
  row_links: Array<{ label: string; href: string }>;
};

export type ReportIntentDto = {
  contract_id: "sli.report-intent.v1";
  version: number;
  user_role: string;
  question: string;
  action: string;
  scope: string;
  exclusions: string;
  sources: string[];
  freshness_expectation: string;
  rights: string;
  field_classes: string[];
  coverage: string;
  completeness: string;
  denominator: string;
  retention: string;
  provenance: string;
  primary_archetype: "list" | "timeline" | "matrix" | "summary" | "detail" | "queue";
};

export type ReportDefinitionDto = {
  default_domain_id?: number | null;
  default_domain_state?: "available" | "unknown" | "denied" | "unavailable";
  /** Additive passport; older servers and transitional declarations may omit it. */
  intent?: ReportIntentDto | null;
  result_states?: ReportResultState[];
  plugin?: { plugin_id: string; state: "enabled" | "disabled" | "unknown"; read_only: boolean };
  access?: ReportAccessDto;
  key: string;
  section: string;
  title: string;
  description: string;
  archetype: string;
  params: ReportParamDto[];
  columns: ReportColumnDto[];
  views: ReportViewDto[];
  row_key: string;
  detail: "fields" | "none" | ReportDetailDto;
  export: boolean;
  limits: { default: number; max: number };
  presets: Array<{ label: string; params: Record<string, string> }>;
  row_links: Array<{ label: string; href: string }>;
  filter_options: Record<string, ReportOption[]>;
  page_actions?: string | null;
};

export type ReportBranchDto = {
  state: ReportResultState | "not_requested";
  reason: string;
  limitations: Array<{ code: string; text: string; params?: Record<string, string | number | null> }>;
  limits?: Record<string, unknown>;
};

export type PasswordCoverageLossCode = "source_error" | "password_v2_native_unavailable" | "password_v2_window_truncated"
  | "password_v2_xml_budget_exceeded" | "xml_invalid" | "state_bound" | "clock_regression" | "too_late"
  | "coverage_gap" | "gap_native_unavailable" | "prequalification_native_unavailable"
  | "episode_evidence_budget_exhausted" | "prequalification_proof_budget_exhausted";
export type PasswordCoverageReason = PasswordCoverageLossCode | "attempt_stale" | "recent_loss" | "checkpoint_absent" | "policy_unconfirmed";
export type PasswordDetectionCoverage = {
  availability: "observed" | "unavailable";
  as_of: string | null;
  has_more: boolean;
  rows: Array<{
    domain_id: string;
    rule_id: "qw.password-brute-force" | "qw.password-spray";
    scope_ref: string;
    policy_state: "enabled" | "disabled" | "disabled_last_known" | "unknown";
    status: "healthy" | "partial" | "error" | "stale" | "unknown" | "frozen";
    reason: PasswordCoverageReason | null;
    last_attempt_at: string | null;
    last_completed_at: string | null;
    last_successful_cutoff: string | null;
    frozen_episode_count: string;
    evidence_snapshot_as_of: string | null;
    loss: Partial<Record<PasswordCoverageLossCode, {
      count_lower_bound: string; count_exact: boolean;
      from: string | null; to: string | null; observation_window_from: string; as_of: string;
    }>>;
  }>;
};

export type ReportResultDto = {
  domains?: Array<{ id: number; display_name: string; is_archived?: boolean; freshness: { observed_at_utc?: string | null } }>;
  plugin?: ReportDefinitionDto["plugin"];
  access?: ReportAccessDto;
  contract_id: "sli.report-result.v2";
  report_key: string;
  state: ReportResultState;
  state_message?: ApiMessage;
  state_details?: ReportStateDetails;
  items: Array<Record<string, unknown>>;
  has_more: boolean;
  next_cursor: string | null;
  filtered_count: number | null;
  computer_logon_activity?: { days: Array<{ day: string; count: number }>; total: number | null; typical: number | null; top: { account: string; count: number } | null };
  change_counts?: Record<string, number>;
  metrics: Array<{ key: string; label: string; value: number | string | null; quality?: "complete" | "observed" | "unknown"; tone?: "neutral" | "accent" | "success" | "warning" | "danger"; caption?: string; filter?: Record<string, string> }>;
  series: Record<string, unknown>;
  journal_counts?: Record<string, number>;
  journal_event_count?: number;
  coverage: { password_detection?: PasswordDetectionCoverage; open_by_severity?: Record<string, number>; state?: string; completeness?: string; evidence_total_lower_bound?: number | null; evidence_missing_sources?: number; [key: string]: unknown };
  filter_options: Record<string, ReportOption[]>;
  limitations: Array<{ code: string; text: string; params?: Record<string, string | number | null> }>;
  window: { from_utc?: string; to_utc_exclusive?: string; to_utc?: string; local_from_date?: string | null; local_to_date?: string | null; timezone?: string | null; source_domain_id?: number | null; generated_at_utc?: string | null; nps_period_clamped?: boolean };
  collections?: Record<string, Array<Record<string, unknown>>>;
  branches?: Record<string, ReportBranchDto>;
};

export type NavigationViewDto = {
  id: string; label: string; path: string; report_key: string; reports: string[];
};
export type NavigationEntryDto = {
  id: string; label: string; path: string; icon: string;
  plugin_id?: string; reports?: string[]; capabilities?: string[]; always?: boolean;
  views?: NavigationViewDto[];
};
export type NavigationRegistryDto = {
  contract_id: "sli.navigation.v3";
  enabled_plugins: string[];
  global_search?: { path: string; capabilities: string[] };
  redirects?: Array<{ from: string; to: string; view?: string }>;
  sections: Array<{
    id: string; title: string;
    groups: Array<{ id: string; title: string; entries: NavigationEntryDto[] }>;
  }>;
};

export type ReportCatalogV2Dto = {
  contract_id: "sli.report-catalog.v2";
  navigation?: NavigationRegistryDto;
  items: Array<{ key: string; title: string; description: string; section: string; section_title: string; owner_id?: string; navigation_section?: string; executable?: boolean; home_order?: number | null; home_view?: ReportViewDto | null }>;
};

/** Snapshot evidence uses native keys and never carries an EventLog identifier. */
export type CoreEventEvidence = {
  storage_kind: "core_event";
  evidence_id: number;
  event_db_id: number | null;
  event_record_id?: number | null;
  event_id?: number | null;
  hostname?: string | null;
  channel?: string | null;
  time_created_utc?: string | null;
  evidence_role: string;
  note?: string | null;
};
export type FileAclSnapshotEvidence = {
  storage_kind: "file_audit_snapshot";
  evidence_key: string;
  evidence_role: "semantic_scenario";
  availability: "available" | "unavailable";
  observed_at_utc: string | null;
  historical: true;
  resource: { agent_id: string; source_instance_id: string; collection_scope_id: string } | null;
  coverage: { state: "complete" | "partial" | "failed" | "unknown"; unread_objects: number | null; has_more: boolean | null };
  grants: Array<{ path: string; layer: "ntfs" | "smb"; principal: "everyone"; grant_mask: number; severity: "medium" }>;
  grants_has_more: boolean;
  limitations: string[];
};
export type SecurityProblemEvidence = CoreEventEvidence | FileAclSnapshotEvidence;
