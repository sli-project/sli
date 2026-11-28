import { getLocale, t, type MessageKey } from "../i18n";
import { ru } from "../i18n/ru";
import { resolveMessage, type ApiMessage } from "../i18n/messages";
import { localizeReportCatalog, localizeReportDefinition, localizeReportResult, reportMetadataText, reportText } from "../i18n/report-metadata";
import type { ReportCatalogV2Dto, ReportDefinitionDto, ReportResultDto, ReportStateDetails } from "./report-v2-types";
import type { SigmaLiveRulesResponse, SigmaValidationRequest, SigmaValidationResponse, SigmaRuleScope, SigmaRuleListResponse } from "./sigma-types";
import type { PluginSettings } from "./plugin-settings-types";
import type { HomePeriod } from "./home-period";

export type AgentEnrollmentToken = { id: string; token: string; host_id: string; expires_at: string };
export type AdOperationCredential = { credential_id: string; domain_id: number; label: string; username: string;
  credential_revision: number; created_by: string; created_at: string; updated_by: string; updated_at: string;
  check_status: "not_checked" | "unavailable"; checked_at: string | null; password_status: "saved"; usages: string[] };
export type AdCredentialList = { items: AdOperationCredential[]; domains: Array<{ id: number; fqdn: string }>;
  key_status: { available: boolean; error_code: string | null }; write_enabled: false };
export type GpoPlanSelection = { domain_id: number; computer_entity_ids?: number[]; ou_entity_ids?: number[] };
export type GpoCredential = { credential_id: string; credential_revision: number; label: string; username: string;
  check_status: string; eligible: boolean };
export type GpoCredentialBinding = { credential_id: string; credential_revision: number;
  authorization_sha256: string;
  recipient: { agent_id: string; certificate_sha256: string; assignment_revision: number } };
export type GpoPlan = { plan_id: string; plan_sha256: string; domain_id: number; domain_name: string;
  expires_at: string; targets: Array<{ entity_id: number; name: string }>; ou_entity_ids: number[]; ous: Array<{ entity_id: number; name: string }>;
  package: { version?: string; sha256?: string; size_bytes?: number; signature?: "valid" | "invalid" | "unavailable"; signer_sha256?: string };
  credential_binding: GpoCredentialBinding; write_enabled: false; token_ttl_seconds: number };
export type AgentDeploymentBinding = { host_id: string; instance_name: string | null; key_fingerprint: string; computer_entity_id: number };
export type AgentGroupToken = { id: string; group_id: string; domain_id: number; ou_entity_ids: number[]; computer_entity_ids: number[];
  auto_approve: boolean; max_uses: number; uses_count: number; expires_at: string; revoked_at: string | null };
export type AgentTemplate = { id: string; version: number; assigned_modules: AgentItem["assigned_modules"]; collection_policy: AgentCollectionPolicy };
export type AgentDeploymentDirectory = { domains?: Array<{ id: number; name: string }>; ous?: Array<{ id: number; name: string }>;
  computers?: Array<{ id: number; name: string }>; has_more?: boolean };
export type AgentDeploymentRequest = AgentDeploymentBinding & { id: string };
export type AgentUpdateWave = { id: string; version: string; status: "running" | "stopped" | "completed"; confirmed: number; errors: number };
export type AgentCollectionPolicy = { state: "active" | "paused" | "drain"; interval_seconds: number; batch_size: number; rate_limit_per_minute: number; spool_max_bytes: number; manage_windows_audit?: boolean; audit_process_command_line?: boolean; manage_domain_root_sacl?: boolean };
export type AgentWindowsAudit = {
  policy_revision: number; reported_at: string; checked_at?: string;
  management_state: "disabled" | "applied" | "restored" | "blocked" | "unknown";
  command_line_enabled: boolean | null;
  powershell_logging?: { channel_enabled: boolean | null; script_block_logging_enabled: boolean | null };
  families: Partial<Record<"logons" | "processes" | "local_admins" | "protection" | "usb" | "domain_controller", {
    state: "ok" | "missing" | "managed_by_gpo" | "unknown";
    required: Array<{ subcategory: string; guid: string; success: boolean; failure: boolean; actual_success: boolean | null; actual_failure: boolean | null;
      state?: "ok" | "missing" | "managed_by_gpo" | "unknown" | "restored"; detections?: number[]; domain_changes?: boolean; enabled_at?: string | null; policy_name?: string | null }>;
    non_security_channels: string[];
  }>>;
};
export const PASSWORD_DETECTION_DOMAIN_UNAVAILABLE = "password_detection_domain_unavailable";
export type AgentPasswordDetectionDomain = { status: "configured" | "unconfigured"; domain_id: number | null; domain_fqdn: string | null };
export type AgentSequenceRecoveryPreview = { preview_token: string; agent_id: string; observation_ids: string[]; streams: AgentSequenceGap[] };
export type AgentSequenceGap = {
  id: string; agent_id: string; module_id: string;
  expected_sequence: string; received_sequence: string; missing_packets: string;
  observed_at: string; previous_observed_at: string | null; packet_observed_at: string;
  status: "pending" | "authorized" | "accepted";
  loss_event_count: null; loss_time_bounds_known: false;
};

export type AgentDeliveryDiagnostic = {
  module_id: string; packet_id: string; sequence: string; error_code: string;
  receipt_status: "rejected" | "retry_later" | "invalid" | "unavailable";
  http_status: number | null; observed_at_utc: string; resolved_at_utc: string | null;
};
export type AgentDeliveryDiagnostics = { reported_at: string; items: AgentDeliveryDiagnostic[] };
export type AgentMachineRole = "domain_controller" | "file_server" | "workstation";
export type AgentEnrollmentRejection = { id: string; reported_hostname: string | null; occurred_at: string; reason: string };
export type AgentInstallPackage = { server_url: string | null; package_url: string | null; sha256?: string; host_limit?: number | null; expires_at?: string | null };
export type AgentInstallPackageSettings = { server_url: string; host_limit?: number | null; expires_at?: string | null };

export type AgentItem = {
  certificate_rejection_reason?: "untrusted_root" | "unexpected_chain_length" | "wrong_eku" | "expired" | "not_yet_valid" | "revoked" | "invalid_chain";
  delivery_diagnostics?: AgentDeliveryDiagnostics | null;
  password_detection_domain?: AgentPasswordDetectionDomain;
  eventlog_diagnostics?: { reported_at: string; items: Array<{
    channel: string; observed_at_utc: string; policy_revision: number;
    error: { exception_class: string; winerror: number | null; hresult: number | null;
      channel: string; record_id: number | null; bookmark_present: boolean; stage: string } | null;
  }> } | null;
  removal?: { operation_id: string; command_id: string; state: "pending" | "cleanup_failed" | "state_cleaned";
    reason: "agent_removal_requires_admin" | "agent_removal_unmanaged" | "agent_removal_cleanup_failed" | null;
    connection: "online" | "offline" | "never_seen"; requested_at: string; reported_at: string | null } | null;
  id: string; host_id: string; status: "active" | "disabled" | "replaced"; last_seen: string | null;
  machine_role?: AgentMachineRole | null;
  windows_product_type?: "WinNT" | "ServerNT" | "LanmanNT" | null;
  certificate_reissue_required?: boolean; server_id?: number | null; agent_version?: string | null; replacement_version?: string | null; replaced_by?: string | null;
  update?: { status: "updating" | "updated" | "failed"; version: string; reason: string | null } | null;
  created_at?: string;
  inventory_hidden_reason?: "administrator_removed" | "registration_replaced" | "never_seen_expired" | null;
  host_name?: string | null; hostname?: string | null; instance_name?: string | null;
  host_name_source?: "ad_enrollment" | "agent_reported" | "module_config" | "unknown";
  policy_revision: number; applied_policy_revision: number;
  collection_policy?: AgentCollectionPolicy;
  windows_audit?: AgentWindowsAudit | Record<string, never>;
  applied_collection_state?: "unknown" | "active" | "paused";
  policy_audit?: Array<{ id: number; action: "module_assign" | "policy_update" | "policy_ack"; actor: string; occurred_at: string; details: Record<string, unknown> }>;
  assigned_modules: Array<string | { module_id: string; enabled: boolean; config: Record<string, unknown> }>;
  certificates: Array<{ serial: string; not_after: string; revoked_at: string | null }>;
  rights_probe: { pending?: { request_id: string; requested_at: string }; last_result?: { status: "allowed" | "denied" | "unavailable"; policy_revision: number; reported_at: string } };
};

export type RadiusPluginSource = {
  source_instance_id: string;
  source_state: string;
};

export type RadiusPluginSources = { status: string; sources: RadiusPluginSource[] };

export type PluginState = {
  plugin_id: string; package_version: string; installed: boolean; configured: boolean;
  enabled: boolean; receiving_data: boolean; component_runtime: string; queue_state: string;
  revision: number; last_data_at_utc: string | null;
  source_count?: number;
  source_names?: string[];
  status?: {
    state: "disabled" | "no_sources" | "waiting" | "working" | "error";
    reason?: "disabled" | "no_sources" | "no_folders" | "no_collection" | "waiting" | "working" | "status_unavailable" | "collection_delayed" | "collection_failed" | "outdated_agent";
    next_action?: "select_file_folders" | "connect_file_server" | "install_workstation_agent" | "connect_nps" | "connect_sigma_events"
      | "connect_domain_controller" | "check_first_delivery" | "check_collection" | "reload_status" | null;
    last_data_at: string | null;
    error_at: string | null;
    error_object: string | null;
    check_agent_requirement?: { agent_version: string; minimum_version: string } | null;
  };
  data_receipts?: {
    state: "observed" | "no_receipts" | "unavailable" | "not_supported";
    last_received_at: string | null; last_imported_at: string | null;
    last_snapshot_completed_at: string | null;
  };
};

type HomeReportLink = { key: string; title: string; href: string };
export type HomeDecisionGroup = {
  key: string; title: string; title_message?: import("../i18n/messages").ApiMessage | null;
  severity: string; total: number; new_count: number | null; last_seen_utc: string | null;
  assigned_to: string | null; assignee_state?: "assigned" | "unassigned" | "mixed" | "unknown";
  unassigned_count?: number | null; day?: string | null; identity_state?: string | null;
  objects: Array<{ name: string; domain: string | null; identifier?: string; snapshot_name?: boolean;
    name_state?: "named" | "literal" | "no_match" | "ambiguous" | "unverified" | "unavailable";
    source?: { observed_at_utc?: string; source_run_id?: string; event_db_id?: number } }>;
  object_count: number | null; href: string;
};
export type HomeDecisionSummary = {
  contract_id: "sli.home-summary.v3"; time_zone: string; state: ReportResultDto["state"];
  total: number | null; new_count: number | null; previous_login_at: string | null;
  updated_at_utc: string | null; groups: HomeDecisionGroup[];
  remaining_groups: number | null; remaining_problems: number | null; href: string;
  warnings: Array<{ domain: string; reason_code: string; href: string }>;
  agent_link_warning?: { reason_code: "home.queue.warning.agent_link_unstable" | "home.queue.warning.agent_link_unknown";
    agent_count?: number; window_from_utc?: string; window_to_utc?: string; observed_at_utc: string; href: string } | null;
};
export type WorkspaceDomain = { id: number; display_name: string; is_archived?: boolean;
  freshness: { snapshot_state?: string | null; observed_at_utc?: string | null } };
export type HomeSummary = {
  contract_id: "sli.home-summary.v1";
  freshness: Array<HomeReportLink & { state: ReportResultDto["state"]; reason?: string | null; observed_at_utc: string | null; limitation: string | null; last_successful_check_utc?: string | null; event_at_utc?: string | null; snapshot_at_utc?: string | null; published_at_utc?: string | null; state_details?: ReportStateDetails }>;
  deviations: Array<{ report_key: string; key: string; report_title: string; label: string; value: number; tone: string; href: string }>;
  action_queue: { state: ReportResultDto["state"]; has_more: boolean; items: Array<{ id: number; title: string; severity: string; assigned_to: string | null; href: string }> };
  reports: HomeReportLink[];
  pinned: HomeReportLink[];
};

type HomeStatement = { state: ReportResultDto["state"] | "unknown"; message_code: string; text?: string };
export type HomeComparison = {
  state: "missing" | "incomparable" | "comparable"; message_code: string;
  absolute_change: number | null; percent_change: number | null; tone: "neutral" | "danger" | "success";
};
export type HomeMeasurement = {
  key: string; report_key: string; label_code: string; unit_code: string; value: number | null;
  state: ReportResultDto["state"]; message_code: string; href: string | null; definition_version: number;
  period_kind: "snapshot" | "observations"; window: { from_utc: string; to_utc: string } | null;
  scope: { mode: string; domain_ids: number[] | null } | null; observed_at_utc: string | null; comparison: HomeComparison;
};
export type HomeAttentionItem = {
  id: string; problem_id?: number; kind: "problem" | "observation" | "ad_check"; priority_group: number;
  severity: string | null; needs_decision: boolean; repeat_count: number; observed_at_utc: string | null;
  repeated?: boolean;
  message_code: string; title?: string | null; title_code?: string | null;
  what?: string | null; what_code?: string | null; object?: string | { report_key: string } | null; object_code?: string | null;
  why?: string | null; why_code?: string | null; next_step?: string | null; next_step_code?: string | null; href: string;
};
export type HomeSummaryV2 = Omit<HomeSummary, "contract_id" | "action_queue"> & {
  contract_id: "sli.home-summary.v2";
  domains?: Array<WorkspaceDomain & { summary: {
    problems_found?: { count: number | null }; observation_health?: { state: string };
  } }>;
  context: { scope: "accessible" | "domain"; domain_id: number | null; time_zone: string;
    period: { preset: string; kind: "snapshot" | "observations"; as_of_utc?: string; from_utc?: string; to_utc?: string } };
  generated_at_utc: string;
  kpis?: HomeMeasurement[];
  readers: Array<HomeSummary["freshness"][number] & { message_code: string; contribution_key?: string; period_kind: "snapshot" | "observations";
    scope: { mode: string; domain_ids: number[] | null } | null }>;
  observation_health: HomeStatement;
  problems_found: HomeStatement & { count: number | null; href: string };
  action_queue: { state: ReportResultDto["state"]; has_more: boolean; items: HomeAttentionItem[] };
};

function localizeHomeSummaryV2(summary: HomeSummaryV2): HomeSummaryV2 {
  const text = (code: string | null | undefined, fallback?: string | null, params?: Record<string, string | number>) =>
    code && Object.hasOwn(ru, code) ? t(code as MessageKey, params) : fallback;
  return { ...summary,
    reports: summary.reports.map((item) => ({ ...item, title: reportMetadataText(item.key, "title", item.title) })),
    pinned: summary.pinned.map((item) => ({ ...item, title: reportMetadataText(item.key, "title", item.title) })),
    freshness: summary.freshness.map((item) => ({ ...item, title: reportMetadataText(item.key, "title", item.title), limitation: item.limitation ? reportText(item.limitation) : null })),
    readers: summary.readers.map((item) => ({ ...item, title: reportMetadataText(item.key, "title", item.title), limitation: item.limitation ? reportText(item.limitation) : null })),
    deviations: summary.deviations.map((item) => ({ ...item, report_title: reportMetadataText(item.report_key, "title", item.report_title), label: reportMetadataText(item.report_key, `metrics.${item.key}.label`, item.label) })),
    observation_health: { ...summary.observation_health, text: text(summary.observation_health.message_code) ?? undefined },
    problems_found: { ...summary.problems_found, text: text(summary.problems_found.message_code, null, { count: summary.problems_found.count ?? "" }) ?? undefined },
    action_queue: { ...summary.action_queue, items: summary.action_queue.items.map((item) => ({ ...item,
      title: text(item.title_code ?? (item.title ? null : item.message_code), item.title, { id: item.problem_id ?? item.id }),
      what: text(item.what_code, item.what), why: text(item.why_code, item.why), next_step: text(item.next_step_code, item.next_step),
      object: item.object_code ? text(item.object_code) : item.object,
    })) },
  };
}

function localizeHomeSummary(summary: HomeSummary): HomeSummary {
  const link = <T extends HomeReportLink>(item: T): T => ({ ...item, title: reportMetadataText(item.key, "title", item.title) });
  return { ...summary, reports: summary.reports.map(link), pinned: summary.pinned.map(link),
    freshness: summary.freshness.map((item) => ({ ...link(item), limitation: item.limitation ? reportText(item.limitation) : null })),
    deviations: summary.deviations.map((item) => ({ ...item,
      report_title: reportMetadataText(item.report_key, "title", item.report_title),
      label: reportMetadataText(item.report_key, `metrics.${item.key}.label`, item.label),
    })),
  };
}

export type EventItem = {
  event_db_id: number;
  event_id: number;
  time_created_utc?: string | null;
  server?: string | null;
  channel?: string | null;
  provider_name?: string | null;
  label?: string;
  category?: string;
  purpose_tier?: string;
  base_risk?: string;
  final_risk?: string;
  confidence?: string;
  noise_class?: string;
  subject?: string;
  target?: string;
  severity?: string;
  assessment_confidence?: string;
  classification_origin?: "catalog_base" | "contextual_rule" | "unavailable";
  card_completeness?: "complete" | "partial" | "not_applicable";
  display_labels?: { risk?: string; confidence?: string };
  relation_count?: number | null;
  summary?: string;
};

export type EventsResponse = {
  api_version: "v1";
  items: EventItem[];
  next_cursor?: string | null;
  has_more: boolean;
  query_status: "ok" | "timeout" | "empty";
  warning?: string | null;
  category_counts?: Record<string, number> | null;
};

export type Bootstrap = {
  api_version: "v1";
  principal?: { username?: string; role?: string } | null;
  effective_role: "viewer" | "operator" | "admin";
  navigation: Array<{ id: string; label: string; path: string }>;
  api_time_contract: string;
  access_model?: "composite_v4";
  capabilities?: string[];
  packages?: Array<{ key: string; name: string }>;
  allowed_report_count?: number;
};

export type V4Report = {
  report_key: string; version: number; name: string; owner: string; purpose: string;
  dataset_key: string; dataset_version: number; sensitivity: string; status: string;
  target_path: string; allowed: boolean; explanation: string; explanation_code?: string; missing_capabilities: string[];
  discoverable?: boolean; requestable?: boolean;
  access_state?: "available" | "available_until" | "requestable" | "request_pending" | "request_rejected" | "request_unavailable";
  access_valid_until?: string | null;
  request?: { id: number; status: string; created_at: string; updated_at: string; decision_reason?: string | null } | null;
  request_profile?: {
    scope_kinds?: string[]; field_categories?: string[];
    allowed_actions?: string[]; max_duration_days?: number;
  };
  resource_context_required?: boolean;
  assignment_version_state?: "owner" | "compatible" | "requires_review" | "not_assigned";
  field_categories: string[]; allowed_actions: string[]; scopes: Array<Record<string, unknown>>;
  sources: Array<{ source_type: string; source: string; valid_until?: string | null }>;
  grants?: Array<{ scope: Record<string, unknown>; allowed_actions: string[]; field_categories: string[] }>;
  pinned: boolean;
  preference_supported?: boolean;
  preference_updated_at?: string | null;
  dashboard_metrics?: Array<{
    key: string; label: string; caption: string; kind: "required" | "optional";
    value_path: string; freshness_path?: string | null; unit?: string | null;
    icon: string; tone: string; priority: number; target_path: string;
    filters: Record<string, string | number | boolean | null>;
    default_selected?: boolean;
  }>;
  selected_optional_metric_keys?: string[];
  focus_preference_configured?: boolean;
};

export type V4Access = {
  api_version: "v4"; evaluated_at_utc: string; preview: boolean; platform_owner?: boolean;
  owner_policy?: { key?: string; full_product_access?: boolean; surveyed_system_write_access?: boolean };
  subject: { type: string; id?: number | null; username: string; coarse_role: string };
  groups: Array<{ id: number; key: string; name: string; source: string; valid_until?: string | null }>;
  packages: Array<{ key: string; name: string }>;
  package_explain: Array<Record<string, unknown>>; capabilities: string[]; resource_bound_capabilities?: string[];
  capability_explain: Record<string, Array<Record<string, unknown>>>;
  capability_policies?: Array<Record<string, unknown>>;
  quarantined_capability_assignments?: Array<Record<string, unknown>>;
  resource_bound_capability_assignments?: Array<Record<string, unknown>>;
  reports: V4Report[];
  allowed_report_count: number; navigation: Array<{ id: string; label: string; path: string }>;
  explicit_denies: { packages: string[]; capabilities: string[]; reports: string[] };
  ignored_denies?: { packages: string[]; capabilities: string[]; reports: string[] };
};

export type V4ReportAccessTrace = {
  api_version: "v4";
  evaluated_at_utc: string;
  subject: { username: string; coarse_role: string };
  report: { report_key: string; name: string; version: number };
  decision: "allowed" | "denied";
  explanation: string;
  platform_owner: boolean;
  owner_policy: { full_product_access?: boolean; surveyed_system_write_access?: boolean };
  exact_deny: boolean;
  ignored_deny: boolean;
  missing_capabilities: string[];
  assignment_version_state: string;
  grants: Array<{
    source_type: string; source: string; scope: Record<string, unknown>;
    field_categories: string[]; allowed_actions: string[];
    valid_from?: string | null; valid_until?: string | null;
    validated_report_version?: number | null; validated_dataset_version?: number | null;
  }>;
};

export type V4ObjectItem = {
  object_type: string; object_id: string; display_name: string; natural_key?: string | null;
  first_seen_utc?: string | null; last_seen_utc?: string | null; observed_at_utc?: string | null;
  source: string; freshness?: string;
};

export type V4Workspace = {
  api_version: "v4"; state: string; subject: V4Access["subject"];
  packages: V4Access["packages"]; groups: V4Access["groups"]; capabilities: string[];
  reports: V4Report[]; recent_objects: V4ObjectItem[];
  focus_metrics: Array<{
    key: string; label: string; caption: string; kind: "required" | "optional";
    value: string | number | null; unit?: string | null; state: string;
    freshness?: string | null; source: string; priority: number; report_key: string;
    target_path: string; filters: Record<string, string | number | boolean | null>;
    icon: string; tone: string;
  }>;
  composition: { package_count: number; group_count: number; direct_report_count: number; allowed_report_count: number; explicit_deny_count: number };
  limits: Record<string, unknown>;
};

export type V4Dataset = {
  dataset_key: string; version: number; name: string; object_type?: string | null;
  fields_json: Array<{ key: string; label: string; category: string }>;
  filters_json: Array<{ key: string; ops: string[] }>; actions_json: string[]; status: string;
  executable?: boolean; executable_filter_keys?: string[]; executable_sort_keys?: string[];
};

export type V4ReportAssignment = {
  id: number; subject_type: string; subject_id: number; report_key: string; effect: string;
  source_type: string; scope_json: Record<string, unknown>; field_categories: string[];
  allowed_actions: string[]; valid_until?: string | null; business_reason: string; created_at: string;
};

export type V4PackageAssignment = {
  id: number; subject_type: string; subject_id: number; package_key: string; package_name: string;
  effect: string; source_type: string; valid_from?: string | null; valid_until?: string | null;
  business_reason: string; approved_by?: string | null; created_at: string;
};

export type V4PackageOption = {
  package_key: string; name: string; description?: string;
  capabilities?: string[]; reports?: string[];
};

export type V4AccessSubjects = {
  users: Array<{ id: number; username: string; role: string; is_active: boolean; is_service: boolean }>;
  groups: Array<{ id: number; group_key: string; name: string; description?: string }>;
  packages: V4PackageOption[];
  assignments: V4ReportAssignment[];
  package_assignments?: V4PackageAssignment[];
};

export type V4AccessAuditItem = {
  id: number; actor_type: string; actor_id?: number | null; action: string;
  subject_type?: string | null; subject_id?: number | null; target_key?: string | null;
  reason?: string | null; outcome: string; details_json?: Record<string, unknown>; created_at: string;
};

export type V4ReportAccessRequest = {
  id: number;
  requester_user_id: number;
  username: string;
  report_key: string;
  report_name: string;
  report_version: number;
  dataset_version: number;
  requested_scope_json: Record<string, unknown>;
  requested_valid_until: string;
  business_reason: string;
  requested_field_categories: string[];
  requested_actions: string[];
  status: "submitted" | "reviewing" | "approved" | "approved_limited" | "rejected" | "expired" | "system_cancelled";
  decision_reason?: string | null;
  granted_scope_json?: Record<string, unknown> | null;
  granted_valid_until?: string | null;
  granted_field_categories?: string[] | null;
  granted_actions?: string[] | null;
  assignment_id?: number | null;
  created_at: string;
  updated_at: string;
};

export type V4ReportDefinition = {
  report_key: string; version: number; name: string; owner_name: string; purpose: string;
  presentation_messages?: Partial<Record<"name" | "purpose", ApiMessage>>;
  sensitivity: string; status: string; dataset_key: string; dataset_version: number;
  published_at?: string | null; created_at: string;
  discoverable?: boolean; requestable?: boolean; assignment_count?: number; package_count?: number; code_defined?: boolean;
};

export type V4ReportDefinitionVersion = {
  report_key: string; version: number; name: string; owner_name: string; purpose: string; sensitivity: string; status: string;
  definition_json: { columns?: string[]; filters?: Array<{ field: string; op: string; value: unknown }>; sort?: Array<{ field: string; direction: string }>; actions?: string[] } | null;
  discoverable: boolean; requestable: boolean; published_at?: string | null; created_by?: number | null; dataset_key: string;
};

export type V4ReportDefinitionDetail = {
  api_version: "v4"; report_key: string; code_defined: boolean; versions: V4ReportDefinitionVersion[];
  assignment_count: number; package_count: number;
};

export type V4BuilderPreview = {
  status: "accepted" | "gated"; required_capabilities: string[]; missing_capabilities: string[]; required_field_categories: string[];
  sample_rows?: Array<Record<string, unknown>>; sample_columns?: Array<{ key: string; label: string }>;
  sample_state?: "rows" | "empty" | "gated" | "not_requested_no_data_disclosure";
};

/** Сводка доступа к отчёту (backend может ещё не отдавать её: тогда 404 и экран деградирует). */
export type V4ReportAccessSummary = {
  assignments?: Array<Record<string, unknown>>; packages?: Array<Record<string, unknown>>; pending_requests?: number | unknown[];
};

export type V4ReportGrantOption = {
  report_key: string; version: number; name: string; purpose: string; sensitivity: string;
  dataset_key: string; field_categories: Array<{ key: string; label: string }>;
  allowed_actions: string[]; required_capabilities: string[];
  scope_kinds: Array<"all" | "server" | "domain" | "channel">;
};

export type V4ReportData = {
  api_version: "v4";
  report: V4Report;
  dataset_key: string;
  state: string;
  items: Array<Record<string, unknown>>;
  fields: Array<{ key: string; label: string; category: string }>;
  /**
   * Поля, фактически выданные назначением доступа.
   *
   * Отличается от `fields`: сервер объявляет контракт датасета, а сюда попадает
   * только то, что видит текущий читатель. Колонка, которой здесь нет, не имеет
   * права рисоваться пустой — иначе «скрыто доступом» неотличимо от
   * «значения нет».
   */
  grant_branch_fields?: string[];
  field_visibility?: string;
  has_more: boolean;
  next_cursor?: string | null;
  limits: Record<string, unknown>;
  summary?: {
    kind: string;
    aggregate_scope?: string;
    total_objects?: number;
    by_entity_type?: Array<{ entity_type: string; count: number }>;
    without_observation_count?: number;
    latest_observed_at_utc?: string | null;
    total_relations?: number;
    unique_subjects?: number;
    unique_target_groups?: number;
    total_gpo?: number;
    missing_owner_count?: number;
    manual_review_count?: number;
    /**
     * Серверные агрегаты GPO по всей разрешённой области, задание `56`.
     *
     * До 02.08.2026 обзор GPO считал эти числа в браузере по загруженной
     * странице `100` строк. Совпадали они с полным множеством случайно —
     * политик около `72`, — и начали бы занижать на `101`-й молча.
     *
     * `manual_review_basis` публикуется машиночитаемо, потому что подпись
     * «требуют оценки» обязана предъявлять своё условие: раньше это число
     * было равно `total_gpo` и отвечало на другой вопрос.
     *
     * `executable_component_risk_qualified` намеренно `false`: наличие
     * скрипта или службы в политике штатно, а без источника, подписи,
     * учётной записи запуска и области это инвентарь, а не риск.
     */
    unlinked_policy_count?: number;
    disabled_policy_count?: number;
    partially_enabled_policy_count?: number;
    executable_component_policy_count?: number;
    executable_component_total_count?: number;
    executable_component_risk_qualified?: boolean;
    manual_review_basis?: string[];
    /** `not_collected` означает несобранный атрибут, а не отсутствие владельцев. */
    owner_observation_state?: "collected" | "not_collected" | string;
    inactive_threshold_days?: number;
    total_users?: number;
    enabled_users?: number;
    disabled_users?: number;
    unknown_account_state_users?: number;
    inactive_users?: number;
    password_never_expires_users?: number;
    privileged_overlap_users?: number;
    account_controls?: {
      observed_users?: number;
      disabled_users?: number;
      inactive_users?: number;
      password_never_expires_users?: number;
      locked_users?: number;
    };
    /**
     * Серверные агрегаты по компьютерам. Считаются в `_ad_snapshot_summary`
     * с самого начала, но фронтовый тип их не принимал — и экран показывал
     * 1327 компьютеров списком имён, теряя готовое распределение ОС.
     */
    computer_controls?: {
      observed_computers?: number;
      disabled_computers?: number;
      inactive_computers?: number;
      computers_with_operating_system?: number;
      operating_system_distribution?: Array<{ operating_system?: string; operating_system_version?: string | null; count?: number }>;
    };
    collection?: Record<string, {
      state: "complete" | "partial" | "failed" | "skipped" | "not_collected" | string;
      domain_count: number;
      complete_domain_count: number;
      partial_domain_count: number;
      failed_domain_count: number;
      skipped_domain_count: number;
      latest_observed_at_utc?: string | null;
    }>;
    limitations?: string[];
  };
};

export type VpnSessionSources = {
  contract_id: "sli.vpn-session-report.v1";
  report_key: "vpn.audit";
  state: "available" | "not_collected" | "not_authorized";
  items: Array<{ source_domain_id: number }>;
  bounded: true;
  limit: 100;
  has_more: boolean;
};

export type VpnSessionReport = {
  contract_id: "sli.vpn-session-report.v1";
  report_key: "vpn.audit";
  source_domain_id: number;
  state: "available" | "partial" | "processing" | "identity_incomplete" | "not_collected" | "not_authorized";
  branches: Record<string, {
    branch: string;
    state: "available" | "not_authorized";
    reason: string;
    dataset_or_resource_group: string;
    required_capability?: string | null;
  }>;
  coverage: {
    domain_id: number;
    total_delivery_count: number;
    queued_delivery_count: number;
    leased_delivery_count: number;
    failed_delivery_count: number;
    delivered_delivery_count: number;
    quarantined_delivery_count: number;
    projected_receipt_count: number;
    identity_unresolved_count: number;
    timestamp_unresolved_count: number;
    projected_session_count: number;
    history_available_from_utc?: string | null;
    history_available_to_utc?: string | null;
  } | null;
  items: Array<{
    session_row_id: string;
    entity_id: number;
    domain_id: number;
    generation: number;
    lifecycle_state: "closed" | "open_observed" | string;
    completeness: "complete" | "partial" | string;
    started_at_utc?: string | null;
    last_observed_at_utc?: string | null;
    stopped_at_utc?: string | null;
    duration_seconds?: number | null;
    observation_count: number;
    anomalies: string[];
    updated_at?: string | null;
  }>;
  page: { limit: number; offset: number; has_more: boolean };
  time_range?: {
    from_utc?: string | null;
    to_utc_exclusive?: string | null;
    timezone: string;
  };
};

export type VpnSessionEvidenceObservation = {
  observation_id: string;
  lifecycle_event: string;
  observed_at_utc?: string | null;
  evidence: {
    evidence_uid: string;
    source_instance_id: string;
    stream_id: string;
    transport_binding: string;
    object_reference: string;
    canonical_record_sha256: string;
    object_sha256: string;
    object_size_bytes: number;
    verified_at_utc?: string | null;
  };
};

export type VpnSessionEvidenceLifecycle = {
  lifecycle_state: string;
  completeness: string;
  started_at_utc?: string | null;
  last_observed_at_utc?: string | null;
  stopped_at_utc?: string | null;
  duration_seconds?: number | null;
  observation_count: number;
  anomalies: string[];
  stop_evidence: VpnSessionEvidenceObservation["evidence"][];
  incomplete_reason?: string | null;
};

export type VpnSessionEvidence = {
  contract_id: "sli.vpn-session-evidence.v1";
  report_key: "vpn.audit";
  source_domain_id: number;
  session_row_id: string;
  state: "available" | "not_authorized" | string;
  branch: {
    branch: string;
    state: string;
    reason: string;
    dataset_or_resource_group: string;
    required_capability?: string | null;
  };
  lifecycle: VpnSessionEvidenceLifecycle | null;
  observations: VpnSessionEvidenceObservation[];
  limits?: { observation_limit: number; bounded: boolean };
};

export type VpnFailedAuthorizationIdentity = {
  entity_id: number | null;
  display_name?: string;
  account_name?: string;
  department?: string;
  observed_subject_sid?: string | null;
};

export type VpnFailedAuthorizationEventReference = {
  event_db_id: number;
  event_record_id?: number | null;
  event_id: number;
  time_created_utc: string;
  source_core_sha256?: string | null;
};

export type VpnFailedAuthorizationSeriesItem = {
  series_state: "grouped" | "single_event_unattributed";
  event_id: number;
  identity_state: "resolved" | "ambiguous" | "unresolved";
  identity: VpnFailedAuthorizationIdentity;
  source_state: "available" | "unavailable";
  source_ip?: string | null;
  count: number;
  first_failed_at_utc: string;
  last_failed_at_utc: string;
  time_bounds: { from_utc: string; to_utc_exclusive: string };
  reason_codes: string[];
  reason_codes_truncated: boolean;
  event_references: VpnFailedAuthorizationEventReference[];
  event_references_truncated: boolean;
};

export type VpnFailedAuthorizationCollectionCoverage = {
  state: "available" | "not_collected" | "empty_unverified" | "coverage_unverified";
  history_event_count: number;
  window_success_6272_count: number;
  window_failed_6273_count: number;
  empty_window_basis?: "durable_6272_nps_event" | null;
  source_completeness: string;
  freshness: string;
};

export type VpnFailedAuthorizationSeries = {
  contract_id: "sli.vpn-audit-failed-authorization-series.v1";
  report_key: "vpn.audit";
  source_domain_id: number;
  state: "available" | "not_authorized" | "not_collected" | "empty_unverified" | "coverage_unverified";
  time_bounds: { from_utc: string; to_utc_exclusive: string };
  items: VpnFailedAuthorizationSeriesItem[];
  collection_coverage?: VpnFailedAuthorizationCollectionCoverage;
  limits: { input_event_limit: number; series_limit: number; event_reference_limit: number; bounded: boolean };
};

export type VpnAuthorizationTimelineItem = {
  event_db_id: number;
  event_record_id?: number | null;
  event_id: 6272 | 6273;
  time_created_utc: string;
  authorization_result: "allowed" | "denied";
  identity_state: "resolved" | "ambiguous" | "unresolved";
  identity: VpnFailedAuthorizationIdentity;
  source_ip?: string;
  correlation_id?: string;
  reason_code?: string;
  source_core_sha256?: string | null;
};

export type VpnAuthorizationTimelineCoverage = {
  state: "available" | "not_collected" | "empty_unverified" | "coverage_unverified";
  history_event_present: boolean;
  window_success_6272_count: number;
  window_failed_6273_count: number;
  empty_window_basis?: "durable_6272_nps_event" | null;
  source_completeness: string;
  freshness: string;
};

export type VpnAuthorizationTimeline = {
  contract_id: "sli.vpn-audit-authorization-timeline.v1";
  report_key: "vpn.audit";
  source_domain_id: number;
  state: "available" | "not_authorized" | "not_collected" | "empty_unverified" | "coverage_unverified";
  time_bounds: { from_utc: string; to_utc_exclusive: string };
  items: VpnAuthorizationTimelineItem[];
  collection_coverage?: VpnAuthorizationTimelineCoverage;
  limits: { input_event_limit: number; bounded: boolean };
};

export type VpnWindowsAuthenticationSources = {
  contract_id: "sli.vpn-audit-windows-authentication.v1";
  report_key: "vpn.audit";
  state: "available" | "not_collected" | "not_authorized";
  items: Array<{ source_domain_id: number }>;
  bounded: true;
  limit: number;
  has_more: boolean;
};

export type VpnWindowsAuthenticationEventReference = {
  event_db_id: number;
  event_record_id?: number | null;
  event_id: number;
  time_created_utc: string;
};

export type VpnWindowsAuthenticationItem = {
  event_db_id: number;
  event_record_id?: number | null;
  event_id: number;
  time_created_utc: string;
  domain_controller: string;
  authentication_fact: string;
  target: { state: "observed" | "unknown"; target_user_sid?: string; target_user_name?: string };
  principal: {
    role: "target_account" | "subject_account";
    state: "observed" | "unknown";
    principal_user_sid?: string;
    principal_user_name?: string;
  };
  source: { state: "observed" | "unknown"; source_ip?: string; workstation_name?: string };
  source_native: { logon_type?: string; result_code?: string; process_name?: string; target_server_name?: string };
  outcome?: { state: "observed" | "unknown"; result?: "success" | "failure"; result_code?: string };
  evidence: {
    event_db_id: number;
    event_record_id?: number | null;
    source_core_sha256?: string | null;
    source_facts_sha256?: string | null;
  };
  earlier_observed_failures_in_window?: {
    state: "observed" | "unknown";
    reason?: string;
    event_references?: VpnWindowsAuthenticationEventReference[];
  };
};

export type VpnWindowsAuthenticationReport = {
  contract_id: "sli.vpn-audit-windows-authentication.v1";
  report_key: "vpn.audit";
  source_domain_id: number;
  state: "available" | "not_authorized" | "not_collected" | "empty_unverified" | "coverage_unverified";
  time_bounds: { from_utc: string; to_utc_exclusive: string };
  items: VpnWindowsAuthenticationItem[];
  collection_coverage?: { state: string; history_event_present?: boolean; source_completeness?: string };
  manual_review_policy?: {
    id: string;
    version: string;
    coverage_scope?: "whole_period" | "displayed_sample";
    distributed_conditions?: {
      rolling_window_hours: number;
      minimum_distinct_target_sids: number;
      minimum_distinct_sources: number;
      maximum_failures_per_target: number;
    };
    signals_truncated?: boolean;
    signal_limit?: number;
    signal_selection?: string;
    conditions: {
      minimum_failure_facts: number;
      minimum_distinct_target_sids: number;
      source_ip: string;
      rolling_window_minutes: number;
    };
    time_bounds: { from_utc: string; to_utc_exclusive: string };
    state: "manual_review_signal" | "no_observed_signal_unverified";
    signals: Array<{
      state: "manual_review_signal";
      rule?: "single_ip" | "distributed";
      source_ip: string | null;
      window: { from_utc: string; to_utc_exclusive: string };
      failure_fact_count: number;
      distinct_target_sid_count: number;
      distinct_source_count?: number;
      evidence_event_db_id?: number;
      event_references: VpnWindowsAuthenticationEventReference[];
      not_a_verdict: true;
    }>;
    not_a_verdict: true;
  };
  result_window?: { display_limit: number; returned_event_count: number; truncated: boolean };
  limits: { max_period_days: number; display_limit: number; max_display_limit: number; bounded: true };
  limitations?: string[];
};

export type DcPowershellActor =
  | { state: "unknown" }
  | { state: "observed"; subject_user_sid?: string | null; subject_user_name?: string | null };

export type DcPowershellActivityDetail =
  | { state: "unknown"; kind: "command" | "script_block" }
  | { state: "observed"; kind: "command"; command_name?: string }
  | { state: "observed"; kind: "script_block"; script_block_text: string }
  | { state: "restricted"; kind: "script_block" };

export type DcPowershellOriginEvidence = {
  process_start_event_db_id?: number | null;
  process_stop_event_db_id?: number | null;
  session_start_event_db_id?: number | null;
  session_end_event_db_id?: number | null;
  boot_start_event_db_id?: number | null;
};

export type DcPowershellOrigin =
  | { state: "unknown"; reason: "no_complete_native_origin_chain" | "origin_crosses_security_boot_boundary" | "native_rdp_source_missing" | "ambiguous_complete_native_origin_chain" }
  | { state: "observed"; kind: "powershell_remoting" | "rdp" | "local"; evidence: DcPowershellOriginEvidence; source_ip?: string; workstation_name?: string };

export type DcPowershellEvidence = {
  event_db_id: number;
  event_record_id?: number | null;
  source_core_sha256?: string | null;
  source_facts_sha256?: string | null;
};

export type DcPowershellActivityItem = {
  event_db_id: number;
  event_record_id?: number | null;
  event_id: 4103 | 4104;
  time_created_utc: string;
  domain_controller: string;
  actor: DcPowershellActor;
  activity: DcPowershellActivityDetail;
  origin: DcPowershellOrigin;
  evidence: DcPowershellEvidence;
};

export type DcPowershellActivity = {
  contract_id: "sli.dc-powershell-activity.v1";
  report_key: "dc.powershell.activity";
  source_domain_id: number;
  state: "available" | "not_authorized" | "not_collected" | "coverage_unverified";
  time_bounds: { from_utc: string; to_utc_exclusive: string };
  items: DcPowershellActivityItem[];
  collection_coverage?: { state: string; history_event_present: boolean; source_completeness: string };
  limits: { input_event_limit: number; origin_context_days: number; bounded: boolean };
  limitations?: string[];
};

export type AdAccountChangeSubject =
  | { state: "unknown" }
  | { state: "observed"; target_user_sid?: string | null; target_user_name?: string | null };

export type AdAccountChangeActor =
  | { state: "unknown" }
  | { state: "observed"; subject_user_sid?: string | null; subject_user_name?: string | null };

export type AdAccountPasswordOperationKind = "password_change_attempt" | "password_reset_attempt";

export type AdAccountChangeKind = "created" | "enabled" | "disabled" | "deleted" | "attributes_changed" | "locked" | "unlocked" | "renamed" | AdAccountPasswordOperationKind;

export type AdAccountChange =
  | { kind: Exclude<AdAccountChangeKind, AdAccountPasswordOperationKind>; detail?: { state: "unknown"; reason: string } }
  | { kind: AdAccountPasswordOperationKind; result?: { state: "observed"; value: string } };

export type AdAccountObservedState = "present" | "enabled" | "disabled" | "deleted" | "locked" | "unlocked";

export type AdAccountChangeTransitionBefore =
  | { state: "unknown"; reason: string }
  | { state: "observed"; value: string }
  | { state: "partial"; last_observed: { value: AdAccountObservedState | string; event_db_id: number; time_created_utc: string }; reason: string };

export type AdAccountChangeTransitionAfter =
  | { state: "unknown"; reason: string }
  | { state: "observed"; value: string };

export type AdAccountChangeHistoryItem = {
  event_db_id: number;
  event_record_id?: number | null;
  event_id: number;
  time_created_utc: string;
  domain_controller: string;
  account: AdAccountChangeSubject;
  actor: AdAccountChangeActor;
  change: AdAccountChange;
  observed_transition: { before: AdAccountChangeTransitionBefore; after: AdAccountChangeTransitionAfter };
  evidence: {
    state?: "complete" | "partial";
    missing_fields?: string[];
    event_db_id: number;
    event_record_id?: number | null;
    source_core_sha256?: string | null;
    source_facts_sha256?: string | null;
  };
};

export type AdAccountChangeHistory = {
  contract_id: "sli.ad-account-change-history.v1";
  report_key: "ad.state.account_changes";
  source_domain_id: number;
  state: "available" | "empty_unverified" | "not_collected" | "not_authorized";
  history_state: "partial" | "unknown";
  time_bounds: { from_utc: string; to_utc_exclusive: string };
  items: AdAccountChangeHistoryItem[];
  collection_coverage?: { state: string; history_event_present: boolean; source_completeness: string };
  limits: { max_period_days: number; row_limit: number; bounded: boolean };
  limitations?: string[];
};

export type AdAccountChangeSources = {
  contract_id: "sli.ad-account-change-history.v1";
  report_key: "ad.state.account_changes";
  state: "available" | "not_collected" | "not_authorized";
  items: Array<{ source_domain_id: number }>;
  bounded: true;
  limit: number;
  has_more: boolean;
};

export type VpnConnectionsIdentity = {
  entity_id: number;
  display_name: string;
  account_name: string;
  department: string;
  enabled?: boolean | null;
  last_logon_utc?: string | null;
  privileged: boolean;
};

export type VpnConnectionsSession = {
  session_row_id: string;
  lifecycle_state: string;
  completeness: string;
  started_at_utc?: string | null;
  last_observed_at_utc?: string | null;
  stopped_at_utc?: string | null;
  duration_seconds?: number | null;
  confirmed_seconds_in_period?: number | null;
  effective_start_utc?: string | null;
  effective_stop_utc?: string | null;
  observation_count: number;
  overlap_violation: boolean;
  anomalies: string[];
  evidence_links: unknown[];
  evidence_state: string;
};

export type VpnConnectionsEmployee = VpnConnectionsIdentity & {
  closed_session_count: number;
  open_session_count: number;
  confirmed_seconds?: number | null;
  confirmed_minutes?: number | null;
  overlap_violation: boolean;
  overlap_count: number;
  days_with_observed_start: number;
  session_count: number;
  session_details_has_more: boolean;
  sessions: VpnConnectionsSession[];
};

export type VpnConnectionsReport = {
  contract_id: "sli.vpn-connections-report.v1";
  report_key: "vpn.connections";
  source_domain_id: number;
  state: "available" | "partial" | "processing" | "identity_incomplete" | "not_collected" | "not_authorized";
  office_timezone: string;
  generated_at_utc?: string;
  period: { from_utc: string; to_utc_exclusive: string; local_from_date?: string; local_to_date?: string };
  coverage: Record<string, number | string | null | undefined>;
  employees: VpnConnectionsEmployee[];
  employee_page: { limit: number; offset: number; has_more: boolean; filtered_count: number };
  analytics: {
    employee_count: number;
    closed_session_count: number;
    confirmed_seconds?: number | null;
    confirmed_minutes?: number | null;
    open_session_count: number;
    employees_with_overlap: number;
    daily: Array<{ date: string; employees_with_observed_start: number; closed_session_count: number; confirmed_seconds: number; confirmed_minutes: number }>;
    employees: Array<Omit<VpnConnectionsEmployee, "sessions">>;
    employees_has_more?: boolean;
    departments: Array<{ department: string; employee_count: number; closed_session_count: number; confirmed_seconds?: number | null; confirmed_minutes?: number | null; employees_with_open_sessions: number; employees_with_overlap: number }>;
    departments_has_more?: boolean;
  };
  entitlements: { state: string; items: VpnConnectionsIdentity[]; has_more: boolean };
  failed_authorizations:
    | {
      state: "available";
      count: number;
      items: Array<{ event_db_id: number; event_record_id?: number | null; event_id: 6273; time_created_utc: string; entity_id?: number | null; display_name: string; account_name: string; department?: string; identity_state: "resolved" | "unresolved"; reason_code: string; reason_text?: string | null; source_core_sha256?: string | null }>;
      has_more: boolean;
    }
    | {
      state: "not_collected";
      count: null;
      items: [];
      has_more: boolean;
    }
    | {
      state: "unavailable";
      unavailable_reason: "input_event_bound_exceeded";
      count: null;
      items: [];
      has_more?: never;
    };
  limitations: string[];
  limits: Record<string, number>;
  branches?: Record<string, unknown>;
};

export type V4ObjectDetail = {
  api_version: "v4"; state: string;
  object: { object_type: string; object_id: string; display_name?: string | null; natural_key?: string | null; first_seen_utc?: string | null; last_seen_utc?: string | null; latest_state?: Record<string, unknown> | null };
  identity_links: Array<Record<string, unknown>>; identity_contract: string;
  tabs: Array<{ id: string; label: string; available: boolean }>;
  current_states: Array<Record<string, unknown>>; directory_context: { resolution?: string; items?: Array<Record<string, unknown>> };
  findings: Array<Record<string, unknown>>;
  events: Array<Record<string, unknown>>; events_state: "available" | "temporarily_unavailable" | "forbidden"; has_more_events: boolean; actions: string[];
  provenance: Array<{ source: string; observed_at_utc?: string | null; freshness: string }>;
  limitations: string[];
};

export type EventDetail = EventItem & {
  read_representation?: "authentication_session";
  source_event_state?: "expired_represented_by_session";
  authentication_session?: { uid: string; revision: number; state: "closed" | "incomplete"; completeness: string; quality_reason: string };
  source_payload_state?: "expired" | "archive_unavailable" | null;
  retained_facts?: Record<string, unknown>;
  subject?: string;
  target?: string;
  source?: string;
  level?: number | null;
  task?: number | string | null;
  opcode?: number | string | null;
  computer?: string | null;
  event_record_id?: number | null;
  message_text?: string;
  event_data?: Record<string, unknown>;
  semantics?: {
    watch_priority?: { base_severity: string; effective_severity: string; reason: "watch" };
    title: string;
    title_code?: string;
    summary_code?: string;
    final_risk?: string;
    risk: string;
    severity?: string;
    assessment_confidence: string;
    classification_origin?: "catalog_base" | "contextual_rule" | "unavailable";
    card_completeness?: "complete" | "partial" | "not_applicable";
    summary: string;
    facts: Array<[string, string]>;
    fact_label_codes?: string[];
    checks: string[];
    check_codes?: string[];
    known: boolean;
  };
};

export type EventBatchResponse = {
  api_version: "v1";
  items: EventDetail[];
  requested_event_db_ids: number[];
  missing_event_db_ids: number[];
  limit: 100;
};

export type StorageFootprintComponent = {
  key: string;
  label?: string;
  status?: "ok" | "partial" | "unavailable" | string;
  bytes?: number | null;
  human?: string | null;
  path?: string | null;
  method?: string;
  included_in_accounted_total?: boolean;
  /** Ключ родительской строки: значение уже посчитано в ней и в итог не идёт. */
  parent?: string | null;
  note?: string | null;
};

export type StorageFootprint = {
  backups?: { last_backup_at_utc?: string | null; last_verified_at_utc?: string | null; capacity_days?: number | null; same_disk_as_postgres?: boolean | null };
  schema?: string;
  status?: "ok" | "partial" | "stale" | "unavailable" | string;
  generated_at_utc?: string | null;
  components?: StorageFootprintComponent[];
  totals?: {
    accounted_bytes?: number;
    accounted_human?: string;
    known_physical_bytes?: number;
    known_physical_human?: string;
    postgres_proxy_included?: boolean;
    accounting_quality?: "measured" | "estimated" | string;
    docker_images_raw_sum_bytes?: number;
    docker_images_raw_sum_human?: string;
    docker_images_included?: boolean;
  };
  disk?: { total_human?: string; used_human?: string; free_human?: string; free_percent?: number };
  warnings?: string[];
  accounting_notes?: string[];
  snapshot?: { age_seconds?: number | null; max_age_seconds?: number; stale?: boolean; available?: boolean; path?: string; error_type?: string };
  raw_spool?: {
    status?: "ok" | "partial" | "unavailable" | string;
    path?: string | null;
    bytes?: number | null;
    human?: string | null;
    batch_count?: number | null;
    oldest_batch_at_utc?: string | null;
    oldest_batch_age_seconds?: number | null;
    timestamp_basis?: string;
    scan?: { complete?: boolean; errors?: number; error_paths?: string[]; error?: string };
    thresholds?: {
      bytes_warning?: number;
      bytes_critical?: number;
      batch_count_warning?: number;
      oldest_age_warning_seconds?: number;
      basis?: string;
    };
  };
};

export type CollectionProgressItem = {
  server?: string | null;
  channel?: string | null;
  recovery_mode?: boolean;
  boundary_reached?: boolean;
  boundary_checked_at_utc?: string | null;
  check_state?: string;
  last_status?: string | null;
  failure_reason?: string | null;
  current_limit?: number | null;
  last_event_record_id?: number | null;
  last_event_time_utc?: string | null;
  last_successful_collection_utc?: string | null;
  last_action?: string | null;
};

export type CollectionProgress = {
  status?: string;
  check_state?: string;
  block_reason?: string | null;
  blocked_since_utc?: string | null;
  source?: string;
  channels_total?: number;
  boundaries_reached?: number;
  channels_in_recovery?: number;
  worker_id?: string | null;
  worker_status?: string;
  worker_phase?: string | null;
  heartbeat_at?: string | null;
  job_id?: number | null;
  job_status?: string | null;
  job_phase?: string | null;
  items?: CollectionProgressItem[];
  recovery_items?: CollectionProgressItem[];
};

export type AgentCollectionCompleteness = {
  state: "known_gaps" | "not_assessed";
};

export type AgentCollectionHealth = {
  connected_domain_controllers?: number;
  replaced_agents?: Array<{ id: string; name: string; agent_version?: string | null; replacement_version?: string | null; certificate_reissue_required?: boolean }>;
  diagnostics?: { state: "unavailable"; reason: "timeout" | "read_failed" };
  completeness?: AgentCollectionCompleteness;
  state: "current" | "partial" | "error" | "unknown" | "unavailable";
  checked_at_utc: string; active_agents: number; current_agents: number;
  items: Array<{
    id: string; host_id: string; name: string; domains: string[];
    duplicate_agents?: number; identity_conflict?: boolean; password_domain_required?: boolean; agent_version?: string | null; replacement_version?: string | null;
    delivery_fallback?: { agent_id: string; last_packet_at: string; since: string | null; can_restore: boolean } | null;
    windows_audit?: AgentWindowsAudit | null;
    eventlog_diagnostics?: AgentItem["eventlog_diagnostics"];
    collection_interval_seconds?: number;
    data_gaps?: Array<{ module_id?: string; from_utc: string; to_utc: string }>;
    completeness?: AgentCollectionCompleteness & { last_accepted_gap_at: string | null };
    state: "current" | "error" | "waiting" | "lagging" | "unknown" | "paused" | "disabled";
    connection: "online" | "offline" | "never_seen" | "unknown";
    last_seen: string | null; last_packet_at: string | null; href: string;
    policy_revision: number; applied_policy_revision: number;
    modules: Array<{ module_id: string; channels: Array<{
      channel: string | null; state: "current" | "error" | "waiting" | "lagging" | "unknown" | "paused" | "disabled";
      failure_reason?: "read_error" | "import_overdue" | "import_rejected" | "packet_missing" | "packet_stale" | null;
      /** Current evidenced deadline exceeded at this time; not outage onset. */
      issue_since_utc?: string | null;
      /** Observation of the issue, distinct from the time it began. */
      issue_observed_at_utc?: string | null;
      historical_unimported_packets?: number;
      historical_error_at?: string | null;
      import_failure_reason?: string | null;
      import_failure_at?: string | null;
      last_packet_at: string | null; last_import_at: string | null; import_lag_seconds: number | null; budget_seconds: number;
    }> }>;
  }>;
};
export type PlatformReadiness = Pick<OperationsOverview, "generated_at_utc" | "postgres" | "storage" | "workers"> & {
  agent_collection?: AgentCollectionHealth | null;
  archive?: { status: "ok" | "invalid_root" | "unavailable" } | null;
};

export type StorageGrowth = {
  measured_growth?: { components?: Partial<Record<"database_bytes" | "disk_used_bytes", { bytes_per_day: number; per_day_human: string }>> };
  forecast?: { estimated_days?: number | null };
};

export type StorageOverview = {
  storage: {
    agent_inbox_capacity?: "ok" | "full" | "unavailable" | null;
    disk_pressure?: { disk?: { used_bytes?: number; free_bytes?: number; used_human?: string; free_human?: string } };
    postgres_volume?: { mount_point: string; used_bytes: number; free_bytes: number } | null;
    retired_clickhouse_data?: boolean;
    footprint?: Pick<StorageFootprint, "components" | "backups">;
  };
};

export type PasswordDetectionStatus = {
  status: "ok" | "unavailable";
  items: {
    rule_id: "qw.password-brute-force" | "qw.password-spray";
    state: "failed" | "stalled" | "behind" | "catching_up" | "history_pending" | "recovered" | "current" | "quiet" | "unknown" | "disabled";
    observed_at: string | null;
  }[];
};

export type OperationsOverview = {
  agent_collection?: AgentCollectionHealth | null;
  api_version: "v1";
  generated_at_utc: string;
  read_only: true;
  collection: {
    collection_enabled?: boolean;
    collection_block_reason?: string | null;
    operational_collection_enabled?: boolean;
    operational_collection_block_reason?: string | null;
    collection_execution_owner?: "external_worker" | "server_process" | string;
    local_runtime_guard_only?: boolean;
    collection_block?: {
      reason_code?: string | null;
      retry_policy?: string | null;
      operator_action?: string | null;
      observed_count?: number | null;
      first_seen_at?: string | null;
      last_seen_at?: string | null;
    };
    [key: string]: unknown;
  };
  collection_progress?: CollectionProgress;
  workers?: {
    status?: string;
    source?: string;
    error_type?: string | null;
    items?: RuntimeWorker[];
    password_detection?: PasswordDetectionStatus;
    semantic_outbox_lag?: { status: "ok" | "unavailable"; live_age_seconds?: number | null; backfill_age_seconds?: number | null };
    /**
     * `H4` и `L3`: глубина очередей, возраст старейшего готового задания,
     * повторы, карантин и просроченные аренды. Источник —
     * `get_semantic_queue_overview()` в `server/app/runtime_workers.py`.
     *
     * `status: "unavailable"` отличается от пустого `items`: первое означает,
     * что очередь не опрошена, второе — что она пуста. На экране это разные
     * состояния, и путать их нельзя.
     */
    semantic_queues?: SemanticQueueOverview;
  };
  /**
   * `K3`: полнота каталога событий. Лежит в корне ответа, а не под `workers`.
   * `basis` обязателен к показу: это доля **различных записей каталога**, а не
   * покрытие корпуса по числу событий.
   */
  catalog_completeness?: CatalogCompleteness;
  collector_health: {
    backend?: string;
    summary?: Record<string, unknown>;
    items?: CollectorHealthItem[];
    operations_slo?: {
      status?: string; label?: string; security_channels?: number; freshness_current?: number;
      freshness_warning?: number; freshness_breached?: number; freshness_unknown?: number;
      warning_minutes?: number; breach_minutes?: number; timeouts_24h?: number;
      partial_timeouts_24h?: number; stale_post_collection?: number;
      analysis_queued?: number; analysis_running?: number;
      error_budget?: {
        window_hours: number; objective: number; schedule_interval_seconds: number;
        expected_security_checks: number; allowed_errors: number; consumed_errors: number | null;
        remaining_errors: number | null; consumed_percent: number | null; status: string; method: string;
      };
    };
    collection_freshness?: CollectionFreshness;
    runtime_history?: { status?: string; source?: string; active_items?: RuntimeCollectionRun[]; channel_items?: RuntimeCollectionRun[]; items?: RuntimeCollectionRun[] };
    storage_v2_outbox?: { status?: string; batches?: number; events?: number; expired_lease_batches?: number; expired_lease_events?: number; completed_batches?: number; completed_events?: number; states?: Record<string, { batches?: number; events?: number }> };
  };
  storage: {
    status?: string;
    disk_pressure?: { disk?: { used_bytes?: number | null; free_bytes?: number | null; used_human?: string | null; free_human?: string | null } };
    project_overview?: { total_human?: string; database_human?: string; growth_human_per_day?: string; [key: string]: unknown };
    /**
     * Полная картина занятого места, задание `56`.
     *
     * Снимок готовит отдельный read-only producer; HTTP-запрос его только
     * читает и никогда не запускает обход файлов или Docker. Поэтому у снимка
     * есть собственные возраст и свежесть, а «нет снимка» и «ноль байт» —
     * разные состояния.
     *
     * Два итога намеренно разные и не складываются. `accounted_bytes`
     * включает PostgreSQL логическим размером базы; `known_physical_bytes` —
     * только измеренное на диске. Вложенные строки каталога и активные части
     * ClickHouse в итог не входят: они уже посчитаны в родителе.
     */
    footprint?: StorageFootprint;
    [key: string]: unknown;
  };
  postgres: {
    status?: string;
    available?: boolean;
    connectivity_status?: "ready" | "unavailable" | "not_applicable" | string;
    metrics_status?: "complete" | "partial" | "unavailable" | "not_applicable" | string;
    database?: { database_human?: string; [key: string]: unknown };
    long_running_queries?: Array<{ pid?: number; duration_seconds?: number; state?: string }>;
    warnings?: string[];
    limitations?: Array<{ metric?: string; error_type?: string }>;
    [key: string]: unknown;
  };
};

export type SourceDetail = {
  api_version: "v1";
  generated_at_utc: string;
  source: {
    hostname: string; fqdn?: string | null; role?: string | null; active?: boolean | null;
    domain_fqdn?: string | null; site?: string | null; os_name?: string | null;
    os_version?: string | null; ip_addresses: string[]; disk_state: string;
    inventory_observed_at_utc?: string | null; inventory_source?: string | null;
    disks: Array<{ name?: string; total_bytes?: number; free_bytes?: number; free_percent?: number }>;
  };
  collection_freshness: CollectionFreshness;
  channels: CollectorHealthItem[];
  limitations: string[];
  read_only: true;
};

/** Одна строка очереди. Карантин представлен статусом строки, а не отдельным полем. */
export type SemanticQueueRow = {
  queue_name: string;
  queue_status: string;
  depth: number;
  retries: number;
  expired_leases: number;
  oldest_ready_age_seconds: number;
};

export type SemanticQueueStage = {
  queue_name: "processing" | "dispatch" | "risk";
  depth: number;
  oldest_pending_age_seconds: number;
  completed_last_hour: number;
};

export type SemanticQueueOverview = {
  status?: "ok" | "unavailable" | string;
  contains_event_payload?: boolean;
  error_type?: string | null;
  items?: SemanticQueueRow[];
  stages?: SemanticQueueStage[];
  window_seconds?: number;
  warning_thresholds?: { depth: number; oldest_pending_age_seconds: number };
};

export type CatalogCompleteness = {
  status?: "ok" | "unavailable" | string;
  /** Сейчас всегда `distinct_catalog_entries`. Показывать обязательно. */
  basis?: string;
  contains_event_payload?: boolean;
  error_type?: string | null;
  entry_count?: number;
  fully_classified?: number;
  classification_ratio?: number;
  schema_v2_ready?: number;
  declared_per_field?: Record<string, number>;
};

export type RuntimeWorker = {
  worker_name: string;
  label: string;
  state: "active" | "warning" | "stale" | "not_registered" | string;
  status?: string | null;
  feature_enabled?: boolean;
  /** `runtime_worker` или `external_worker`. Семантика запускается снаружи supervisor. */
  execution_owner?: string | null;
  worker_id?: string | null;
  process_pid?: number | null;
  phase?: string | null;
  expected_interval_seconds?: number | null;
  heartbeat_age_seconds?: number | null;
  heartbeat_at?: string | null;
  started_at?: string | null;
  details?: Record<string, unknown>;
};

export type CollectorHealthItem = {
  timeouts_24h_available?: boolean;
  usage_state?: "unused";
  server?: string | null;
  channel?: string | null;
  last_event_time_utc?: string | null;
  last_successful_collection_utc?: string | null;
  collection_lag_minutes?: number | null;
  lag_minutes?: number | null;
  inserted_24h?: number | null;
  skipped_24h?: number | null;
  last_status?: string | null;
  failure_reason?: string | null;
  display_status?: string | null;
  freshness_label?: string | null;
  event_observation_label?: string | null;
  event_observation_severity?: string | null;
  collection_state?: "error" | "stale" | "lagging" | "current" | string | null;
  collection_label?: string | null;
  collection_severity?: string | null;
  recovery_mode?: boolean;
  adaptive_limit?: number | null;
  adaptive_action?: string | null;
  severity?: string | null;
};

export type CollectionFreshness = {
  state: "error" | "partial" | "stale" | "lagging" | "current";
  label: string;
  worst_lag_minutes?: number | null;
  checked_at_utc?: string | null;
  latest_event_utc?: string | null;
  worst_event_lag_minutes?: number | null;
  collection_error: boolean;
  channels_total?: number;
  channels_checked?: number;
  channels_failed?: number;
  basis?: string;
};

export type RuntimeCollectionRun = {
  run_id?: string; worker_id?: string; status?: string; phase?: string;
  servers_json?: string[]; hours?: number; max_events_per_channel?: number;
  created_at?: string; started_at?: string; finished_at?: string;
  duration_ms?: number | null; errors_json?: string[];
};

type ReleaseMetadata = {
  project_version?: string | null;
  generated_at_utc?: string;
  build_id?: string;
  release_tag?: string | null;
  git_commit?: string | null;
  installed_at_utc?: string | null;
  [key: string]: unknown;
};

export type DiagnosticsOverview = {
  status: string;
  web_console?: { available: boolean; url: string | null };
  release_metadata?: ReleaseMetadata;
  warnings?: string[];
  parsed_checks?: Record<string, { status?: string; duration_ms?: number; [key: string]: unknown } | null>;
  logs?: Record<string, string>;
};

export type SystemHealth = {
  release_metadata?: ReleaseMetadata;
  password_catchup?: { from: string; to: string; cursor: string; heartbeat: string | null } | null;
  generated_at_utc?: string;
  status?: string;
  warnings?: string[];
  db?: { backend?: string; size_human?: string; events?: number; [key: string]: unknown };
  storage_health?: { status?: string; warnings?: string[]; [key: string]: unknown };
  runtime_storage?: {
    snapshot?: { status?: string; stale?: boolean; refreshing?: boolean; age_ms?: number | null; [key: string]: unknown };
    [key: string]: unknown;
  };
  collector_summary?: { channels_total?: number; servers_total?: number; high?: number; warn?: number; [key: string]: unknown };
  [key: string]: unknown;
};

export type SourcePack = {
  pack_id: string;
  version: string;
  display_name: string;
  source_kind: "event" | "context";
  channels: string[];
  sections: string[];
  adapters: string[];
  entity_contract: string;
  analysis_contract: string;
  manifest_sha256: string;
};

export type DcOnboardingPlan = {
  kind: "dc_onboarding_preflight";
  valid: boolean;
  hostname: string;
  connect_address: string;
  source_pack_id: string;
  channels: string[];
  adapter_id: string;
  network_actions: [];
  database_actions: [];
  collection_actions: [];
  issues: Array<{ code: string; message: string }>;
  next_operator_action: string;
};

export type DashboardSnapshot = {
  generated_at_utc?: string;
  status?: "ok" | "partial" | "stale" | "warming" | string;
  health?: { status?: string; runtime?: { active_backend?: string; collection?: Record<string, unknown> } };
  sources?: { items?: Array<{ hostname?: string; fqdn?: string; role?: string; is_active?: boolean }> };
  events_summary?: {
    total_events?: number;
    estimated?: boolean;
    dashboard_mode?: string;
    by_channel?: Array<{ channel?: string; count?: number }>;
    by_server?: Array<{ hostname?: string; count?: number; is_active?: boolean }>;
    limitations?: string[];
  };
  entity_summary?: { total_entities?: number; total_event_entity_links?: number; estimated?: boolean };
  collector_health?: { summary?: Record<string, number>; items?: CollectorHealthItem[] };
  role_views?: { summary?: { active_findings?: number; security_high?: number; worst_security_lag_minutes?: number | null; sources?: number } };
  diagnostics?: { stale?: boolean; refreshing?: boolean; failures?: string[]; cache_hit?: boolean; cache_age_ms?: number; request_model?: string };
};

export type InvestigationWorkspace = {
  q: string;
  empty_query?: boolean;
  no_results?: boolean;
  scope?: string;
  summary?: { total_events?: number; findings?: number; attention_level?: string; story?: string; why_it_matters?: string; has_more?: boolean };
  timeline?: { chain?: Array<{ time?: string; event_db_id?: number; event_id?: number; label?: string; server?: string; subject?: string; target?: string }> };
  findings?: { items?: FindingItem[] };
  next_checks?: string[];
  data_quality?: { limitations?: string[]; returned_events?: number; truncated?: boolean };
};

export type FindingItem = { id: number; title?: string; severity?: string; status?: string; actor?: string; target?: string; source?: string; summary?: string; last_seen_utc?: string; recommended_action?: string | null; assigned_to?: string | null; status_reason?: string | null; updated_at?: string | null; status_history?: Array<{ id: number; old_status?: string | null; new_status: string; changed_at?: string | null; changed_by: string; note?: string | null }> };

export type FindingRiskAcceptance = {
  id: number; finding_id: number; state: "active" | "expired" | "revoked";
  reason: string; responsible_user_id: number; responsible_username?: string;
  expires_at: string; created_at: string; created_by: string; changed_by?: string | null;
};
export type FindingRiskAudit = {
  id: number; action: string; actor: string; occurred_at: string;
  details: { rule: FindingRiskAcceptance };
};
export type FindingRiskRequest =
  | { action: "create"; reason: string; responsible_user_id: number; expires_at: string }
  | { action: "revoke"; id: number };

export type SecurityProblemFinding = FindingItem & {
  decoy_id?: string | null;
  decoy_revision?: number | null;
  risk_acceptance?: FindingRiskAcceptance | null;
  risk_audit?: FindingRiskAudit[];
  presentation_code?: string | null;
  presentation_messages?: Record<string, ApiMessage>;
  status_message?: ApiMessage | null;
  severity_message?: ApiMessage | null;
  why_it_matters?: string | null;
  first_seen_utc?: string | null;
  evidence_count?: number;
  repeat_count?: number;
  evidence: Array<{ event_db_id: number; event_id: number; hostname?: string | null; channel?: string | null; time_created_utc?: string | null; evidence_role?: string | null; note?: string | null }>;
  entities: Array<{ entity_type?: string | null; display_name?: string | null; entity_role?: string | null }>;
  status_history: Array<{ id: number; old_status?: string | null; new_status: string; changed_at?: string | null; changed_by: string; note?: string | null }>;
};

export type SecurityProblemsReport = {
  generated_at_utc: string;
  status: "ok" | "unavailable";
  state: "available" | "empty" | "partial" | "stale" | "unavailable";
  source: "semantic_production_findings";
  items: SecurityProblemFinding[];
  summary: Array<{ severity: string; status: string; count: number }>;
  has_more: boolean;
  limits: { limit: number; details_per_finding: number };
  lifecycle: { valid_statuses: string[]; allowed_transitions: Record<string, string[]> };
  semantic_runtime: {
    state: "active" | "inactive" | "stale" | "unknown";
    runtime_mode: string | null;
    facts_state: "active" | "inactive" | "stale" | "unknown";
    relations_state: "active" | "inactive" | "stale" | "unknown";
    findings_state: "active" | "inactive" | "stale" | "unknown";
    status?: string | null;
    phase?: string | null;
    heartbeat_at?: string | null;
    enabled_policy?: string | null;
  };
  limitations: string[];
};

export type EntitySummary = { total_entities?: number; total_event_entity_links?: number; by_type?: Array<{ entity_type?: string; count?: number }>; by_role?: Array<{ link_role?: string; count?: number }> };

export type AuthUserInventory = { items: Array<{ id: number; username: string; role: string; is_active: boolean; is_service: boolean; last_login_at?: string | null }>; roles: Array<{ id: string; label: string; description: string }> };
export type ApiKeyInventoryItem = {
  id: number;
  key_prefix: string;
  label: string;
  role: string;
  is_active: boolean;
  expires_at?: string | null;
  created_at?: string | null;
  last_used_at?: string | null;
  revoked_at?: string | null;
};

export type CreatedApiKey = {
  item: ApiKeyInventoryItem;
  /** Returned by the server exactly once. Never persisted by the UI. */
  token: string;
};

export type OverviewWorkspace = {
  agent_collection?: AgentCollectionHealth | null;
  api_version: "v1";
  generated_at_utc?: string | null;
  status: string;
  data_state: { cache: string; stale: boolean; failures: string[] };
  metrics: { events_total: number; events_estimated: boolean; entities_total: number; entities_estimated: boolean; important_recent: number; sources_total: number };
  alerts: Array<{ id: number; title: string; severity: string; status: string; actor?: string | null; target?: string | null; source?: string | null; last_seen_utc?: string | null; evidence_count: number; assigned_to?: string | null; updated_at?: string | null; event_db_id?: number | null }>;
  sources: Array<{
    hostname: string; fqdn?: string | null; role?: string | null; active?: boolean | null; registered?: boolean;
    site?: string | null; os_name?: string | null; os_version?: string | null;
    ip_addresses?: string[];
    disk_state?: string; disks?: Array<{ name?: string; total_bytes?: number; free_bytes?: number; free_percent?: number }>;
    inventory_observed_at_utc?: string | null; inventory_source?: string | null;
    collection_state?: "error" | "stale" | "lagging" | "current" | string | null;
    collection_label?: string | null; last_successful_collection_utc?: string | null;
    last_event_time_utc?: string | null; channels_total?: number;
    channels?: CollectorHealthItem[];
  }>;
  collection_freshness: CollectionFreshness;
  collection_progress: CollectionProgress;
  activity: { period_label: string; time_from_utc: string; time_to_utc: string; selected_source?: string | null; available: boolean; exact: boolean; reason?: string | null; items: Array<{ index: number; bucket_start_utc?: string | null; bucket_end_utc?: string | null; critical: number; important: number; informational: number }> };
  limits: Record<string, unknown>;
};

export type InvestigationWorkspaceV1 = {
  next_cursor?: string | null;
  api_version: "v1";
  query: string;
  anchor_event_db_id?: number | null;
  context?: { event_db_id?: number | null; entity_id?: number | null; time_from_utc?: string | null; time_to_utc_exclusive?: string | null; timezone: string; anchor_in_window?: boolean | null } | null;
  scope: string;
  state: "query_required" | "empty" | "ok";
  summary: { events_returned: number; has_more: boolean; attention_level: string; anchor_classification?: { risk: string; classification_origin: "catalog_base" | "contextual_rule" | "unavailable"; card_completeness: "complete" | "partial" | "not_applicable" } | null; story: string; story_code?: string | null; why_it_matters: string; why_it_matters_code?: string | null };
  timeline: Array<{ event_db_id: number; time_utc?: string | null; server?: string | null; channel?: string | null; event_id: number; title: string; title_code?: string | null; summary_code?: string | null; category: string; severity?: string | null; assessment_confidence?: string | null; classification_origin?: "catalog_base" | "contextual_rule" | "unavailable"; card_completeness?: "complete" | "partial" | "not_applicable"; inclusion_reason?: string | null; actor?: string | null; target?: string | null; source?: string | null; summary?: string | null; catalogued: boolean }>;
  findings: FindingItem[];
  next_checks: string[];
  next_check_codes?: string[];
  limits: Record<string, unknown>;
};

export type InvestigationCase = {
  status_message?: ApiMessage;
  case_number?: string | null;
  id: number; public_id?: string | null; title: string; status: string; owner?: string | null; created_by: string;
  created_at: string; updated_at: string; closed_at?: string | null;
  events: Array<{ event_db_id: number; relation_status: "confirmed" | "excluded"; added_by: string; added_at: string }>;
  evidence_page_size?: number | null;
  events_total?: number | null;
  events_next_cursor?: number | null;
  evidence_refs_total?: number | null;
  evidence_refs_next_cursor?: string | null;
  anchor_event?: InvestigationCase["events"][number] | null;

  evidence_refs: Array<{ evidence_kind: "vpn_accounting_session"; source_domain_id: number; reference_id: string; relation_status: "confirmed" | "excluded"; added_by: string; added_at: string }>;
  evidence_refs_state: "available" | "partially_authorized";
  notes: Array<{ id: number; body: string; created_by: string; created_at: string }>;
  audit: Array<{ id: number; action: string; actor: string; payload?: Record<string, unknown> | null; created_at: string }>;
};

export type InvestigationCaseSummary = Omit<InvestigationCase, "events" | "evidence_refs" | "evidence_refs_state" | "notes" | "audit"> & {
  public_id?: string | null;
  evidence_count?: number | null;
};

export type EntitiesWorkspace = { api_version: "v1"; query: string; state: "empty" | "ok"; items: Array<{ id: number; type: string; natural_key: string; display_name?: string | null; first_seen_utc?: string | null; last_seen_utc?: string | null; latest_state?: { status: string; summary?: string | null; observed_at_utc?: string | null; evidence_event_db_id: number } | null }>; has_more: boolean; filters?: { entity_types?: string[]; exclude_entity_types?: string[] }; type_counts?: Array<{ entity_type: string; count: number }>; type_counts_scope?: string; total_entities?: number; limits: Record<string, unknown> };
export type EntityWorkspaceItem = EntitiesWorkspace["items"][number] & { domain_id?: number | null };

export type EntityWorkspaceEvent = {
  event_db_id: number;
  summary_key?: string | null;
  event_id?: number | null;
  label?: string | null;
  severity?: string | null;
  title_code?: string | null;
  time_utc?: string | null;
  server?: string | null;
  channel?: string | null;
  provider_name?: string | null;
  link_role?: string | null;
  confidence?: number | null;
  actor?: string | null;
  target?: string | null;
};

export type EntityCurrentState = {
  state_type: string;
  status: string;
  projection_status: "normal" | "unknown" | "conflict";
  observed_at_utc?: string | null;
  evidence_event_db_id: number;
  rule_id?: string | null;
  rule_version?: string | null;
  summary?: string | null;
};

export type EntityWorkspaceDetail = {
  api_version: "v1";
  entity: EntityWorkspaceItem;
  current_states: EntityCurrentState[];
  current_states_state: "available" | "temporarily_unavailable";
  ad_context: {
    resolution: "shared_entity_id" | "exact_alias" | "not_observed" | "no_exact_alias" | "ambiguous" | "not_found" | "temporarily_unavailable";
    ad_context_entity_id?: number;
    returned_count: number;
    bounded: boolean;
    items: Array<{
      context_evidence_id?: number | null;
      evidence_type: string;
      source_pack_id: string;
      observed_at_utc?: string | null;
      integrity_sha256?: string | null;
      context_kind: "entity" | "relation";
      subject_entity_id?: number;
      subject_display_name?: string | null;
      related_entity_id?: number | null;
      related_display_name?: string | null;
      current: boolean;
      /** Начало версионного наблюдения: когда сбор впервые увидел эту связь. */
      valid_from_utc?: string | null;
      valid_to_utc?: string | null;
      supplemental_context_only: true;
      changes_entity_state: false;
      source_section?: string;
      /**
       * Наблюдение AD Context как есть. Внутренний `attributes.attributes`
       * содержит атрибуты учётной записи из секции `directory_accounts`.
       * Читается только у наблюдений с `current: true`.
       */
      attributes?: { section?: string; membership_type?: string; attributes?: Record<string, unknown> };
    }>;
  };
  ad_context_state: "available" | "temporarily_unavailable";
  events: EntityWorkspaceEvent[];
  events_state: "available" | "temporarily_unavailable" | "forbidden";
  events_scope_filtered: boolean;
  security_actions_state: string;
  security_actions: SecurityEventItem[];
  semantic_relations_state: string;
  semantic_relations: SemanticRelationItem[];
  has_more: boolean;
  next_cursor?: { time_utc?: string | null; event_db_id: number; summary_key?: string | null } | null;
  context?: { time_from_utc?: string | null; time_to_utc_exclusive?: string | null; timezone?: string | null };
  limits: Record<string, unknown>;
};

export type EntityVpnSession = {
  session_row_id: string;
  entity_id: number;
  source_domain_id: number;
  generation: number;
  lifecycle_state: string;
  completeness: string;
  started_at_utc?: string | null;
  last_observed_at_utc?: string | null;
  stopped_at_utc?: string | null;
  duration_seconds?: number | null;
  observation_count: number;
  anomalies: string[];
  evidence_ref: { kind: "vpn_accounting_session"; source_domain_id: number; session_row_id: string } | { state: "not_authorized" };
};

export type EntityVpnSessions = {
  contract_id: "sli.entity-vpn-sessions.v1";
  entity_id: number;
  source_domain_id: number;
  state: "available" | "not_authorized";
  branches: { sessions: { state: string }; session_evidence: { state: string } };
  time_range: { from_utc: string; to_utc_exclusive: string };
  items: EntityVpnSession[];
  has_more: boolean;
  limits: Record<string, unknown>;
};

export type SemanticScenarioEvidence = {
  normalized_event_id: string;
  event_db_id: number;
  evidence_order: number;
};

/**
 * Снимок полноты проверки. Все поля необязательны намеренно: сервер хранит
 * неизмеренное как `null`, а не подставляет умолчание, и интерфейс обязан
 * различать «ноль» и «не измеряли».
 */
export type CompletenessSnapshot = {
  captured_at_utc?: string;
  catalog_completeness?: {
    entry_count?: number;
    fully_classified?: number;
    classification_ratio?: number;
    schema_v2_ready?: number;
  };
  collection_freshness?: { max_age_seconds?: number | null; budget_seconds?: number; complete?: boolean };
  channel_availability?: {
    required?: string[];
    available?: string[];
    required_count?: number;
    available_count?: number;
    complete?: boolean;
  };
  window_closure?: {
    window_end_utc?: string;
    descriptor_close_timeout_seconds?: number | null;
    allowed_lateness_seconds?: number | null;
    close_deadline_utc?: string | null;
    closed?: boolean;
  };
  supports_negative_conclusion?: boolean;
};

export type SemanticScenario = {
  evidence_has_more?: boolean;
  evidence_next_cursor?: string | null;
  scenario_id: string;
  scenario_kind: string;
  result_class: "security_incident" | "security_exposure" | "control_gap";
  status: "open" | "under_review" | "resolved" | "dismissed";
  partition_key: string;
  strict_keys: Record<string, unknown>;
  title: string;
  explanation: string;
  first_seen_utc: string;
  last_seen_utc: string;
  risk_class: string;
  raw_score: number;
  display_score: number;
  hard_critical: boolean;
  confidence: string;
  confidence_score: number;
  confidence_factors: Record<string, unknown>;
  coverage_status: "complete" | "partial" | "unavailable" | "unknown";
  /**
   * Три состояния вывода, а не два. `not_found` означает «проверили и не
   * нашли», `not_checked` — «не смогли проверить». Сервер понижает первое до
   * второго, если каталог, свежесть сбора, каналы и закрытие окна не полны
   * одновременно: `resolve_conclusion_state()` в `server/app/semantic_risk.py`.
   */
  conclusion_state: "observed" | "not_found" | "not_checked";
  /** Форма — `CompletenessSnapshot.as_dict()`, см. `server/app/semantic_risk.py`. */
  completeness_snapshot: CompletenessSnapshot;
  step_count: number;
  evidence_count: number;
  contribution_count: number;
  updated_at: string;
  evidence: SemanticScenarioEvidence[];
  review_count: number;
  latest_review?: SemanticScenarioReview | null;
  payload_state?: "available" | "metadata_only";
};

export type SecurityEventPrincipal =
  | { state: "unknown" }
  | { state: "observed"; sid?: string | null; name?: string | null; entity_id?: number | null };

export type SecurityEventOutcome =
  | { state: "unknown"; reason: string; result_code?: string | null }
  | { state: "observed"; value: "success" | "failure"; basis: "event_id" | "result_code"; result_code?: string | null };

export type SecurityEventItem = {
  event_db_id: number;
  event_record_id?: number | null;
  event_id: number;
  event_family: "authentication" | "account_lock" | "password_operation" | "account_lifecycle" | "account_change" | "group_membership" | "group_lifecycle" | "audit_configuration";
  time_created_utc: string;
  actor: SecurityEventPrincipal;
  affected_account: SecurityEventPrincipal;
  member: SecurityEventPrincipal;
  group: SecurityEventPrincipal;
  source_host: { state: "unknown" } | { state: "observed"; hostname: string };
  caller_computer?: { state: "unknown" } | { state: "observed"; hostname: string };
  outcome: SecurityEventOutcome;
  change?: {
    state: "observed" | "partial" | "unknown";
    kind?: string;
    observed_value?: string;
    attributes?: Record<string, string>;
    detail?: { state: string; reason?: string };
    [publicField: string]: unknown;
  };
  account_change?: {
    change: AdAccountChange;
    observed_transition: {
      before: AdAccountChangeTransitionBefore;
      after: AdAccountChangeTransitionAfter;
    };
  };
  evidence: {
    state: "complete" | "partial";
    missing_fields: string[];
    event_db_id: number;
    event_record_id?: number | null;
    source_core_sha256?: string | null;
    source_facts_sha256?: string | null;
  };
};

export type SecurityEventsReport = {
  contract_id: "sli.security-events.v1";
  report_key: "security.events.chains";
  source_domain_id: number;
  state: "available" | "empty_unverified" | "not_collected" | "not_authorized";
  time_bounds: { from_utc: string; to_utc_exclusive: string };
  items: SecurityEventItem[];
  has_more: boolean;
  next_cursor?: string | null;
  collection_coverage?: { state: string; history_event_present: boolean; source_completeness: string };
  category_coverage?: Record<string, { state: string }>;
  limits: { max_period_days: number; row_limit: number; max_row_limit: number; bounded: boolean };
  limitations?: string[];
};

export type SecurityEventsSources = {
  contract_id: "sli.security-events.v1";
  report_key: "security.events.chains";
  state: "available" | "not_collected" | "not_authorized";
  items: Array<{ source_domain_id: number }>;
  bounded: true;
  limit: number;
  has_more: boolean;
};

export type SemanticRelationEvidence = {
  event_db_id: number;
  event_id: number;
  time_created_utc: string;
  semantic_type: string;
  source_host: string;
  channel: string;
  evidence_order: number;
  evidence_role?: "anchor" | "alternative_continuation";
};

export type SemanticRelationIdentityBasis =
  | { kind: "exact_domain_account_sid"; domain_id: number; account_sid: string }
  | { kind: "exact_domain_member_group_sid"; domain_id: number; member_sid: string; group_sid: string }
  | { kind: "exact_domain_account_member_sid"; domain_id: number; account_member_sid: string };

export type SemanticRelationItem = {
  candidate_id: string;
  rule_id: string;
  rule_version: number;
  relation_kind: string;
  window_start_utc: string;
  window_end_utc: string;
  confidence: "low" | "medium" | "high";
  explanation: string;
  identity_basis?: SemanticRelationIdentityBasis;
  continuation_state?: "unique" | "ambiguous";
  possible_continuation_count?: number;
  evidence: SemanticRelationEvidence[];
};

export type SemanticRelationsReport = {
  contract_id: "sli.semantic-relations.v1";
  state: "available" | "empty" | "schema_unavailable" | "not_authorized";
  domain_id: number;
  time_bounds: { from_utc: string; to_utc_exclusive: string };
  filters: Record<string, unknown>;
  result_revision?: string | null;
  items: SemanticRelationItem[];
  has_more: boolean;
  next_cursor?: string | null;
  coverage?: {
    state: string;
    matched_relation_count?: number | null;
    matched_relation_state?: string;
    supported_rules_state?: "available" | "check_unavailable";
    supported_rules?: Array<{ rule_id: string; rule_version: number; lifecycle_status: "test" | "shadow" | "enabled" }>;
    observed_rules?: Array<{ rule_id: string; rule_version: number }>;
    limitations?: string[];
    limitation_codes?: string[];
  };
  limits: Record<string, unknown>;
};

export type SemanticScenarioReview = {
  review_id: string;
  review_request_id: string;
  scenario_id: string;
  supersedes_review_id?: string | null;
  verdict: "confirmed_security" | "false_positive" | "benign_expected" | "insufficient_evidence";
  review_confidence: "high" | "medium" | "low";
  rationale: string;
  scenario_snapshot_sha256: string;
  reviewed_by: string;
  reviewer_role: "viewer" | "operator" | "admin";
  reviewed_at: string;
};

export type SemanticScenariosWorkspace = {
  next_cursor?: string | null;
  api_version: "v1";
  generated_at_utc: string;
  read_only: true;
  execution: {
    state: "disabled" | "partially_enabled" | "enabled_without_worker" | "active";
    runtime_mode?: "facts-v1" | "investigation-v1" | "findings-v1" | null;
    schema_state: "ready" | "unavailable";
    runtime_marker?: number | null;
    semantic_schema_marker?: number | null;
    feature_chain: Record<string, boolean>;
    worker: { state: string; status: string; runtime_mode?: string | null; heartbeat_at?: string | null };
    finding_path_live: boolean;
    analyst_review_schema_ready: boolean;
  };
  state: "available" | "empty" | "schema_unavailable" | "unavailable";
  items: SemanticScenario[];
  has_more: boolean;
  filters: Record<string, string | null>;
  limits: Record<string, unknown>;
};

export type SemanticAction = {
  canonical_action_id: string;
  action_kind: string;
  status: "observed" | "partially_confirmed" | "state_confirmed" | "multi_source_confirmed" | "contradicted" | "superseded" | "quarantined";
  semantic_contract_version: number;
  assembler_id: string;
  assembler_version: string;
  occurred_at_utc: string;
  attributes: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  evidence: Array<{
    normalized_event_id: string;
    event_db_id: number;
    evidence_role: "primary" | "supporting" | "state_confirmation" | "context";
    entity_role?: string | null;
    evidence_order: number;
    relation_confidence: number;
  }>;
  payload_state?: "available" | "metadata_only";
};

export type SemanticActionsWorkspace = Omit<SemanticScenariosWorkspace, "items"> & { items: SemanticAction[] };

export type SemanticCalibrationWorkspace = {
  api_version: "v1";
  generated_at_utc: string;
  read_only: true;
  execution: SemanticScenariosWorkspace["execution"];
  window_hours: number;
  state: "available" | "empty" | "schema_unavailable";
  jobs: Array<{ evaluation_mode: string; evaluation_status: string; job_count: number; attempts: number; errors: number; first_created_at?: string | null; last_updated_at?: string | null }>;
  results: Array<{ evaluation_mode: string; risk_class: string; confidence: string; coverage_status: string; result_count: number; scenario_count: number; average_risk_score: number; average_confidence_score: number; average_evaluation_ms: number; max_evaluation_ms: number }>;
  policies: Array<{ lifecycle_status: string; source_kind: string; policy_count: number }>;
  calibration_readiness?: {
    control_health: { total: number; by_status: Record<string, number> };
    coverage: { total: number; by_status: Record<string, number> };
    execution_reliability: { jobs: number; completed: number; failed: number; quarantined: number; retries: number };
    source_quality: { normalized: number; flags: Record<string, number> };
    time_provenance: { observed: number; future_clock_skew: number; delayed_ingest: number; average_ingest_delay_seconds: number; max_ingest_delay_seconds: number };
    source_coverage_integrity: {
      state: string;
      channels: { total: number; by_status: Record<string, number>; items: Array<{ server: string; channel: string; status: string; reason: string; collection_age_minutes: number | null }> };
      cursor_integrity: { audits?: number; committed?: number; no_change?: number; rejected_rollbacks?: number; stale_empty_proposals?: number; actionable_rollbacks?: number; reset_or_rollover_classification?: string };
      run_integrity: { runs?: number; noncomplete_runs?: number; inserted?: number; replay_skipped?: number; replay_skip_percent?: number };
      gap_detection: { state?: string; remote_sequence_scan_performed?: boolean; reason?: string };
      surveyed_servers_contacted: boolean;
      payload_read: boolean;
    };
    false_positive_rate: {
      state: "not_measurable" | "insufficient_sample" | "measured";
      reason: string;
      reviewed_scenarios: number;
      decisive_labels: number;
      false_positive_labels: number;
      rate_percent?: number | null;
      minimum_decisive_sample: number;
      by_verdict: Record<string, number>;
    };
  };
  limits: Record<string, unknown>;
};
export type EventRelations = { api_version: "v1"; event_db_id: number; truncated?: boolean; contract: "explicit_event_link_or_rule_based_correlation"; confidence_contract: Record<string, string>; items: Array<{ relation_type: "explicit_event_link" | "computed_correlation"; relation_origin: "stored" | "computed"; confidence_kind: "stored_link_value" | "rule_policy_score"; related_event_db_id: number; related_event_id?: number | null; related_time_utc?: string | null; confidence: number; reason: string; reason_code?: string; reason_params?: Record<string, string | number>; explanation?: string; relation_strength?: "strong" | "medium"; relation_rule?: string; time_delta_seconds?: number; evidence_fields?: string[]; entity?: string; entity_type?: string; source_role?: string; related_role?: string }> };
export type EventEntities = { api_version: "v1"; event_db_id: number; event_found?: boolean | null; evidence_status?: "present" | "zero_extracted" | "event_not_found" | "timeout"; warning?: string | null; limit: number; items: Array<{ id: number; type: string; natural_key: string; display_name?: string | null; link_role: string; confidence: number }> };

/** Настройка платформы (страница «Настройки платформы», решение владельца 2026-10-01). */
export type BackupSettingsUpdate = { enabled: boolean; path: string | null; revision: string };
export type BackupSettings = BackupSettingsUpdate & { storage_status: "unconfigured" | "ready" | "unavailable" };
type BackupSettingsResponse = BackupSettings | { enabled: false; path: null; revision: null; storage_status: "unavailable" };

export type PlatformSetting = {
  effective_value?: string | null;
  effective_state?: "available" | "unknown" | "unavailable";
  key: string;
  label: string;
  description: string;
  value: string;
  source: "database" | "environment" | "default" | "not_configured";
  environment: string;
  updated_by: string | null;
  updated_at: string | null;
};

export type SemanticControls = {
  policies: Array<{ policy_id: string; policy_version: number; title?: string | null; version_created_at?: string | null; lifecycle_status: string; enabled: boolean | null; managed: boolean }>;
  suppressions: Array<{ id: number; semantic_type: string; domain_id: number; scope_kind: "subject_sid" | "bucket"; scope_value: string; reason: string; expires_at: string; created_by: string; state: string }>;
  audit: Array<{ action: string; target: string; actor: string; occurred_at: string }>;
  limit: number;
};
export type SemanticControlChange =
  | { action: "policy_admission"; policy_id: string; policy_version: number; enabled: boolean; reason: string }
  | { action: "revoke_suppression"; id: number; reason: string }
  | { action: "create_suppression"; semantic_type: string; domain_id: number; scope_kind: "subject_sid" | "bucket"; scope_value: string; reason: string; expires_at: string };

export type SetupDomain = { is_archived?: boolean; observed_at_utc?: string | null; fqdn: string; netbios_name: string | null; forest?: string; server_count: number };

export type SetupDomainControllerSource = "db" | "file" | "none";
/** Цель сбора; IP-адрес подтверждения DNS не передаётся, только признак проверки. */
export type SetupDomainController = {
  hostname: string;
  connect_address: string;
  domain: string | null;
  enabled: boolean;
  source: "db" | "file";
  dns_readback: boolean;
};

/** Состояние мастера «Первичная настройка». */
export type SetupStep = {
  id: string;
  title: string;
  state: "done" | "todo" | "unavailable";
  summary: string;
  link?: string;
  manual?: string;
  doc?: string;
};
export type SetupSourceAction = "configure" | "check_configuration" | "enable" | "collect" | "check_data";
export type SetupSourceDataState = "fresh" | "stale" | "never" | "unavailable";
export type SetupSourceInstance = {
  /** Present only for agent-backed source evidence; absent on older servers. */
  collection_state?: AgentCollectionHealth["items"][number]["state"];
  source_instance_id: string;
  configured: boolean | null;
  enabled: boolean | null;
  data_received: boolean | null;
  data_state: SetupSourceDataState;
  last_data_utc: string | null;
  next_action: SetupSourceAction | null;
};
export type SetupSource = {
  collection_basis?: "agents";
  pack_id: string; display_name: string; version: string; source_kind: string; enabled: boolean;
  installed?: boolean;
  configured?: boolean | null;
  activation_state?: "enabled" | "disabled" | "unavailable";
  data_received?: boolean | null;
  data_state?: SetupSourceDataState;
  freshness_seconds?: number | null;
  instances?: SetupSourceInstance[];
};
export type SetupStatus = {
  api_version: "v1";
  generated_at_utc: string;
  read_only: true;
  steps: SetupStep[];
  report_domain: { key: string; value: string; source: PlatformSetting["source"]; configured_value?: string; suggested_value?: string | null } | null;
  domains: SetupDomain[];
  domain_controllers: SetupDomainController[];
  domain_controller_source: SetupDomainControllerSource | null;
  sources: SetupSource[];
  next_step?: { pack_id: string; source_instance_id: string | null; action: SetupSourceAction } | null;
  agent_collection?: AgentCollectionHealth | null;
  collection: { collection_enabled: boolean | null; block_reason: string | null; channels: number; last_success_utc: string | null } | null;
};

async function request<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, { credentials: "same-origin", headers: { Accept: "application/json", "Accept-Language": getLocale() }, ...(signal ? { signal } : {}) });
  // Чтение бросает тот же структурированный ApiResponseError, что и изменение.
  // Прежде здесь создавался обычный Error со статусом, впечатанным в строку:
  // число превращалось в текст и переставало быть значением. Из-за этого
  // экраны не могли отличить «не найдено» от «нет прав» и от отказа сервера,
  // и все три показывались одной фразой «недоступна или была удалена».
  if (!response.ok) throw await apiResponseError(response);
  return response.json() as Promise<T>;
}

async function requestJson<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { Accept: "application/json", "Accept-Language": getLocale(), "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw await apiResponseError(response);
  return response.json() as Promise<T>;
}

export class ApiResponseError extends Error {
  constructor(
    public readonly status: number,
    public readonly code?: string,
    public readonly detail?: string,
    public readonly payload?: Record<string, unknown>,
  ) {
    super(detail || code || `Запрос не выполнен: ${status}`);
    this.name = "ApiResponseError";
  }
}

async function apiResponseError(response: Response): Promise<ApiResponseError> {
  let code: string | undefined;
  let detail: string | undefined;
  let extra: Record<string, unknown> | undefined;
  try {
    const payload = await response.json() as { error?: unknown; message?: unknown; [key: string]: unknown };
    extra = payload;
    if (typeof payload.error === "string") code = payload.error;
    if (typeof payload.message === "string") detail = payload.message;
    else detail = resolveMessage(payload.message) || undefined;
  } catch { /* A non-JSON proxy response still has an HTTP status. */ }
  return new ApiResponseError(response.status, code, detail, extra);
}

async function requestMutation<T>(path: string, method: "POST" | "PATCH" | "PUT", body?: unknown): Promise<T> {
  const response = await fetch(path, { method, credentials: "same-origin", headers: { Accept: "application/json", "Accept-Language": getLocale(), ...(body === undefined ? {} : { "Content-Type": "application/json" }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  if (!response.ok) throw await apiResponseError(response);
  return response.json() as Promise<T>;
}

function requestEventBatch(eventDbIds: readonly (number | string)[]) {
  const params = new URLSearchParams({ event_db_id: eventDbIds.slice(0, 100).join(",") });
  return request<EventBatchResponse>(`/api/v1/events/batch?${params.toString()}`);
}

export const api = {
  adOperationCredentials: () => request<AdCredentialList>("/api/v1/ad-operation-credentials"),
  createAdOperationCredential: (body: { domain_id: number; label: string; username: string; password: string }) =>
    requestMutation<AdOperationCredential>("/api/v1/ad-operation-credentials", "POST", body),
  replaceAdOperationPassword: (body: { credential_id: string; credential_revision: number; password: string }) =>
    requestMutation<AdOperationCredential>("/api/v1/ad-operation-credentials/replace-password", "POST", body),
  deleteAdOperationCredential: (body: { credential_id: string; credential_revision: number }) =>
    requestMutation<{ status: "deleted" }>("/api/v1/ad-operation-credentials/delete", "POST", body),
  checkAdOperationCredential: (body: { credential_id: string; credential_revision: number }) =>
    requestMutation<{ write_enabled: false }>("/api/v1/ad-operation-credentials/check", "POST", body),
  agents: (agentId?: string, after?: string) => request<{ items: AgentItem[]; rejected_enrollments?: AgentEnrollmentRejection[]; next_cursor?: string | null }>(
    `/api/v1/admin/agents${agentId ? `?agent_id=${encodeURIComponent(agentId)}` : after ? `?after=${encodeURIComponent(after)}` : ""}`),
  agentSequenceRecovery: (agentId: string) => request<{ gaps: AgentSequenceGap[]; truncated: boolean; recovery_preview: AgentSequenceRecoveryPreview }>(`/api/v1/admin/agents/sequence-recovery?agent_id=${encodeURIComponent(agentId)}`),
  acceptAgentSequenceGap: (agentId: string, observationIds: string[], previewToken: string) => requestMutation<{ status: "authorized"; agent_id: string; observation_ids: string[]; preview_token: string }>("/api/v1/admin/agents/sequence-recovery", "POST", { agent_id: agentId, observation_ids: observationIds, preview_token: previewToken, confirm_loss: true }),
  refreshFileAuditCatalogs: () => requestMutation("/api/v1/admin/agents/file-audit/catalog", "POST", {}),
  fileAuditAccounts: (q: string, sids: string[]) =>
    requestMutation<{ items: Array<{ sid: string; name: string }> }>("/api/v1/admin/agents/file-audit/accounts", "POST", { q, sids }),
  agentAction: async (kind: "modules" | "disable" | "revoke" | "rights-probe" | "policy" | "remove" | "restore" | "file-audit" | "role", body: Record<string, unknown>) => {
    const result = await requestMutation<{ status?: string; password_detection_domain?: { status?: string } }>(`/api/v1/admin/agents/${kind}`, "POST", body);
    if (kind === "modules" && Object.prototype.hasOwnProperty.call(body, "password_detection_domain")
        && !["configured", "unchanged"].includes(result?.password_detection_domain?.status ?? "")) {
      throw new Error(PASSWORD_DETECTION_DOMAIN_UNAVAILABLE);
    }
    return result;
  },
  agentDeploymentDirectory: (body: { domain_id?: number; ou_entity_ids?: number[] }) => requestMutation<AgentDeploymentDirectory>("/api/v1/admin/agent-deployment-directory", "POST", body),
  gpoPlanCredentials: (body: GpoPlanSelection) => requestMutation<{ items: GpoCredential[]; selected_credential_id: string | null;
    write_enabled: false }>("/api/v1/agent-deployment/gpo/credentials", "POST", body),
  previewGpoPlan: (body: GpoPlanSelection & { credential_id: string; credential_revision: number }) => requestMutation<GpoPlan>("/api/v1/agent-deployment/gpo/preview", "POST", body),
  confirmGpoPlan: (body: { plan_id: string; plan_sha256: string; acknowledged: true; credential_id: string; credential_revision: number }) => requestMutation<{ plan_id: string; status: "confirmed"; write_enabled: false }>("/api/v1/agent-deployment/gpo/confirm", "POST", body),
  cancelGpoPlan: (body: { plan_id: string; plan_sha256: string }) => requestMutation<{ plan_id: string; status: "cancelled"; write_enabled: false }>("/api/v1/agent-deployment/gpo/cancel", "POST", body),
  agentGroupTokens: () => request<{ items: AgentGroupToken[] }>("/api/v1/admin/agent-group-tokens"),
  createAgentGroupToken: (body: { domain_id: number; ou_entity_ids: number[]; computer_entity_ids: number[]; max_uses: number; ttl_seconds: number;
    template_id: string; template_version: number; auto_approve: boolean; trusted_bindings: AgentDeploymentBinding[] }) => requestMutation<{ id: string; group_id: string; token: string; expires_at: string }>("/api/v1/admin/agent-group-tokens", "POST", body),
  revokeAgentGroupToken: (id: string) => requestMutation<{ status: string }>("/api/v1/admin/agent-group-tokens/revoke", "POST", { id }),
  agentTemplates: () => request<{ items: AgentTemplate[] }>("/api/v1/admin/agent-templates"),
  saveAgentTemplate: (body: { expected_version: number; assigned_modules: AgentItem["assigned_modules"]; collection_policy: Partial<AgentCollectionPolicy> }) => requestMutation<{ id: string; version: number }>("/api/v1/admin/agent-templates", "POST", body),
  agentGroupRequests: (filter: { group_id: string; token_id: string }) => requestMutation<{ items: AgentDeploymentRequest[]; has_more: boolean }>("/api/v1/admin/agent-group-requests", "POST", filter),
  approveAgentGroupRequests: (body: { filter: { group_id: string; token_id: string }; evidence: Array<AgentDeploymentBinding & { request_id: string }> }) => requestMutation<{ items: Array<{ request_id: string; status: string; token?: string; reason?: string }> }>("/api/v1/admin/agent-group-requests/approve", "POST", body),
  agentUpdateWaves: () => request<{ items: AgentUpdateWave[] }>("/api/v1/admin/agent-update-waves"),
  stopAgentUpdateWave: (wave_id: string) => requestMutation<AgentUpdateWave>("/api/v1/admin/agent-update-waves/stop", "POST", { wave_id }),
  createAgentToken: (body: { host_id: string; key_fingerprint: string; ttl_seconds: number; registration_host_name?: string }) => requestMutation<AgentEnrollmentToken>("/api/v1/admin/agent-tokens", "POST", body),
  agentInstallPackage: () => request<AgentInstallPackage>("/api/v1/admin/agent-install-package"),
  configureAgentInstallPackage: (body: AgentInstallPackageSettings) => requestMutation<AgentInstallPackage>("/api/v1/admin/agent-install-package", "POST", body),
  revokeAgentInstallPackage: (id: string) => requestMutation<AgentInstallPackage>("/api/v1/admin/agent-install-package/revoke", "POST", { id }),
  agentConsoleTokens: () => request<{ items: { id: string; created_at: string; expires_at: string | null; remaining: number | null; packaged: boolean; connected: number }[] }>(
    "/api/v1/admin/agent-console-tokens"),
  revokeAgentConsoleToken: (id: string) => requestMutation("/api/v1/admin/agent-console-tokens/revoke", "POST", { id }),
  homeSummary: () => request<HomeSummary>("/api/v1/home/summary").then(localizeHomeSummary),
  homePeriod: (params: URLSearchParams) => {
    const query = new URLSearchParams(params);
    query.set("contract", "v5");
    return request<HomePeriod>(`/api/v1/home/summary?${query}`);
  },
  homeDecisions: (params = new URLSearchParams()) => {
    const query = new URLSearchParams(params);
    query.set("contract", "v3");
    return request<HomeDecisionSummary>(`/api/v1/home/summary?${query}`);
  },
  domains: () => request<{ items: WorkspaceDomain[] }>("/api/v1/domains"),
  homeSummaryV2: (params = new URLSearchParams()) => {
    const query = new URLSearchParams(params);
    query.set("contract", "v2");
    return request<HomeSummaryV2>(`/api/v1/home/summary?${query}`).then(localizeHomeSummaryV2);
  },
  reportsV2Catalog: () => request<ReportCatalogV2Dto>("/api/v2/reports").then(localizeReportCatalog),
  reportV2Definition: (key: string) => request<ReportDefinitionDto>(`/api/v2/reports/${encodeURIComponent(key)}`).then(localizeReportDefinition),
  reportV2Detail: (key: string, rowId: string, params: URLSearchParams) => request<ReportResultDto>(`/api/v2/reports/${encodeURIComponent(key)}/rows/${encodeURIComponent(rowId)}/detail?${params.toString()}`).then((result) => localizeReportResult(result, params.get("tz") ?? undefined)),
  reportV2Data: (key: string, params: URLSearchParams, signal?: AbortSignal) => request<ReportResultDto>(`/api/v2/reports/${encodeURIComponent(key)}/data?${params.toString()}`, signal).then((result) => localizeReportResult(result, params.get("tz") ?? undefined)),
  problemPasswordCoverage: (params: URLSearchParams, signal: AbortSignal) =>
    request<ReportResultDto>(`/api/v2/reports/security.problems/password-coverage?${params.toString()}`, signal),
  bootstrap: () => request<Bootstrap>("/api/v1/ui/bootstrap"),
  v4Workspace: () => request<V4Workspace>("/api/v1/workspace"),
  v4Reports: () => request<{ api_version: "v4"; state: string; items: V4Report[]; allowed_count: number; total_count: number; explain_contract: string }>("/api/v1/reports/catalog"),
  v4ReportData: (reportKey: string, limit = 50, filters = new URLSearchParams()) => {
    const params = new URLSearchParams(filters);
    params.set("limit", String(limit));
    return request<V4ReportData>(`/api/v1/reports/${encodeURIComponent(reportKey)}/data?${params.toString()}`);
  },
  v4ReportAccessTrace: (reportKey: string) => request<V4ReportAccessTrace>(`/api/v1/reports/${encodeURIComponent(reportKey)}/access-trace`),
  vpnSessionSources: () => request<VpnSessionSources>("/api/v1/reports/vpn.audit/session-sources"),
  vpnSessions: (sourceDomainId: number, timeZone: string, limit = 200) => {
    const params = new URLSearchParams({
      domain_id: String(sourceDomainId),
      timezone: timeZone,
      limit: String(limit),
    });
    return request<VpnSessionReport>(`/api/v1/reports/vpn.audit/sessions?${params.toString()}`);
  },
  vpnSessionsByParams: (params: URLSearchParams) =>
    request<VpnSessionReport>(`/api/v1/reports/vpn.audit/sessions?${params.toString()}`),
  vpnSessionEvidence: (sourceDomainId: number, sessionRowId: string) => {
    const params = new URLSearchParams({ domain_id: String(sourceDomainId), session_row_id: sessionRowId });
    return request<VpnSessionEvidence>(`/api/v1/reports/vpn.audit/sessions/evidence?${params.toString()}`);
  },
  vpnFailedAuthorizationSeries: (sourceDomainId: number, timeFrom: string, timeTo: string, timezone = "UTC") => {
    const params = new URLSearchParams({ domain_id: String(sourceDomainId), time_from: timeFrom, time_to: timeTo, timezone });
    return request<VpnFailedAuthorizationSeries>(`/api/v1/reports/vpn.audit/failed-authorizations/series?${params.toString()}`);
  },
  vpnAuthorizationTimeline: (sourceDomainId: number, timeFrom: string, timeTo: string, timezone = "UTC") => {
    const params = new URLSearchParams({ domain_id: String(sourceDomainId), time_from: timeFrom, time_to: timeTo, timezone });
    return request<VpnAuthorizationTimeline>(`/api/v1/reports/vpn.audit/authorizations?${params.toString()}`);
  },
  vpnWindowsAuthenticationSources: () => request<VpnWindowsAuthenticationSources>("/api/v1/reports/vpn.audit/windows-authentication-sources"),
  vpnWindowsAuthentication: (sourceDomainId: number, timeFrom: string, timeTo: string, timezone = "UTC", limit = 200) => {
    const params = new URLSearchParams({
      domain_id: String(sourceDomainId),
      time_from: timeFrom,
      time_to: timeTo,
      timezone,
      limit: String(limit),
    });
    return request<VpnWindowsAuthenticationReport>(`/api/v1/reports/vpn.audit/windows-authentication?${params.toString()}`);
  },
  dcPowershellActivity: (sourceDomainId: number, timeFrom: string, timeTo: string, timezone = "UTC", limit = 200) => {
    const params = new URLSearchParams({ domain_id: String(sourceDomainId), time_from: timeFrom, time_to: timeTo, timezone, limit: String(limit) });
    return request<DcPowershellActivity>(`/api/v1/reports/dc.powershell/activity?${params.toString()}`);
  },
  adAccountChangeSources: () => request<AdAccountChangeSources>("/api/v1/reports/ad.state/account-change-sources"),
  adAccountChangeHistory: (sourceDomainId: number, timeFrom: string, timeTo: string, timezone = "UTC", limit = 200) => {
    const params = new URLSearchParams({ domain_id: String(sourceDomainId), time_from: timeFrom, time_to: timeTo, timezone, limit: String(limit) });
    return request<AdAccountChangeHistory>(`/api/v1/reports/ad.state/account-changes?${params.toString()}`);
  },
  securityEventSources: () => request<SecurityEventsSources>("/api/v1/reports/ad.state/security-event-sources"),
  securityEvents: (params: URLSearchParams) => request<SecurityEventsReport>(`/api/v1/reports/ad.state/security-events?${params.toString()}`),
  semanticRelations: (params: URLSearchParams) => request<SemanticRelationsReport>(`/api/v1/semantic/relations?${params.toString()}`),
  securityEventsExportUrl: (params: URLSearchParams) => {
    const bounded = new URLSearchParams(params);
    bounded.delete("cursor");
    bounded.delete("limit");
    return `/api/v1/reports/ad.state/security-events.csv?${bounded.toString()}`;
  },
  v4UpdateReportPreference: (reportKey: string, pinned: boolean) => requestMutation<{ item: { report_key: string; pinned: boolean; updated_at: string } }>(`/api/v1/reports/${encodeURIComponent(reportKey)}/preference`, "POST", { pinned }),
  v4UpdateFocusMetrics: (reportKey: string, focusMetricKeys: string[]) => requestMutation<{ item: { report_key: string; pinned: boolean; view_json: { focus_metric_keys?: string[] }; updated_at: string } }>(`/api/v1/reports/${encodeURIComponent(reportKey)}/preference`, "POST", { focus_metric_keys: focusMetricKeys }),
  v4ReportExportUrl: (reportKey: string, filters = new URLSearchParams()) => {
    const params = new URLSearchParams(filters);
    params.delete("cursor");
    params.delete("limit");
    const query = params.toString();
    return `/api/v1/reports/${encodeURIComponent(reportKey)}/export.csv${query ? `?${query}` : ""}`;
  },
  v4Access: (userId?: number) => request<V4Access>(`/api/v1/access/effective${userId ? `?user_id=${userId}` : ""}`),
  v4AccessSubjects: () => request<V4AccessSubjects>("/api/v1/access/subjects"),
  v4AccessSubjectsForAccountType: (accountType: "people" | "service") => request<V4AccessSubjects>(`/api/v1/access/subjects?account_type=${accountType}`),
  v4AccessGrantOptions: () => request<{ api_version: "v4"; items: V4ReportGrantOption[]; limits: { reports: number } }>("/api/v1/access/grant-options"),
  v4AccessAudit: () => request<{ items: V4AccessAuditItem[]; limit: number }>("/api/v1/access/audit?limit=100"),
  v4ReportAccessRequests: (includeAll = false) => request<{ api_version: "v4"; items: V4ReportAccessRequest[]; limit: number; review_allowed: boolean }>(`/api/v1/access/report-requests?scope=${includeAll ? "all" : "mine"}&limit=100`),
  v4CreateReportAccessRequest: (body: Record<string, unknown>) => requestMutation<{ item: V4ReportAccessRequest }>("/api/v1/access/report-requests", "POST", body),
  v4DecideReportAccessRequest: (requestId: number, body: Record<string, unknown>) => requestMutation<{ item: V4ReportAccessRequest }>(`/api/v1/access/report-requests/${requestId}/decision`, "POST", body),
  v4CreateReportAssignment: (body: Record<string, unknown>) => requestMutation<{ item: Record<string, unknown> }>("/api/v1/access/assignments", "POST", body),
  v4CreatePackageAssignment: (body: Record<string, unknown>) => requestMutation<{ item: Record<string, unknown> }>("/api/v1/access/package-assignments", "POST", body),
  watchEntries: (params: URLSearchParams) => request<import("./watch-types").WatchRegistry>(`/api/v1/watch?${params}`),
  saveWatchEntry: (id: string | null, body: import("./watch-types").WatchInput) => requestMutation(`/api/v1/watch${id ? `/${encodeURIComponent(id)}` : ""}`, "POST", body),
  decoys: (params: URLSearchParams) => request<import("./decoy-types").DecoyRegistry>(`/api/v1/decoys?${params}`),
  decoyTouches: (params: URLSearchParams) => request<import("./decoy-types").DecoyTouches>(`/api/v1/decoys?${params}`),
  saveDecoy: (id: string | null, body: import("./decoy-types").DecoyInput) => requestMutation(`/api/v1/decoys${id ? `/${encodeURIComponent(id)}` : ""}`, "POST", body),
  notificationWorkspace: (params: URLSearchParams) => request<import("./notification-types").NotificationWorkspace>(`/api/v1/notification-channels/workspace?${params}`),
  smtpSetupStatus: () => requestMutation<import("./notification-types").SmtpSetup>("/api/v1/notification-channels/smtp/setup/status", "POST", {}),
  smtpSetupSave: (body: import("./notification-types").SmtpSetupSave) => requestMutation<import("./notification-types").SmtpSetupResult>("/api/v1/notification-channels/smtp/setup/save", "POST", body),
  telegramSetup: (action: "status" | "token" | "chats" | "bind" | "test", body: Record<string, string> = {}) => requestMutation<import("./notification-types").TelegramSetup>(`/api/v1/notification-channels/telegram/setup/${action}`, "POST", body),
  updateNotificationChannel: (kind: string, body: { enabled: boolean; tls_mode: string; secret_ref: string; revision: number }) => requestMutation<{ item: import("./notification-types").NotificationChannel }>(`/api/v1/notification-channels/${encodeURIComponent(kind)}`, "POST", body),
  saveNotificationSubscription: (id: string | null, body: { recipient_user_id: number; channel: string; enabled: boolean; revision?: number }) => requestMutation<{ item: import("./notification-types").NotificationSubscription }>(`/api/v1/notification-subscriptions${id ? `/${encodeURIComponent(id)}` : ""}`, "POST", body),
  notificationSchedules: () => request<{ items: import("./notification-types").NotificationSchedule[] }>("/api/v1/notification-subscriptions/schedules"),
  saveNotificationSchedule: (id: string | null, body: import("./notification-types").NotificationScheduleInput & { revision?: number }) => requestMutation<{ item: import("./notification-types").NotificationSchedule }>(`/api/v1/notification-subscriptions/schedules${id ? `/${encodeURIComponent(id)}` : ""}`, "POST", body),
  testNotificationChannel: (id: string, problemId: string) => requestMutation<{ item: import("./notification-types").NotificationDelivery }>(`/api/v1/notification-subscriptions/${encodeURIComponent(id)}/test`, "POST", { problem_id: problemId }),
  platformSettings: () => request<{ items: PlatformSetting[] }>("/api/v1/platform-settings"),
  backupSettings: (signal?: AbortSignal) => request<BackupSettingsResponse>("/api/v1/admin/backup-settings", signal),
  updateBackupSettings: (body: BackupSettingsUpdate) => requestMutation<BackupSettings>("/api/v1/admin/backup-settings", "PUT", body),
  semanticControls: () => request<SemanticControls>("/api/v1/platform-settings/semantic-control"),
  updateSemanticControl: (change: SemanticControlChange) => requestMutation<{ status: string }>("/api/v1/platform-settings/semantic-control", "POST", change),
  plugins: () => request<{ items: PluginState[]; can_manage: boolean }>("/api/v1/plugins"),
  radiusPluginSources: () => request<{ item: { observed: RadiusPluginSources } }>("/api/v1/operations/plugins/sli.remote-access"),
  pluginSettings: (id: string) => request<PluginSettings>(`/api/plugins/${encodeURIComponent(id)}/settings`),
  savePluginSetting: (id: string, key: string, value: unknown) => requestMutation<{ plugin_id: string; key: string; value: unknown }>(`/api/plugins/${encodeURIComponent(id)}/settings`, "PUT", { key, value }),
  setPluginEnabled: (item: PluginState, enabled: boolean) => requestMutation<{ item: PluginState }>(`/api/v1/plugins/${encodeURIComponent(item.plugin_id)}`, "POST", { enabled, expected_revision: item.revision }),
  setupStatus: () => request<SetupStatus>("/api/v1/setup/status"),
  setSetupDomainArchived: (fqdn: string, is_archived: boolean) => requestMutation<{ item: SetupDomain }>(`/api/v1/setup/domains/${encodeURIComponent(fqdn)}`, "POST", { is_archived }),
  setupDomains: () => request<{ items: SetupDomain[] }>("/api/v1/setup/domains"),
  addSetupDomain: (domain: { fqdn: string; netbios_name?: string; forest?: string }) => requestMutation<{ item: SetupDomain }>("/api/v1/setup/domains", "POST", domain),
  setupDomainControllers: () => request<{ source: SetupDomainControllerSource; items: SetupDomainController[] }>("/api/v1/setup/domain-controllers"),
  addSetupDomainController: (body: { hostname: string; domain: string }) => requestMutation<{ item: SetupDomainController }>("/api/v1/setup/domain-controllers", "POST", body),
  setSetupDomainControllerEnabled: (hostname: string, enabled: boolean) => requestMutation<{ item: { hostname: string; enabled: boolean; previous_enabled: boolean } }>(`/api/v1/setup/domain-controllers/${encodeURIComponent(hostname)}`, "POST", { enabled }),
  updatePlatformSetting: (key: string, value: string) => requestMutation<{ item: PlatformSetting }>(`/api/v1/platform-settings/${encodeURIComponent(key)}`, "POST", { value }),
  v4Objects: (params = new URLSearchParams()) => request<{ api_version: "v4"; query: string; object_type?: string | null; state: string; items: V4ObjectItem[]; has_more: boolean; scope_filtered?: boolean; limits: Record<string, unknown> }>(`/api/v1/objects?${params.toString()}`),
  v4Object: (objectType: string, objectId: string) => request<V4ObjectDetail>(`/api/v1/objects/${encodeURIComponent(objectType)}/${encodeURIComponent(objectId)}`),
  v4Datasets: () => request<{ api_version: "v4"; items: V4Dataset[]; arbitrary_sql_allowed: false }>("/api/v1/reports/datasets"),
  v4ReportDefinitions: () => request<{ api_version: "v4"; items: V4ReportDefinition[]; limit: number; total_count: string }>("/api/v1/reports/definitions?limit=200"),
  v4BuilderPreview: (body: Record<string, unknown>) => requestMutation<V4BuilderPreview>("/api/v1/reports/builder/preview", "POST", body),
  v4ReportDefinitionDetail: (key: string) => request<V4ReportDefinitionDetail>(`/api/v1/reports/definitions/${encodeURIComponent(key)}`),
  v4PromoteReportVersion: (key: string, version: number) => requestMutation<{ item: Record<string, unknown> }>(`/api/v1/reports/definitions/${encodeURIComponent(key)}/versions/${version}/publish`, "POST"),
  v4RetireReport: (key: string) => requestMutation<{ item: Record<string, unknown> }>(`/api/v1/reports/definitions/${encodeURIComponent(key)}/retire`, "POST"),
  v4SetReportVisibility: (key: string, body: { discoverable: boolean; requestable: boolean }) => requestMutation<{ item: Record<string, unknown> }>(`/api/v1/reports/definitions/${encodeURIComponent(key)}/visibility`, "POST", body),
  v4ReportAccessSummary: (key: string) => request<V4ReportAccessSummary>(`/api/v1/reports/${encodeURIComponent(key)}/access-summary`),
  v4PublishReport: (body: Record<string, unknown>) => requestMutation<{ item: Record<string, unknown> }>("/api/v1/reports/definitions", "POST", body),
  events: (params = new URLSearchParams()) => request<EventsResponse>(`/api/v1/events?${params.toString()}`),
  event: (eventDbId: string) => request<{ api_version: "v1"; item: EventDetail }>(`/api/v1/events/${encodeURIComponent(eventDbId)}`),
  eventsBatch: (eventDbIds: readonly number[]) => requestEventBatch(eventDbIds),
  eventAvailable: async (eventDbId: string) => (await requestEventBatch([eventDbId])).items.length > 0,
  eventRelations: (eventDbId: number) => request<EventRelations>(`/api/v1/events/${encodeURIComponent(String(eventDbId))}/relations`),
  eventEntities: (eventDbId: number) => request<EventEntities>(`/api/v1/events/${encodeURIComponent(String(eventDbId))}/entities`),
  operations: () => request<OperationsOverview>("/api/v1/operations/overview"),
  operationsWorkers: () => request<Pick<OperationsOverview, "workers">>("/api/v1/operations/overview?view=workers"),
  storageOverview: () => request<StorageOverview>("/api/v1/operations/overview?view=storage"),
  storageGrowth: () => request<StorageGrowth>("/api/v1/operations/overview?view=storage-growth"),
  platformReadiness: () => request<PlatformReadiness>("/api/v1/operations/overview?view=readiness"),
  sourceDetail: (hostname: string) => request<SourceDetail>(`/api/v1/operations/sources/${encodeURIComponent(hostname)}`),
  diagnostics: () => request<DiagnosticsOverview>("/api/diagnostics/overview?run_checks=0"),
  securityLogFull: () => request<{ items: { server: string; time_created_utc: string; record_id: string }[] }>("/api/v1/operations/security-log-full"),
  systemHealth: () => request<SystemHealth>("/api/system/health"),
  dashboardSnapshot: () => request<DashboardSnapshot>("/api/dashboard/snapshot"),
  overview: (params = new URLSearchParams()) => request<OverviewWorkspace>(`/api/v1/overview?${params.toString()}`),
  agentCollection: () => request<{ agent_collection: AgentCollectionHealth }>("/api/v1/overview?view=agents"),
  investigationWorkspace: (params: URLSearchParams) => request<InvestigationWorkspaceV1>(`/api/v1/investigations?${params.toString()}`),
  semanticScenarios: (params = new URLSearchParams()) => request<SemanticScenariosWorkspace>(`/api/v1/semantic/scenarios?${params.toString()}`),
  sigmaValidation: (params: SigmaValidationRequest) => request<SigmaValidationResponse>(`/api/v1/semantic/attack-coverage?${new URLSearchParams(params).toString()}`),
  sigmaRules: (scope?: SigmaRuleScope) => request<SigmaRuleListResponse>(`/api/v1/semantic/sigma-rules${scope ? `?${new URLSearchParams(scope).toString()}` : ""}`),
  sigmaLiveRules: () => request<SigmaLiveRulesResponse>("/api/v1/semantic/sigma-live-rules"),
  setSigmaLiveRule: (rule_id: string, enabled: boolean) => requestMutation<SigmaLiveRulesResponse>(
    "/api/v1/semantic/sigma-live-rules", "POST", { rule_id, enabled }),
  securityProblems: (params = new URLSearchParams()) => {
    const query = new URLSearchParams(params);
    query.set("source", "semantic-production");
    return request<SecurityProblemsReport>(`/api/findings?${query.toString()}`);
  },
  semanticActions: (params = new URLSearchParams()) => request<SemanticActionsWorkspace>(`/api/v1/semantic/actions?${params.toString()}`),
  semanticCalibration: (windowHours = 24) => request<SemanticCalibrationWorkspace>(`/api/v1/semantic/calibration?window_hours=${encodeURIComponent(String(windowHours))}`),
  reviewSemanticScenario: (scenarioId: string, body: { review_request_id: string; verdict: SemanticScenarioReview["verdict"]; review_confidence: SemanticScenarioReview["review_confidence"]; rationale: string }) => requestMutation<{ api_version: "v1"; item: SemanticScenarioReview; replayed: boolean }>(`/api/v1/semantic/scenarios/${encodeURIComponent(scenarioId)}/review`, "POST", body),
  investigationCase: (id: number, page?: { eventAfter?: number; referenceAfter?: string; anchorEventId?: number }) => {
    const query = new URLSearchParams({ evidence_page: "1" });
    if (page?.eventAfter !== undefined) query.set("event_after", String(page.eventAfter));
    if (page?.referenceAfter !== undefined) query.set("reference_after", page.referenceAfter);
    if (page?.anchorEventId !== undefined) query.set("anchor_event_id", String(page.anchorEventId));
    return request<InvestigationCase>(`/api/v1/investigations/${id}?${query}`);
  },
  investigationCases: () => request<{ items: InvestigationCaseSummary[]; limit: number }>("/api/v1/investigation-cases?limit=50"),
  createInvestigation: (body: { title: string; owner?: string | null; event_db_id?: number }) => requestMutation<InvestigationCase>("/api/v1/investigations", "POST", body),
  createInvestigationFromFinding: (findingId: number) => requestMutation<InvestigationCase>("/api/v1/investigations/from-finding", "POST", { finding_id: findingId }),
  linkFindingToInvestigation: (id: number, findingId: number) => requestMutation<InvestigationCase>(`/api/v1/investigations/${id}/findings`, "POST", { finding_id: findingId }),
  addInvestigationEvent: (id: number, body: { event_db_id: number; relation_status?: "confirmed" | "excluded" }) => requestMutation<{ status: "ok" }>(`/api/v1/investigations/${id}/events`, "POST", body),
  addInvestigationEvidenceRef: (id: number, body: { evidence_kind: "vpn_accounting_session"; source_domain_id: number; reference_id: string; relation_status?: "confirmed" | "excluded" }) => requestMutation<{ status: "ok" }>(`/api/v1/investigations/${id}/evidence-refs`, "POST", body),
  addInvestigationNote: (id: number, body: { body: string }) => requestMutation<{ status: "ok" }>(`/api/v1/investigations/${id}/notes`, "POST", body),
  updateInvestigationStatus: (id: number, body: { status: string }) => requestMutation<InvestigationCase>(`/api/v1/investigations/${id}/status`, "POST", body),
  entitiesWorkspace: (params = new URLSearchParams()) => request<EntitiesWorkspace>(`/api/v1/entities?${params.toString()}`),
  entityWorkspace: (entityId: string, params = new URLSearchParams()) => request<EntityWorkspaceDetail>(`/api/v1/entities/${encodeURIComponent(entityId)}?${params.toString()}`),
  entityVpnSessions: (entityId: string, params: URLSearchParams) => request<EntityVpnSessions>(`/api/v1/entities/${encodeURIComponent(entityId)}/vpn-sessions?${params.toString()}`),
  adminUsers: () => request<AuthUserInventory>("/api/auth/users"),
  logout: () => requestMutation<{ status: "ok" }>("/api/auth/logout", "POST"),
  createUser: (body: { username: string; password: string; role: string }) => requestMutation<{ item: unknown }>("/api/auth/users", "POST", body),
  updateUser: (id: number, body: { role?: string; is_active?: boolean }) => requestMutation<{ item: unknown }>(`/api/auth/users/${id}`, "POST", body),
  resetUserPassword: (id: number, password: string) => requestMutation<{ item: { id: number; username: string; sessions_revoked: boolean } }>(`/api/auth/users/${id}/password`, "POST", { password }),
  apiKeys: () => request<{ items: ApiKeyInventoryItem[] }>("/api/auth/api-keys"),
  createApiKey: (body: { label: string; role: string }) => requestMutation<CreatedApiKey>("/api/auth/api-keys", "POST", body),
  revokeApiKey: (id: number) => requestMutation<{ status: "revoked" }>(`/api/auth/api-keys/${id}/revoke`, "POST"),
  updateFinding: (id: number, body: { status: string; assigned_to?: string | null; note?: string | null; status_reason?: string | null }) => requestMutation<{ status: "ok"; changed: boolean; finding: FindingItem }>(`/api/findings/${id}/status`, "POST", body),
  decideProblems: (body: { ids: number[]; state?: "new" | "active" | "deferred" | "closed" | "false_positive"; assignee_id?: number | null;
    until?: string; classification?: "fixed" | "expected" | "false_positive"; comment?: string }) =>
    requestMutation<{ status: "ok"; changed: number }>("/api/findings/queue-decisions", "POST", body),
  riskResponsibles: () => request<{ items: Array<{ id: number; username: string }> }>("/api/findings/risk-responsibles"),
  findingRiskAudit: (id: number, before: number) => request<{ items: FindingRiskAudit[]; has_more: boolean }>(`/api/findings/${id}/risk-audit?before=${before}`),
  changeFindingRisk: (id: number, body: FindingRiskRequest) => requestMutation<{ status: "ok"; acceptance: FindingRiskAcceptance; risk_audit: FindingRiskAudit[] }>(`/api/findings/${id}/risk-acceptance`, "POST", body),
  sourcePacks: () => request<{ api_version: "v1"; items: SourcePack[] }>("/api/v1/source-packs"),
  dcOnboardingPreflight: (candidate: { hostname: string; connect_address: string; channels: string[] }) => requestJson<DcOnboardingPlan>("/api/v1/source-onboarding/preflight", candidate),
};

