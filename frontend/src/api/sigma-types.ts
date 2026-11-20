/** Read-only projection from /api/v1/semantic/attack-coverage. */
export type SigmaValidationRequest = {
  installation_id: string;
  plugin_id: string;
  source_instance_id: string;
  source_generation: string;
  collection_scope_id: string;
  catalog_sha256: string;
  since: string;
  until: string;
};

export type SigmaHistoryExecution = {
  manifest_sha256: string;
  plan_sha256: string;
  compiler_version: string;
  mapping_version: string;
  overlay_sha256: string | null;
  mode: "test";
  state: "no_data" | "no_matches" | "matched" | "degraded" | "not_evaluable" | "incomplete";
  complete: boolean;
  counts: Record<"scanned" | "evaluable" | "matched" | "suppressed" | "unknown" | "skipped", number>;
  evaluable_percent: number | null;
  matches_per_1000_evaluable: number | null;
  required_fields: string[];
  evaluation_intervals: Array<{ since: string; until: string }>;
  quality: Array<{
    since: string;
    until: string;
    status: string;
    reasons: Array<[string, number]>;
    unknown_fields: Array<[string, string, number]>;
  }>;
};

export type SigmaValidationRule = {
  rule_id: string;
  raw_sha256: string;
  upstream_commit: string;
  compile_state: "supported" | "unsupported" | "not_checked";
  fixture_validation: string;
  current_admission: string;
  executions: SigmaHistoryExecution[];
};

export type SigmaValidationResponse = {
  api_version: "v1";
  contract: "sli.sigma.attack-coverage.v1";
  read_only: true;
  state: "available" | "unavailable";
  reason: string | null;
  scope: Pick<SigmaValidationRequest, "installation_id" | "plugin_id" | "source_instance_id" | "source_generation" | "collection_scope_id">;
  since: string;
  until: string;
  rules: SigmaValidationRule[];
};

export type SigmaRuleScope = SigmaValidationResponse["scope"];
export type SigmaRulePolicy = {
  policy_id: string;
  policy_version: number;
  policy_title: string | null;
  lifecycle_status: string;
  admitted: boolean;
  effective_mode: string | null;
  execution: Record<string, unknown>;
};
export type SigmaRuleListRow = {
  rule_id: string;
  raw_sha256: string;
  canonical_sha256: string;
  upstream_commit: string;
  status: string;
  tags: string[];
  title: string | null;
  description: string | null;
  metadata_state: "available" | "unavailable";
  executions: SigmaHistoryExecution[];
  admission: { state: "available" | "unavailable"; reason: string | null; policies: SigmaRulePolicy[] };
  runtime: { state: "measured" | "unmeasured"; basis: "eligible_atomic_detection_inputs";
    enabled: number | null; shadow: number | null; test: number | null };
};
export type SigmaRuleListResponse = {
  api_version: "v1";
  contract: "sli.sigma.rules.v1";
  read_only: true;
  state: "available" | "unavailable";
  reason: string | null;
  metadata_state: "available" | "unavailable";
  window_basis: "latest_retained_test_history";
  sources: SigmaRuleScope[];
  scope: SigmaRuleScope | null;
  since: string | null;
  until: string | null;
  rules: SigmaRuleListRow[];
};
