import type { ReportCatalogV2Dto, ReportColumnDto, ReportDefinitionDto, ReportDetailDto, ReportResultDto, ReportViewDto } from "../api/report-v2-types";
import { getLocale, t, type MessageKey } from "./index";
import { ru } from "./ru";
import { en } from "./en";
import { entityLabel, problemPresentation } from "../app/security-problems-report";
import type { SecurityProblemFinding } from "../api/client";
import { resolvePresentation } from "./messages";
import { formatDateTime } from "../design-system/format";

/** Translate declared values only; preserve source codes and object names. */
export function reportEnumText(value: unknown): unknown {
  const labels = {
    not_collected: "reports.states.not_collected.title", passed: "reports.values.passed", unknown: "reports.values.unknown", inactive: "reports.values.inactive",
    BiDirectional: "reports.values.BiDirectional", Uplevel: "reports.values.Uplevel",
    Inbound: "reports.values.Inbound", Outbound: "reports.values.Outbound", Downlevel: "reports.values.Downlevel",
  } as const;
  return typeof value === "string" && Object.hasOwn(labels, value) ? t(labels[value as keyof typeof labels]) : value;
}

function adValueText(value: unknown, timeZone?: string): unknown {
  if (typeof value === "boolean") return t(value ? "reports.boolean.yes" : "reports.boolean.no");
  if (typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(value)) return formatDateTime(value, true, timeZone);
  return reportEnumText(value);
}

/** Reports whose declared wording arrives as message codes; the server sends the codes with the text. */
const CODED_REPORTS = new Set(["security.rule-quality", "security.problems", "ad.users.v2", "ad.computers.v6", "ad.infrastructure"]);

// Only declared presentation is translated. Object descriptions, domain
// options, paths and filter values retain the server's exact values.
const keys = new Map<string, MessageKey>(
  (Object.keys(ru) as MessageKey[]).filter((key) => key.startsWith("reports.metadata.")).map((key) => [ru[key], key]),
);
const userSecurityFlags = new Map<string, MessageKey>(
  (Object.keys(ru) as MessageKey[]).filter((key) => key.startsWith("reports.v2.ad.users.v2.flags.")).map((key) => [ru[key], key]),
);

export function reportText(value: string): string {
  const key = keys.get(value);
  if (getLocale() !== "en") return value;
  if (key) return t(key);
  const coverage = /^Ограничений покрытия источников: (\d+)\. Пустой список не доказывает безопасное состояние\.$/.exec(value);
  if (coverage) return t("reports.metadata.coverage_count", { count: coverage[1] });
  const truncated = /^Показаны первые (\d+) строк; уточните поиск\.$/.exec(value);
  return truncated ? t("reports.metadata.truncated_count", { count: truncated[1] }) : value;
}

/** Stable presentation keys survive changes to the server's Russian wording. */
export function reportMetadataText(report: string, field: string, fallback: string, params?: Record<string, string | number>): string {
  const key = `reports.v2.${report}.${field}`;
  return (getLocale() === "en" || field === "limitations.coverage_unverified" && /^workstations\.(logons|processes|protection|overview)$/.test(report)) && Object.hasOwn(en, key) ? t(key as MessageKey, params) : fallback;
}

// Presets and links have no DTO key; use their stable action rather than their label or position.
export function reportPresetKey(params: Record<string, string>): string {
  return JSON.stringify(Object.fromEntries(Object.entries(params).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)));
}

function column(report: string, prefix: string, value: ReportColumnDto): ReportColumnDto {
  const field = `${prefix}.${value.key}`;
  return { ...value, label: reportMetadataText(report, `${field}.label`, value.label),
    labels: value.labels ? Object.fromEntries(Object.entries(value.labels).map(([key, label]) => [key, reportMetadataText(report, `${field}.labels.${key}`, label)])) : undefined };
}

export function localizeReportView(view: ReportViewDto, report: string): ReportViewDto {
  const field = `views.${view.key}`;
  return { ...view, title: view.title ? reportMetadataText(report, `${field}.title`, view.title) : view.title,
    note: view.note ? reportMetadataText(report, `${field}.note`, view.note) : view.note,
    columns: view.columns?.map((item) => column(report, `${field}.columns`, item)),
    series: view.series?.map((item) => ({ ...item, label: reportMetadataText(report, `${field}.series.${item.path}`, item.label) })) };
}

function detail(report: string, value: ReportDetailDto): ReportDetailDto {
  return { ...value, title: reportMetadataText(report, "detail.title", value.title),
    columns: value.columns.map((item) => column(report, "detail.columns", item)),
    row_links: value.row_links.map((link) => ({ ...link, label: reportMetadataText(report, `detail.row_links.${link.href}`, link.label) })) };
}

function options(report: string, param: string, values: ReportDefinitionDto["params"][number]["options"]) {
  const localized = values?.map((option) => {
    const label = reportMetadataText(report, `params.${param}.options.${option.value}`, option.label);
    return label === option.label ? option : { ...option, label };
  });
  return localized?.some((option, index) => option !== values![index]) ? localized : values;
}

function filterOptions(report: string, values: ReportDefinitionDto["filter_options"]) {
  const entries = Object.entries(values).map(([param, values]) => [param, options(report, param, values)!] as const);
  return entries.some(([param, options]) => options !== values[param]) ? Object.fromEntries(entries) : values;
}

function localizeReportDefinitionText(value: ReportDefinitionDto): ReportDefinitionDto {
  if (value.key === "security.problems" && "presentation_messages" in value) return resolvePresentation(value);
  if (CODED_REPORTS.has(value.key) && "presentation_messages" in value) value = resolvePresentation(value);
  if (getLocale() !== "en") return value;
  const report = value.key;
  return { ...value, title: reportMetadataText(report, "title", value.title), description: reportMetadataText(report, "description", value.description),
    intent: value.intent ? { ...value.intent,
      question: reportMetadataText(report, "intent.question", value.intent.question),
      denominator: reportMetadataText(report, "intent.denominator", value.intent.denominator),
      freshness_expectation: reportMetadataText(report, "intent.freshness_expectation", value.intent.freshness_expectation),
    } : value.intent,
    params: value.params.map((param) => ({ ...param, label: reportMetadataText(report, `params.${param.key}.label`, param.label), options: options(report, param.key, param.options) })),
    filter_options: filterOptions(report, value.filter_options),
    columns: value.columns.map((item) => column(report, "columns", item)), views: value.views.map((view) => localizeReportView(view, report)),
    detail: typeof value.detail === "object" ? detail(report, value.detail) : value.detail,
    presets: value.presets.map((preset) => ({ ...preset, label: reportMetadataText(report, `presets.${reportPresetKey(preset.params)}`, preset.label) })),
    row_links: value.row_links.map((link) => ({ ...link, label: reportMetadataText(report, `row_links.${link.href}`, link.label) })),
  };
}

function withoutADInfrastructureClutter(value: ReportDefinitionDto): ReportDefinitionDto {
  if (value.key !== "ad.infrastructure") return value;
  return { ...value,
    columns: value.columns.map((item) => ({ ...item,
      hidden_by_default: item.key === "entity_type" ? true : item.hidden_by_default,
      labels: item.key === "qualification" ? { ...item.labels, not_evaluated: "—", policy_not_defined: "—" } : item.labels,
    })),
    params: value.params.map((param) => param.key === "qualification"
      ? { ...param, options: param.options?.map((option) => ["not_evaluated", "policy_not_defined"].includes(option.value) ? { ...option, label: "—" } : option) }
      : param),
  };
}

export function localizeReportDefinition(value: ReportDefinitionDto): ReportDefinitionDto {
  return withoutADInfrastructureClutter(localizeReportDefinitionText(value));
}

export function localizeReportCatalog(value: ReportCatalogV2Dto): ReportCatalogV2Dto {
  if (value.items.some((item) => CODED_REPORTS.has(item.key) && "presentation_messages" in item)) {
    value = { ...value, items: value.items.map((item) => CODED_REPORTS.has(item.key) ? resolvePresentation(item) : item) };
  }
  if (getLocale() !== "en") return value;
  return { ...value, items: value.items.map((item) => ({ ...item, title: reportMetadataText(item.key, "title", item.title), description: reportMetadataText(item.key, "description", item.description),
    section_title: reportMetadataText("sections", `${item.section}.title`, item.section_title), home_view: item.home_view ? localizeReportView(item.home_view, item.key) : item.home_view })) };
}

export function localizeReportRow(report: string, row: Record<string, unknown>, timeZone?: string): Record<string, unknown> {
  if (report === "security.problems") {
    const { presentation_messages: messages } = row as unknown as SecurityProblemFinding;
    if (row.next_step_code === "security.problems.presentation.default_next" ||
        messages?.next_text?.code === "security.problems.presentation.default_next") {
      return { ...resolvePresentation(row, timeZone), next_text: null };
    }
    if (messages) return resolvePresentation(row, timeZone);
    if (getLocale() !== "en") return row;
  }
  const missingADValue = report === "ad.infrastructure" && ("actual_value" in row || "actual_text" in row) && (row.actual_value == null
    || ["not_collected", "not_evaluated", "unknown", "unavailable", "timeout", "partial"].includes(String(row.actual_value).toLowerCase()));
  if (missingADValue) row = { ...row, actual_text: "—" };
  if (report === "ad.infrastructure" && typeof row.control_id === "string") {
    const originalContext = row.object_context as Record<string, unknown> | undefined;
    row = { ...row, actual_text: missingADValue ? "—" : adValueText(row.actual_value, timeZone) ?? row.actual_text,
      context: Array.isArray(row.context) ? (row.context as Array<{ code?: string; value: unknown }>).map((entry) => ({ ...entry,
        value: entry.code && (entry.code.endsWith("_utc") || ["trust_type", "trust_direction", "is_global_catalog", "is_read_only"].includes(entry.code))
          ? adValueText(originalContext?.[entry.code] ?? entry.value, timeZone) : entry.value,
      })) : row.context,
    };
  }
  if (getLocale() !== "en") return row;
  if (report === "ad.infrastructure" && typeof row.control_id === "string") {
    const control = row.control_id;
    const text = (field: string, value: unknown) => typeof value === "string" ? reportMetadataText(report, field, value) : value;
    const unset = row.authority === "not_defined";
    const zero = ["replication.result_code", "replication.consecutive_failures"].includes(control);
    return { ...row,
      label: text(`controls.${control}.label`, row.label),
      expected_condition: text(`controls.${unset ? "policy_unset" : zero ? "zero.expected" : `${control}.expected`}`, row.expected_condition),
      authority_text: text(`authority.${row.authority}`, row.authority_text),
      actual_text: typeof row.actual_value === "boolean" ? t(row.actual_value ? "reports.boolean.yes" : "reports.boolean.no") : row.actual_text,
      context: Array.isArray(row.context) ? (row.context as Array<{ code?: string; label: string; value: unknown }>).map((entry) => ({ ...entry,
        label: entry.code ? reportMetadataText(report, `context_labels.${entry.code}`, entry.label) : entry.label,
        value: entry.code && typeof (row.object_context as Record<string, unknown> | undefined)?.[entry.code] === "boolean"
          ? t((row.object_context as Record<string, unknown>)[entry.code] ? "reports.boolean.yes" : "reports.boolean.no") : entry.value,
      })) : row.context,
    };
  }
  if (report === "ad.computers.v6" && (Array.isArray(row.reasons) || Array.isArray(row.quality_issues))) {
    type Reason = { code: string; label: string; threshold_days?: number; presentation_messages?: Record<string, unknown>; [key: string]: unknown };
    const reasonText = (reason: Reason, kind: string) => reason.presentation_messages?.label
      || (reason.code === "stale_activity" && typeof reason.threshold_days !== "number") ? reason.label
      : reportMetadataText(report, `${kind}.${reason.code}`, reason.label, { threshold_days: reason.threshold_days ?? "" });
    const securityCodes = ["unsupported_os", "laps_expired", "unconstrained_delegation"];
    const reasons = Array.isArray(row.reasons) && (row.reasons as Reason[]).some((reason) => securityCodes.includes(reason.code)) ? (row.reasons as Reason[]).map((reason) => {
      if (!securityCodes.includes(reason.code)) return reason;
      const params = { operating_system: String(reason.operating_system ?? ""), support_end_date: formatDateTime(String(reason.support_end_date ?? ""), false, timeZone), expiration_utc: formatDateTime(String(reason.expiration_utc ?? ""), true, timeZone) };
      return { ...reason, label: reasonText(reason, "reasons"), ...Object.fromEntries(
        ["observed", "condition", "qualification", "limitation", "next_action"].map((field) => [field,
          reason.presentation_messages?.[field] ? reason[field]
            : reportMetadataText(report, `security.${reason.code}.${field}`, String(reason[field] ?? ""), params)]),
      ) };
    }) : row.reasons;
    return { ...row, reasons,
      reason_text: Array.isArray(reasons) ? (reasons as Reason[]).map((reason) => reasonText(reason, "reasons")).join(", ") || null : row.reason_text,
      quality_text: Array.isArray(row.quality_issues) ? (row.quality_issues as Reason[]).filter((reason) => reason.code !== "not_evaluated").map((reason) => reasonText(reason, "quality")).join(", ") || null : row.quality_text,
    };
  }
  if (report === "security.problems") {
    const bucket = (row.review_hint as { bucket?: string } | undefined)?.bucket;
    const finding = row as unknown as SecurityProblemFinding;
    const view = problemPresentation(finding);
    return { ...row,
      ...(bucket && typeof row.review_hint_text === "string" ? {
        review_hint_text: reportMetadataText(report, `presentation.${bucket}`, row.review_hint_text),
      } : {}),
      ...(row.presentation_code === "audit_policy_changed" ? {
        title_text: view.title, what_happened: view.whatHappened, why_text: view.whyItMatters, next_text: view.nextAction,
      } : {}),
      actor_text: typeof row.actor === "string" ? view.actor : row.actor_text,
      entity_text: Array.isArray(row.entities) && row.entities.length
        ? row.entities.map((entity) => entityLabel(entity)).join(", ") : row.entity_text,
    };
  }
  if (report === "ad.users.v2" && Array.isArray(row.reasons)) {
    const observations = Array.isArray(row.review_details) ? row.review_details : [...row.reasons, ...(Array.isArray(row.information_limitations) ? row.information_limitations : [])];
    const hasLocalizedFlags = Array.isArray(row.flags) && row.flags.some((flag) => userSecurityFlags.has(String(flag)));
    if (!hasLocalizedFlags && !observations.some((reason) => reason.policy || reason.key === "temporary_membership"
      || reportMetadataText(report, `params.reason.options.${reason.key}`, String(reason.label)) !== reason.label)) return row;
    const localized: Array<Record<string, unknown>> = (observations as Array<Record<string, unknown>>).map((reason) => {
      const policy = reason.policy as { status: string; reason: string | null; threshold_days: number; value: string | null; observed_at: string | null } | undefined;
      if (["password_not_required", "kerberos_no_preauth", "spn_privileged", "spn_old_password", "privileged_password_never_expires"].includes(String(reason.key))) {
        const label = reportMetadataText(report, `params.reason.options.${reason.key}`, String(reason.label));
        const evidence = reason.evidence as { uac?: number; spn?: string[]; password_last_set?: string; snapshot_at?: string } | undefined;
        return { ...reason, label, summary: label, qualification: label,
          condition: reportMetadataText(report, `security.${reason.key}.condition`, String(reason.condition)),
          observed: evidence ? reportMetadataText(report, "security.observed", String(reason.observed), {
            uac: evidence.uac ?? "—", spn: evidence.spn?.join("; ") || "—", password: evidence.password_last_set ?? "—", snapshot: evidence.snapshot_at ?? "—",
          }) : reason.observed,
          limitation: reportMetadataText(report, "security.limitation", String(reason.limitation)),
          next: reportMetadataText(report, `security.${reason.key}.next`, String(reason.next)) };
      }
      if (policy && ["password_age", "password_age_unknown", "inactive_threshold", "enabled_activity_unknown"].includes(String(reason.key))) {
        const field = String(reason.key).startsWith("password_age") ? "pwdLastSet" : "lastLogonTimestamp";
        const params = { days: policy.threshold_days, field, reason: reportMetadataText(report, `hygiene.reasons.${policy.reason}`, policy.reason ?? "") };
        const unknown = policy.status === "unknown";
        return { ...reason, label: reportMetadataText(report, `params.reason.options.${reason.key}`, String(reason.label)),
          summary: reportMetadataText(report, `hygiene.${unknown ? "unknown" : "summary"}`, String(reason.summary), params),
          observed: `${field} = ${policy.value ?? "—"}; ${reportMetadataText(report, "hygiene.snapshot", "")} = ${policy.observed_at ?? "—"}`,
          condition: reportMetadataText(report, "hygiene.condition", String(reason.condition), params),
          qualification: reportMetadataText(report, `hygiene.${unknown ? "unknown" : "exceeded"}`, String(reason.qualification), params),
          limitation: reportMetadataText(report, `hygiene.${field === "pwdLastSet" ? "password_caveat" : "inactivity_caveat"}`, String(reason.limitation)),
          next: reportMetadataText(report, "hygiene.next", String(reason.next)) };
      }
      if (reason.key !== "temporary_membership") return { ...reason, label: reportMetadataText(report, `params.reason.options.${reason.key}`, String(reason.label)) };
      return { ...reason, ...Object.fromEntries(["label", "condition", "qualification", "limitation", "next"].map((field) => [
        field, reportMetadataText(report, field === "label" ? "params.reason.options.temporary_membership" : `presentation.temporary_membership.${field}`, String(reason[field] ?? "")),
      ])) };
    });
    const confirmedKeys = new Set((row.reasons as Array<Record<string, unknown>>).map((reason) => reason.key));
    const reasons = localized.filter((reason) => confirmedKeys.has(reason.key));
    const information = localized.filter((reason) => !confirmedKeys.has(reason.key));
    return { ...row, reasons, reason_text: reasons.map((reason) => reason.label).join(", ") || null,
      ...(Array.isArray(row.flags) ? { flags: row.flags.map((flag) => userSecurityFlags.has(String(flag)) ? t(userSecurityFlags.get(String(flag))!) : flag) } : {}),
      ...(Array.isArray(row.review_details) ? { review_details: localized } : {}),
      ...(Array.isArray(row.information_limitations) ? { information_limitations: information, information_text: information.map((reason) => reason.label).join(", ") || null } : {}) };
  }
  if (report === "ad.gpo.v2" && Array.isArray(row.reasons)) {
    const reasons: Array<Record<string, unknown>> = (row.reasons as Array<Record<string, unknown>>).map((reason) => ({ ...reason,
      title: reportMetadataText(report, `reasons.${reason.code}.title`, String(reason.title)),
      next: reportMetadataText(report, `reasons.${reason.code}.next`, String(reason.next)),
    }));
    const titles = (category: string) => reasons.filter((reason) => reason.category === category).map((reason) => reason.title).join(", ") || null;
    return { ...row, reasons, reason_titles: titles("deviation"), unverified_titles: titles("unverified"), assignment_titles: titles("assignment"), next_step: reasons[0]?.next ?? null };
  }
  if (report === "vpn.accounts") {
    const localized = { ...row };
    for (const field of ["department_text", "password_text", "privilege_text"]) {
      const code = row[`${field}_code`];
      if (typeof code === "string" && typeof row[field] === "string") localized[field] = reportMetadataText(report, `presentation.${code}`, row[field]);
    }
    return localized;
  }
  if (report === "security.events.chains" && typeof row.change_text === "string") {
    // These structured source observations already carry stable state/kind codes.
    type ObservedState = { state?: string; value?: string };
    const transition = (row.account_change as { observed_transition?: { before?: ObservedState; after?: ObservedState } } | undefined)?.observed_transition;
    if (transition?.before && Object.keys(transition.before).length || transition?.after && Object.keys(transition.after).length) {
      const stateText = (state?: ObservedState) => state?.state === "observed"
        ? reportMetadataText(report, `presentation.states.${state.value}`, state.value ?? "")
        : t("reports.v2.security.events.chains.presentation.states.not_confirmed");
      return { ...row, change_text: `${stateText(transition?.before)} → ${stateText(transition?.after)}` };
    }
    const change = row.change as { state?: string; kind?: string } | undefined;
    if (change?.state === "observed" && change.kind) return { ...row, change_text: reportMetadataText(report, `presentation.changes.${change.kind}`, row.change_text) };
  }
  return row;
}

export function localizeReportResult(value: ReportResultDto, timeZone?: string): ReportResultDto {
  if (value.report_key === "events.journal") {
    value = { ...value, items: value.items.map((row) => {
      const messages = row.presentation_messages as Record<string, { code?: string }> | undefined;
      return messages?.participant?.code === "events.participant_unknown" ? { ...row, participant: null } : row;
    }) };
  }
  if (CODED_REPORTS.has(value.report_key)) value = resolvePresentation(value, timeZone);
  if (getLocale() !== "en" && ["ad.infrastructure", "security.problems"].includes(value.report_key)) {
    return { ...value, items: value.items.map((row) => localizeReportRow(value.report_key, row, timeZone)) };
  }
  if (getLocale() !== "en") return value;
  const items = ["vpn.accounts", "security.events.chains", "ad.infrastructure", "ad.computers.v6", "security.problems", "ad.users.v2", "ad.gpo.v2"].includes(value.report_key)
    ? value.items.map((row) => localizeReportRow(value.report_key, row, timeZone)) : value.items;
  const usersCoverage = value.report_key === "ad.users.v2" ? value.coverage : undefined;
  const hygiene = value.coverage?.hygiene_policy as { password_age?: number; inactivity?: number } | undefined;
  const policyParams = {
    ...(hygiene ? { password_days: hygiene.password_age ?? "", inactivity_days: hygiene.inactivity ?? "" } : {}),
    ...(usersCoverage ? { count: String(usersCoverage.unknown_accounts ?? ""), password_age: hygiene?.password_age ?? "", inactivity: hygiene?.inactivity ?? "" } : {}),
  };
  return { ...value, items: items.some((row, index) => row !== value.items[index]) ? items : value.items,
    metrics: value.metrics.map((metric) => ({ ...metric, label: reportMetadataText(value.report_key, `metrics.${metric.key}.label`, metric.label), caption: metric.caption ? reportMetadataText(value.report_key, `metrics.${metric.key}.caption`, metric.caption) : metric.caption })),
    filter_options: filterOptions(value.report_key, value.filter_options),
    branches: value.branches ? Object.fromEntries(Object.entries(value.branches).map(([key, branch]) => [key, {
      ...branch, limitations: branch.limitations.map((item) => ({ ...item, text: reportMetadataText(value.report_key, `limitations.${item.code}`, reportText(item.text), { ...policyParams, ...Object.fromEntries(Object.entries(item.params ?? {}).map(([key, val]) => [key, val ?? ""])) }) })),
    }])) : undefined,
    limitations: value.limitations.map((item) => ({ ...item, text: reportMetadataText(value.report_key, `limitations.${item.code}`, reportText(item.text), { ...policyParams, ...Object.fromEntries(Object.entries(item.params ?? {}).map(([key, val]) => [key, val ?? ""])) }) })) };
}
