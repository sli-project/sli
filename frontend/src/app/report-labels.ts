import { t } from "../i18n";
import type { V4Report } from "../api/client";

const objectTypeLabels = (): Record<string, string> => ({
  watch_entry: t("watch.title"),
  ad_user: t("access.labels.ad_account"), ad_computer: t("access.labels.ad_computer"), auth_session: t("access.labels.logon_session"),
  asset: t("access.labels.asset"), ip_address: t("access.labels.ip_address"), group: t("access.labels.group"), gpo: t("access.labels.group_policy"),
  event_provider: t("access.labels.event_provider"), log_source: t("access.labels.log_source"),
  account: t("access.labels.account"), computer: t("access.labels.computer"), server: t("access.labels.server"), entity: t("access.labels.object"),
  ad_group: t("entities.types.ad_group"), device: t("entities.types.device"), device_identity: t("entities.types.device_identity"),
  domain: t("entities.types.domain"), domain_controller: t("entities.types.domain_controller"),
  domain_trust: t("entities.types.domain_trust"), replication_link: t("entities.types.replication_link"), password_policy: t("entities.types.password_policy"),
  host: t("access.labels.computer"), ip: t("access.labels.ip_address"),
});

export function objectTypeLabel(value: string) { return objectTypeLabels()[value] ?? value.replaceAll("_", " "); }
export function roleLabel(value: string) {
  return ({ viewer: t("access.labels.viewer"), operator: t("access.labels.operator"), admin: t("access.labels.administrator") } as Record<string, string>)[value] ?? value;
}
export function accessActionLabel(value: string) {
  return ({ view: t("access.labels.view"), export: t("access.labels.export"), create_task: t("access.labels.create_task"), start_case: t("access.labels.start_investigation"), configure_channel: t("access.labels.configure_channel"), manage_decoy: t("decoys.manage"), manage_watch: t("watch.manage") } as Record<string, string>)[value] ?? value;
}
export function fieldCategoryLabel(value: string) {
  return ({ identity_basic: t("access.labels.basic_identity"), security: t("access.labels.security_information"), technical: t("access.labels.technical_fields"), privilege: t("access.labels.privileges"), contact: t("access.labels.contact_details"), hr: t("access.labels.hr_attributes"), raw_evidence: t("access.labels.raw_evidence"), sensitive: t("access.labels.sensitive_fields") } as Record<string, string>)[value] ?? value;
}
export function scopeKindLabel(value: string) {
  return ({ all: t("access.labels.all_permitted_rows"), server: t("access.labels.servers"), domain: t("access.labels.domains"), channel: t("access.labels.event_channels") } as Record<string, string>)[value] ?? value;
}

export function auditActionLabel(value: string): string {
  const keys = {
    initial_owner_claimed: "access.audit.actions.initial_owner_claimed",
    "auth.initial_owner.claimed": "access.audit.actions.initial_owner_claimed",
    report_assignment_created: "access.audit.actions.report_assignment_created",
    package_assignment_created: "access.audit.actions.package_assignment_created",
    platform_setting_update: "access.audit.actions.platform_setting_update",
    notification_channel_update: "access.audit.actions.notification_channel_update",
    notification_subscription_update: "access.audit.actions.notification_subscription_update",
    notification_schedule_update: "access.audit.actions.notification_schedule_update",
    notification_test_enqueue: "access.audit.actions.notification_test_enqueue",
    decoy_label_update: "decoys.changed",
    watch_entry_update: "watch.changed",
    vpn_session_evidence_grant_created: "access.audit.actions.vpn_session_evidence_grant_created",
    report_access_requested: "access.audit.actions.report_access_requested",
    report_access_request_approved: "access.audit.actions.report_access_request_approved",
    report_access_request_rejected: "access.audit.actions.report_access_request_rejected",
  } as const;
  return Object.hasOwn(keys, value) ? t(keys[value as keyof typeof keys]) : value;
}

export function auditReasonLabel(value: string | null | undefined): string {
  if (!value?.trim()) return t("access.audit.noReason");
  return value === "Access allowed by assignment and capability policy"
    ? t("access.audit.assignmentBasis") : value;
}

export function reportSensitivityLabel(value: string): string {
  return ({ low: t("studio.sensitivity.low"), restricted: t("studio.sensitivity.restricted"), confidential: t("studio.sensitivity.confidential") } as Record<string, string>)[value] ?? value;
}
export const REPORT_WORKSPACE_PATHS: Record<string, string> = {
  "security.queue": "/report/security.problems",
  "ad.state": "/report/ad.infrastructure",
  "ad.users": "/report/ad.users.v2",
  "ad.users.v2": "/report/ad.users.v2",
  "ad.computers": "/report/ad.computers.v6",
  "ad.computers.v5": "/report/ad.computers.v6",
  "ad.computers.v6": "/report/ad.computers.v6",
  "ad.computer-logons": "/report/ad.computer-logons",
  "ad.gpo.v2": "/report/ad.gpo.v2",
  "ad.privileged": "/reports",
  "ad.gpo.review": "/report/ad.gpo.v2",
  "vpn.audit": "/report/vpn.accounts",
  "vpn.connections": "/report/vpn.connections",
  "security.events.chains": "/report/security.events.chains",
};

export const AD_STATE_LEGACY_ROUTE = "/reports/ad.state";

export function reportTargetPath(report: Pick<V4Report, "report_key" | "target_path">): string {
  return REPORT_WORKSPACE_PATHS[report.report_key] ?? report.target_path;
}

export function reportSupportsPreference(report: Pick<V4Report, "preference_supported">): boolean {
  return report.preference_supported !== false;
}
