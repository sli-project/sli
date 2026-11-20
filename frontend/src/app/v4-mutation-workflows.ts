import { api, type InvestigationCase, type V4AccessAuditItem, type V4PackageAssignment, type V4ReportAssignment, type V4ReportDefinition } from "../api/client";

type AssignmentGateway = Pick<typeof api, "v4CreateReportAssignment" | "v4AccessSubjects" | "v4AccessAudit" | "v4Access">;
type PackageAssignmentGateway = Pick<typeof api, "v4CreatePackageAssignment" | "v4AccessSubjects" | "v4AccessAudit" | "v4Access">;
type ReportGateway = Pick<typeof api, "v4PublishReport" | "v4ReportDefinitions" | "v4AccessAudit">;
type InvestigationGateway = Pick<typeof api, "createInvestigation" | "investigationCase">;

export type VerifiedMutation<T> = {
  item: T;
  registryVerified: true;
  auditVerified: true;
};

export type VerifiedAssignment = VerifiedMutation<V4ReportAssignment> & {
  effectiveAccess: { allowed: boolean; explanation: string; missingCapabilities: string[] } | null;
};

export type VerifiedPackageAssignment = VerifiedMutation<V4PackageAssignment> & {
  effectiveAccess: { assigned: boolean; denied: boolean };
};

function numberValue(value: unknown): number | undefined {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function auditMatchesAssignment(audit: V4AccessAuditItem, assignment: V4ReportAssignment): boolean {
  return audit.action === "report_assignment_created"
    && audit.outcome === "ok"
    && audit.subject_type === assignment.subject_type
    && Number(audit.subject_id) === assignment.subject_id
    && audit.target_key === assignment.report_key
    && numberValue(audit.details_json?.assignment_id) === assignment.id;
}

export async function createAssignmentWithVerification(
  body: Record<string, unknown>,
  gateway: AssignmentGateway = api,
): Promise<VerifiedAssignment> {
  const created = await gateway.v4CreateReportAssignment(body);
  const item = created.item as unknown as V4ReportAssignment;
  if (!Number.isFinite(Number(item.id))) throw new Error("Сервер не вернул идентификатор назначения.");
  const [subjects, audit, effective] = await Promise.all([
    gateway.v4AccessSubjects(), gateway.v4AccessAudit(),
    item.subject_type === "user" ? gateway.v4Access(Number(item.subject_id)) : Promise.resolve(null),
  ]);
  const registryItem = subjects.assignments.find((candidate) => candidate.id === Number(item.id));
  if (!registryItem) throw new Error("Назначение записано, но не найдено при повторном чтении реестра.");
  if (!audit.items.some((entry) => auditMatchesAssignment(entry, registryItem))) {
    throw new Error("Назначение записано, но подтверждающая запись журнала действий не найдена.");
  }
  const report = effective?.reports.find((candidate) => candidate.report_key === registryItem.report_key);
  if (effective && !report) throw new Error("Назначение записано, но отчёт отсутствует при проверке эффективного доступа.");
  return {
    item: registryItem, registryVerified: true, auditVerified: true,
    effectiveAccess: report ? { allowed: report.allowed, explanation: report.explanation, missingCapabilities: report.missing_capabilities } : null,
  };
}

function auditMatchesPackageAssignment(audit: V4AccessAuditItem, assignment: V4PackageAssignment): boolean {
  return audit.action === "package_assignment_created"
    && audit.outcome === "ok"
    && audit.subject_type === assignment.subject_type
    && Number(audit.subject_id) === assignment.subject_id
    && audit.target_key === assignment.package_key
    && numberValue(audit.details_json?.assignment_id) === assignment.id;
}

export async function createPackageAssignmentWithVerification(
  body: Record<string, unknown>,
  gateway: PackageAssignmentGateway = api,
): Promise<VerifiedPackageAssignment> {
  const created = await gateway.v4CreatePackageAssignment(body);
  const item = created.item as unknown as V4PackageAssignment;
  if (!Number.isFinite(Number(item.id)) || !item.package_key) throw new Error("Сервер не вернул идентификатор назначения пакета.");
  const [subjects, audit, effective] = await Promise.all([
    gateway.v4AccessSubjects(), gateway.v4AccessAudit(),
    item.subject_type === "user" ? gateway.v4Access(Number(item.subject_id)) : Promise.resolve(null),
  ]);
  const registryItem = (subjects.package_assignments ?? []).find((candidate) => candidate.id === Number(item.id));
  if (!registryItem) throw new Error("Назначение пакета записано, но не найдено при повторном чтении реестра.");
  if (!audit.items.some((entry) => auditMatchesPackageAssignment(entry, registryItem))) {
    throw new Error("Назначение пакета записано, но подтверждающая запись журнала действий не найдена.");
  }
  const assigned = Boolean(effective?.packages.some((candidate) => candidate.key === registryItem.package_key));
  const denied = Boolean(effective?.explicit_denies.packages.includes(registryItem.package_key));
  if (effective && registryItem.effect === "allow" && !assigned) throw new Error("Пакет записан, но отсутствует в эффективном доступе пользователя.");
  if (effective && registryItem.effect === "deny" && !denied) throw new Error("Запрет пакета записан, но отсутствует в эффективном доступе пользователя.");
  return { item: registryItem, registryVerified: true, auditVerified: true, effectiveAccess: { assigned, denied } };
}

function auditMatchesReport(audit: V4AccessAuditItem, definition: V4ReportDefinition): boolean {
  const expectedAction = definition.status === "published" ? "report_published" : "report_draft_created";
  return audit.action === expectedAction
    && audit.outcome === "ok"
    && audit.target_key === definition.report_key
    && numberValue(audit.details_json?.version) === definition.version;
}

export async function publishReportWithVerification(
  body: Record<string, unknown>,
  gateway: ReportGateway = api,
): Promise<VerifiedMutation<V4ReportDefinition>> {
  const created = await gateway.v4PublishReport(body);
  const reportKey = String(created.item.report_key ?? "");
  const version = numberValue(created.item.version);
  if (!reportKey || version === undefined) throw new Error("Сервер не вернул ключ и версию отчёта.");
  const [definitions, audit] = await Promise.all([gateway.v4ReportDefinitions(), gateway.v4AccessAudit()]);
  const registryItem = definitions.items.find((candidate) => candidate.report_key === reportKey && candidate.version === version);
  if (!registryItem) throw new Error("Версия отчёта записана, но не найдена при повторном чтении реестра.");
  if (!audit.items.some((entry) => auditMatchesReport(entry, registryItem))) {
    throw new Error("Версия отчёта записана, но подтверждающая запись журнала действий не найдена.");
  }
  return { item: registryItem, registryVerified: true, auditVerified: true };
}

type StudioGateway = Pick<typeof api, "v4PublishReport" | "v4ReportDefinitionDetail">;

/**
 * Сохранение версии из «Студии отчётов». Подтверждается повторным чтением карточки отчёта (нужны только
 * возможности дизайна и публикации), а не журналом доступа, который требует отдельного права `access.manage`.
 */
export async function saveReportVersionWithVerification(
  body: Record<string, unknown>,
  gateway: StudioGateway = api,
): Promise<{ reportKey: string; version: number; status: string }> {
  const created = await gateway.v4PublishReport(body);
  const reportKey = String(created.item.report_key ?? "");
  const version = numberValue(created.item.version);
  if (!reportKey || version === undefined) throw new Error("Сервер не вернул ключ и версию отчёта.");
  const detail = await gateway.v4ReportDefinitionDetail(reportKey);
  const saved = detail.versions.find((candidate) => candidate.version === version);
  if (!saved) throw new Error("Версия отчёта записана, но не найдена при повторном чтении.");
  return { reportKey, version, status: saved.status };
}

export async function createInvestigationWithVerification(
  body: { title: string; owner?: string | null; event_db_id?: number },
  gateway: InvestigationGateway = api,
): Promise<VerifiedMutation<InvestigationCase>> {
  const created = await gateway.createInvestigation(body);
  if (!Number.isFinite(Number(created.id))) throw new Error("Сервер не вернул идентификатор расследования.");
  const registryItem = await gateway.investigationCase(Number(created.id));
  if (registryItem.id !== Number(created.id) || registryItem.title !== created.title) {
    throw new Error("Расследование записано, но не совпало при повторном чтении.");
  }
  if (!registryItem.audit.some((entry) => entry.action === "created")) {
    throw new Error("Расследование записано, но подтверждающая запись журнала действий не найдена.");
  }
  return { item: registryItem, registryVerified: true, auditVerified: true };
}
