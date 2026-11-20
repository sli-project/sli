import { describe, expect, it, vi } from "vitest";
import { createAssignmentWithVerification, createInvestigationWithVerification, createPackageAssignmentWithVerification, publishReportWithVerification } from "./v4-mutation-workflows";

const assignment = {
  id: 41, subject_type: "user", subject_id: 7, report_key: "security.events", effect: "allow",
  source_type: "direct", scope_json: { kind: "all" }, field_categories: [], allowed_actions: ["view"],
  business_reason: "Рабочая функция", created_at: "2026-07-20T10:00:00Z",
};

const packageAssignment = {
  id: 52, subject_type: "user", subject_id: 7, package_key: "security_analyst", package_name: "Аналитик ИБ",
  effect: "allow", source_type: "direct", business_reason: "Рабочая функция", created_at: "2026-07-20T10:00:00Z",
};

const definition = {
  report_key: "security.events", version: 3, name: "События", owner_name: "ИБ", purpose: "Анализ",
  sensitivity: "restricted", status: "published", dataset_key: "events.v2", dataset_version: 2,
  published_at: "2026-07-20T10:00:00Z", created_at: "2026-07-20T10:00:00Z",
};

const effectiveAccess = {
  api_version: "v4" as const, evaluated_at_utc: definition.created_at, preview: true,
  subject: { type: "session", id: 7, username: "user", coarse_role: "viewer" }, groups: [], packages: [],
  package_explain: [], capabilities: ["reports.catalog"], capability_explain: {},
  reports: [{ report_key: "security.events", version: 3, name: "События", owner: "ИБ", purpose: "Анализ", dataset_key: "events.v2", dataset_version: 2, sensitivity: "restricted", status: "published", target_path: "/reports/security.events", allowed: true, explanation: "Доступ разрешён", missing_capabilities: [], field_categories: ["security"], allowed_actions: ["view"], scopes: [{ kind: "all" }], sources: [{ source_type: "direct", source: "user:7" }], pinned: false }],
  allowed_report_count: 1, navigation: [], explicit_denies: { packages: [], capabilities: [], reports: [] },
};

describe("проверяемые изменяющие операции SLI v4", () => {
  it("подтверждает назначение повторным чтением реестра и журнала", async () => {
    const gateway = {
      v4CreateReportAssignment: vi.fn().mockResolvedValue({ item: assignment }),
      v4AccessSubjects: vi.fn().mockResolvedValue({ users: [], groups: [], packages: [], assignments: [assignment], package_assignments: [] }),
      v4AccessAudit: vi.fn().mockResolvedValue({ items: [{ id: 8, actor_type: "session", action: "report_assignment_created", subject_type: "user", subject_id: 7, target_key: "security.events", outcome: "ok", details_json: { assignment_id: 41 }, created_at: assignment.created_at }], limit: 100 }),
      v4Access: vi.fn().mockResolvedValue(effectiveAccess),
    };
    await expect(createAssignmentWithVerification({}, gateway)).resolves.toMatchObject({ item: assignment, registryVerified: true, auditVerified: true, effectiveAccess: { allowed: true } });
  });

  it("не сообщает об успехе назначения без записи журнала", async () => {
    const gateway = {
      v4CreateReportAssignment: vi.fn().mockResolvedValue({ item: assignment }),
      v4AccessSubjects: vi.fn().mockResolvedValue({ users: [], groups: [], packages: [], assignments: [assignment], package_assignments: [] }),
      v4AccessAudit: vi.fn().mockResolvedValue({ items: [], limit: 100 }),
      v4Access: vi.fn().mockResolvedValue(effectiveAccess),
    };
    await expect(createAssignmentWithVerification({}, gateway)).rejects.toThrow("журнала действий");
  });

  it("отличает сохранённое назначение от реально открывшегося отчёта", async () => {
    const gatedAccess = { ...effectiveAccess, reports: effectiveAccess.reports.map((report) => ({ ...report, allowed: false, explanation: "Не хватает возможностей", missing_capabilities: ["field.security"] })) };
    const gateway = {
      v4CreateReportAssignment: vi.fn().mockResolvedValue({ item: assignment }),
      v4AccessSubjects: vi.fn().mockResolvedValue({ users: [], groups: [], packages: [], assignments: [assignment], package_assignments: [] }),
      v4AccessAudit: vi.fn().mockResolvedValue({ items: [{ id: 8, actor_type: "session", action: "report_assignment_created", subject_type: "user", subject_id: 7, target_key: "security.events", outcome: "ok", details_json: { assignment_id: 41 }, created_at: assignment.created_at }], limit: 100 }),
      v4Access: vi.fn().mockResolvedValue(gatedAccess),
    };
    await expect(createAssignmentWithVerification({}, gateway)).resolves.toMatchObject({ effectiveAccess: { allowed: false, missingCapabilities: ["field.security"] } });
  });

  it("подтверждает пакет повторным чтением реестра, журнала и эффективного доступа", async () => {
    const packageAccess = { ...effectiveAccess, packages: [{ key: "security_analyst", name: "Аналитик ИБ" }] };
    const gateway = {
      v4CreatePackageAssignment: vi.fn().mockResolvedValue({ item: packageAssignment }),
      v4AccessSubjects: vi.fn().mockResolvedValue({ users: [], groups: [], packages: [], assignments: [], package_assignments: [packageAssignment] }),
      v4AccessAudit: vi.fn().mockResolvedValue({ items: [{ id: 11, actor_type: "session", action: "package_assignment_created", subject_type: "user", subject_id: 7, target_key: "security_analyst", outcome: "ok", details_json: { assignment_id: 52 }, created_at: packageAssignment.created_at }], limit: 100 }),
      v4Access: vi.fn().mockResolvedValue(packageAccess),
    };
    await expect(createPackageAssignmentWithVerification({}, gateway)).resolves.toMatchObject({ item: packageAssignment, registryVerified: true, auditVerified: true, effectiveAccess: { assigned: true } });
  });

  it("не сообщает об успехе пакета без эффективного назначения", async () => {
    const gateway = {
      v4CreatePackageAssignment: vi.fn().mockResolvedValue({ item: packageAssignment }),
      v4AccessSubjects: vi.fn().mockResolvedValue({ users: [], groups: [], packages: [], assignments: [], package_assignments: [packageAssignment] }),
      v4AccessAudit: vi.fn().mockResolvedValue({ items: [{ id: 11, actor_type: "session", action: "package_assignment_created", subject_type: "user", subject_id: 7, target_key: "security_analyst", outcome: "ok", details_json: { assignment_id: 52 }, created_at: packageAssignment.created_at }], limit: 100 }),
      v4Access: vi.fn().mockResolvedValue(effectiveAccess),
    };
    await expect(createPackageAssignmentWithVerification({}, gateway)).rejects.toThrow("эффективном доступе");
  });

  it("подтверждает опубликованную версию повторным чтением реестра и журнала", async () => {
    const gateway = {
      v4CreateReportAssignment: vi.fn(), v4AccessSubjects: vi.fn(),
      v4PublishReport: vi.fn().mockResolvedValue({ item: definition }),
      v4ReportDefinitions: vi.fn().mockResolvedValue({ api_version: "v4", items: [definition], limit: 200, total_count: "not_calculated" }),
      v4AccessAudit: vi.fn().mockResolvedValue({ items: [{ id: 9, actor_type: "session", action: "report_published", target_key: "security.events", outcome: "ok", details_json: { version: 3 }, created_at: definition.created_at }], limit: 100 }),
    };
    await expect(publishReportWithVerification({}, gateway)).resolves.toMatchObject({ item: definition, registryVerified: true, auditVerified: true });
  });

  it("не сообщает об успехе версии без повторного чтения реестра", async () => {
    const gateway = {
      v4CreateReportAssignment: vi.fn(), v4AccessSubjects: vi.fn(),
      v4PublishReport: vi.fn().mockResolvedValue({ item: definition }),
      v4ReportDefinitions: vi.fn().mockResolvedValue({ api_version: "v4", items: [], limit: 200, total_count: "not_calculated" }),
      v4AccessAudit: vi.fn().mockResolvedValue({ items: [], limit: 100 }),
    };
    await expect(publishReportWithVerification({}, gateway)).rejects.toThrow("повторном чтении реестра");
  });

  it("подтверждает новое расследование повторным чтением дела и его журнала", async () => {
    const created = { id: 17, title: "Проверка события", status: "new", created_by: "analyst", created_at: definition.created_at, updated_at: definition.created_at, events: [], notes: [], audit: [] };
    const readBack = { ...created, audit: [{ id: 1, action: "created", actor: "analyst", created_at: definition.created_at }] };
    const gateway = {
      createInvestigation: vi.fn().mockResolvedValue(created),
      investigationCase: vi.fn().mockResolvedValue(readBack),
    };
    await expect(createInvestigationWithVerification({ title: created.title }, gateway)).resolves.toMatchObject({ item: readBack, registryVerified: true, auditVerified: true });
  });

  it("не сообщает об успехе расследования без записи журнала", async () => {
    const created = { id: 18, title: "Проверка", status: "new", created_by: "analyst", created_at: definition.created_at, updated_at: definition.created_at, events: [], notes: [], audit: [] };
    const gateway = { createInvestigation: vi.fn().mockResolvedValue(created), investigationCase: vi.fn().mockResolvedValue(created) };
    await expect(createInvestigationWithVerification({ title: created.title }, gateway)).rejects.toThrow("журнала действий");
  });
});
