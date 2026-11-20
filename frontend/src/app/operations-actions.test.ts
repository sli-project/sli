import { localeRuntime, setLocale } from "../i18n";
import { describe, expect, it, vi } from "vitest";
import type { OperationsOverview, SystemHealth } from "../api/client";
import { adContextWorkerSections, buildOperationsExport, collectionChannelPresentation, collectionHeaderPresentation, collectionProgressPresentation, evaluateOperationsReadiness, postgresOperationalState, runtimeErrorLabel, runtimeWorkerPresentation, workerNameLabel, channelNameLabel } from "./operations-actions";

it("uses a human product name for the snapshot process and retains custom process labels", () => {
  expect(workerNameLabel({ worker_name: "ad_snapshot_manifest_coordinator", label: "Canonical manifest worker", state: "active" })).toBe("Сбор снимков Active Directory");
  expect(workerNameLabel({ worker_name: "custom", label: "Custom label", state: "active" })).toBe("Custom label");
  expect(channelNameLabel("Security")).toBe("Безопасность");
  expect(channelNameLabel("System")).toBe("Система");
  expect(channelNameLabel("Custom channel")).toBe("Custom channel");
});

function operations(overrides: Partial<OperationsOverview> = {}): OperationsOverview {
  return {
    api_version: "v1",
    generated_at_utc: "2026-07-16T12:00:00Z",
    read_only: true,
    collection: { collection_enabled: true },
    workers: { status: "ok", items: [] },
    collector_health: { operations_slo: { status: "ok", label: "В норме" } },
    storage: { status: "ok" },
    postgres: { status: "ok" },
    ...overrides,
  };
}

it.each(["current", "partial", "error", "unavailable"] as const)("uses agent health over a retired blocked collector (%s)", (state) => {
  const data = operations({ collection: { collection_enabled: false, collection_block_reason: "access_denied" },
    agent_collection: { state, checked_at_utc: "2026-10-19T12:00:00Z", items: state === "error" ? [{
      id: "fixture-agent", host_id: "fixture-host", name: "fixture-agent", domains: [], state: "error", connection: "offline",
      last_seen: null, last_packet_at: null, href: "/app/agents", policy_revision: 1, applied_policy_revision: 1, modules: [],
    }] : [], active_agents: 1, current_agents: state === "current" ? 1 : 0 },
    collector_health: { operations_slo: { status: "breached" } } });
  const result = evaluateOperationsReadiness(data, { status: "ok" } as SystemHealth);
  const expected = state === "error" ? "blocked" : state === "current" ? "ready" : "warning";
  expect(result.checks[1].status).toBe(expected);
  expect(result.checks[2].status).toBe(expected);
});

it("shows unused server channels without their old failure", () => {
  expect(collectionChannelPresentation({ usage_state: "unused", last_status: "access_denied", collection_state: "error" })).toMatchObject({
    label: "Не используется", tone: "neutral",
  });
});

describe("operations actions", () => {
  it("names failed sources and does not repeat successful collection copy during a failure", () => {
    const result = collectionHeaderPresentation({ status: "failed", channels_total: 1, boundaries_reached: 1 }, [
      { server: "fixture-host", channel: "Security", collection_state: "error", last_status: "access_denied" },
    ]);
    expect(result?.state).toBe("error");
    expect(result?.detail).toContain("fixture-host · Security");
    expect(result?.detail).toContain("нет доступа к источнику");
    expect(result?.detail).toContain("время начала неизвестно");
    expect(result?.detail).not.toContain("; с");
    expect(result?.detail).not.toContain("подтверждено");
    expect(collectionHeaderPresentation({ status: "failed", channels_total: 1, boundaries_reached: 1 })?.detail).toContain("не указаны");
  });
  it("does not claim completed collection when its known boundaries are incomplete", () => {
    expect(collectionHeaderPresentation({status:"completed",channels_total:4,boundaries_reached:2,channels_in_recovery:0,items:[]})).toMatchObject({state:"partial",title:"Частичный сбор"});
  });

  it("labels success as collection only, not semantic or report completeness", () => {
    expect(collectionHeaderPresentation({status:"completed",channels_total:1,boundaries_reached:1,channels_in_recovery:0,items:[]}, [{ collection_state: "current", last_successful_collection_utc: new Date().toISOString() }])).toMatchObject({state:"current",title:"Сбор подтверждён"});
  });

  it("does not infer measured boundaries from zero channels", () => {
    expect(collectionHeaderPresentation({status:"completed",channels_total:0,boundaries_reached:0,channels_in_recovery:0,items:[]})).toMatchObject({state:"unknown"});
  });
  it("shows bounded boundaries instead of treating quiet channels as stale collection", () => {
    const progress = {
      status: "running",
      channels_total: 12,
      boundaries_reached: 8,
      channels_in_recovery: 4,
      worker_id: "collection-example-39124",
      job_id: 2,
      recovery_items: [
        { server: "DC1", channel: "Security", current_limit: 50_000 },
        { server: "DC1", channel: "DNS Server", current_limit: 35_200 },
        { server: "DC2", channel: "Security", current_limit: 50_000 },
        { server: "DC2", channel: "DNS Server", current_limit: 35_200 },
      ],
      items: [],
    };
    expect(collectionProgressPresentation(progress)).toEqual({
      value: "8 из 12 источников проверено",
      detail: "Восстановление: DC1 · Security (50 000), DC1 · DNS Server (35 200), DC2 · Security (50 000), DC2 · DNS Server (35 200)",
      tone: "warning",
    });
    expect(collectionHeaderPresentation(progress)).toEqual({
      state: "lagging",
      title: "Сбор выполняется",
      detail: "Каналов с загрузкой пропущенных данных: 4",
    });
  });

  it("keeps an old boundary separate from the current check", () => {
    expect(collectionChannelPresentation({
      server: "DC1",
      channel: "Directory Service",
      recovery_mode: false,
      adaptive_action: "exit_recovery:source_boundary_reached; 100->500; recovery=off",
      collection_label: "проверка сильно отстаёт",
      collection_severity: "high",
      last_successful_collection_utc: "2020-01-01T00:00:00Z",
    })).toMatchObject({ label: "проверка сильно отстаёт", tone: "bad" });
    expect(collectionChannelPresentation({
      server: "DC1",
      channel: "Security",
      recovery_mode: true,
      adaptive_action: "keep:completed_fast_recovery",
      collection_label: "проверка сильно отстаёт",
      collection_severity: "high",
    })).toEqual({ label: "Загружаются пропущенные данные", tone: "warning" });
  });

  it("does not make stale or missing checks green even when progress says completed", () => {
    const progress = { status: "completed", channels_total: 1, boundaries_reached: 1 };
    expect(collectionHeaderPresentation(progress, [{ collection_state: "stale", last_successful_collection_utc: "2020-01-01T00:00:00Z" }])?.state).toBe("stale");
    expect(collectionHeaderPresentation(progress)?.state).toBe("unknown");
    expect(collectionHeaderPresentation({ ...progress, channels_total: 2, boundaries_reached: 2 }, [
      { last_successful_collection_utc: new Date().toISOString() },
    ])?.state).toBe("unknown");
    expect(collectionProgressPresentation({ ...progress, check_state: "current", items: [] })?.tone).not.toBe("good");
    expect(collectionChannelPresentation({ last_status: "access_denied", adaptive_action: "exit_recovery:source_boundary_reached" }).tone).toBe("bad");
  });

  it("allows a recent successful check of a quiet log without treating its old event as an outage", () => {
    const result = collectionChannelPresentation({ server: "fixture-node", channel: "System",
      last_status: "completed", last_successful_collection_utc: new Date().toISOString(),
      last_event_time_utc: "2020-01-01T00:00:00Z", adaptive_action: "exit_recovery:source_boundary_reached" });
    expect(result.tone).toBe("good");
    expect(result.detail).toContain("Граница прочитана при проверке");
  });

  it("names the failure and both clocks without deriving outage start from the last event", () => {
    const result = collectionHeaderPresentation({ status: "failed" }, [{
      server: "fixture-node", channel: "Security", last_status: "failed", failure_reason: "windows_event_log_access_denied",
      last_successful_collection_utc: "2026-10-01T00:00:00Z", last_event_time_utc: "2020-01-01T00:00:00Z",
    }]);
    expect(result?.detail).toContain("fixture-node · Security");
    expect(result?.detail).toContain("Нет доступа к журналу событий");
    expect(result?.detail).toContain("Последняя успешная проверка");
    expect(result?.detail).toContain("Последнее событие");
    expect(result?.detail).toContain("время начала неизвестно");
    expect(result?.detail).not.toContain("; с");
  });

  it("shows the runtime block reason and only its confirmed start date", () => {
    const result = collectionHeaderPresentation({ status: "blocked", block_reason: "windows_event_log_access_denied",
      blocked_since_utc: "2026-10-01T00:00:00Z", items: [{ server: "fixture-node", channel: "Security",
        last_status: "access_denied",
        last_successful_collection_utc: "2026-09-01T00:00:00Z", last_event_time_utc: "2020-01-01T00:00:00Z" }] });
    expect(result?.state).toBe("error");
    expect(result?.detail).toContain("Нет доступа к журналу событий");
    expect(result?.detail).toContain("Блокировка подтверждена с");
    expect(result?.detail).toContain("Последнее событие");
    expect(result?.detail).not.toContain("время начала неизвестно");
  });

  it("explains the partial AD context worker by section instead of a generic warning", () => {
    expect(adContextWorkerSections({
      worker_name: "ad_context_snapshot",
      label: "Снимок Active Directory",
      state: "warning",
      details: {
        sections: {
          vpn_membership: { status: "partial", record_count: 868 },
          gpo_governance: { status: "complete", record_count: 72 },
          directory_accounts: { status: "complete", record_count: 4524 },
          privileged_membership: { status: "complete", record_count: 69 },
        },
      },
    })).toEqual({
      label: "3 из 4 штатно",
      detail: "Учётные записи AD: штатно · Привилегии AD: штатно · GPO: штатно · VPN: частично",
    });
  });

  it("does not reinterpret section details of unrelated workers", () => {
    expect(adContextWorkerSections({
      worker_name: "collection",
      label: "Сбор событий",
      state: "active",
      details: { sections: { directory_accounts: { status: "partial" } } },
    })).toBeNull();
  });

  it("distinguishes a partial collector from a failed lifecycle cycle", () => {
    expect(runtimeWorkerPresentation({
      worker_name: "collection",
      label: "Сбор событий",
      state: "warning",
      status: "partial",
      phase: "sleep",
    })).toEqual({ label: "Частичный сбор", tone: "warning" });
    expect(runtimeWorkerPresentation({
      worker_name: "storage_lifecycle",
      label: "Жизненный цикл хранения",
      state: "warning",
      status: "failed",
      phase: "sleep",
    })).toEqual({ label: "Ошибка цикла", tone: "bad" });
  });

  it("переводит известные ошибки Windows в понятное объяснение", () => {
    expect(runtimeErrorLabel("(5, 'EvtQuery', 'Отказано в доступе.')")).toBe("Нет доступа к одному из журналов событий.");
    expect(runtimeErrorLabel("EvtNext access denied")).toBe("Доступ к чтению событий был отклонён.");
    expect(runtimeErrorLabel("read timed out")).toBe("Источник не ответил за отведённое время.");
    expect(runtimeErrorLabel("неизвестная ошибка")).toBe("неизвестная ошибка");
  });

  it("treats a durable collection circuit breaker as blocked readiness", () => {
    const snapshot = operations({
      collection: {
        collection_enabled: false,
        collection_block_reason: "windows_security_context_invalid",
        collection_block: { retry_policy: "operator_recovery_required" },
      },
    });

    const result = evaluateOperationsReadiness(snapshot, { status: "ok", warnings: [] });

    expect(result.status).toBe("blocked");
    expect(result.checks.find((item) => item.label === "Контур сбора")?.status).toBe("blocked");
  });
  it("reports a fully ready runtime", () => {
    const result = evaluateOperationsReadiness(operations(), { status: "ok", warnings: [] });
    expect(result.status).toBe("ready");
    expect(result.checks).toHaveLength(4);
  });

  it("treats the protected HTTP process as ready when the external collector is active", () => {
    const result = evaluateOperationsReadiness(operations({
      collection: {
        collection_enabled: false,
        collection_block_reason: "collection_disabled_by_ADLOG_DISABLE_COLLECTION",
        operational_collection_enabled: true,
        operational_collection_block_reason: null,
        collection_execution_owner: "external_worker",
        local_runtime_guard_only: true,
      },
    }), { status: "ok", warnings: [] });

    expect(result.status).toBe("ready");
    expect(result.checks.find((item) => item.label === "Контур сбора")?.detail).toContain("разрешённым контуром");
  });

  it("does not hide a disabled collector or breached freshness", () => {
    const result = evaluateOperationsReadiness(operations({
      collection: { collection_enabled: false, collection_block_reason: "maintenance" },
      collector_health: { operations_slo: { status: "breached", label: "Отставание" } },
    }), { status: "warn", warnings: ["Диск требует внимания"] } satisfies SystemHealth);
    expect(result.status).toBe("blocked");
    expect(result.checks.map((item) => item.detail)).toContain("maintenance");
  });

  it("keeps PostgreSQL available when only optional metrics are partial", () => {
    const snapshot = operations({
      postgres: {
        status: "warn",
        available: true,
        connectivity_status: "ready",
        metrics_status: "partial",
        limitations: [{ metric: "table_statistics", error_type: "LockNotAvailable" }],
      },
    });
    const result = evaluateOperationsReadiness(snapshot, { status: "ok", warnings: [] });
    const postgres = result.checks.find((item) => item.label === "PostgreSQL");

    expect(postgresOperationalState(snapshot.postgres)).toBe("warning");
    expect(result.status).toBe("warning");
    expect(postgres?.detail).toContain("База доступна");
  });

  it("blocks readiness when PostgreSQL connectivity is unavailable", () => {
    const snapshot = operations({
      postgres: {
        status: "failed",
        available: false,
        connectivity_status: "unavailable",
        metrics_status: "unavailable",
      },
    });
    expect(postgresOperationalState(snapshot.postgres)).toBe("blocked");
    expect(evaluateOperationsReadiness(snapshot, { status: "ok", warnings: [] }).status).toBe("blocked");
  });

  it("does not call complete PostgreSQL metrics unavailable when warnings exist", () => {
    const snapshot = operations({
      postgres: {
        status: "warn",
        available: true,
        connectivity_status: "ready",
        metrics_status: "complete",
        warnings: ["Long-running PostgreSQL queries: 1"],
      },
    });
    const postgres = evaluateOperationsReadiness(snapshot, { status: "ok", warnings: [] })
      .checks.find((item) => item.label === "PostgreSQL");

    expect(postgres?.status).toBe("warning");
    expect(postgres?.detail).toBe("База доступна, есть эксплуатационные предупреждения.");
  });

  it("exports a versioned read-only snapshot", () => {
    const result = buildOperationsExport(operations(), "2026-07-16T12:30:00Z");
    expect(result.schema).toBe("ad-log-reports/operations-state/v1");
    expect(result.read_only).toBe(true);
    expect(result.operations.generated_at_utc).toBe("2026-07-16T12:00:00Z");
  });
});


describe("ransomware policy wait", () => {
  it("shows a precise non-healthy state without hiding other worker failures", () => {
    const worker = { worker_name: "semantic", label: "Semantic", state: "warning", status: "failed", phase: "production_sleep",
      details: { last_result: { failed: 1, detections: { file_ransom_status: { code: "source_policy_waiting", sources: 1 } } } } };
    expect(runtimeWorkerPresentation(worker)).toEqual({ label: "Проверка шифровальщика ждёт политики источника", tone: "warning" });
    expect(runtimeWorkerPresentation({ ...worker, state: "stale" }).tone).toBe("bad");
    expect(runtimeWorkerPresentation({ ...worker, details: { last_result: { ...worker.details.last_result, failed: 2 } } }).label).toBe("Ошибка цикла");
  });
});

it("renders source-policy wait in English without leaking the backend message", () => {
  vi.stubGlobal("document", { documentElement: { lang: "ru" } });
  const reload = vi.spyOn(localeRuntime, "reload").mockImplementation(() => {});
  try {
    setLocale("en");
    const result = runtimeWorkerPresentation({ worker_name: "semantic", label: "Semantic", state: "warning", status: "failed", phase: "production_sleep",
      details: { last_result: { failed: 1, detections: { file_ransom_status: { code: "source_policy_waiting", sources: 1, message: "private raw details" } } } } });
    expect(result).toEqual({ label: "Ransomware check is waiting for the source policy", tone: "warning" });
  } finally {
    setLocale("ru");
    reload.mockRestore();
    vi.unstubAllGlobals();
  }
});
