// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { api, type HomeSummary, type HomeSummaryV2 } from "./client";
import { localeRuntime, setLocale, t } from "../i18n";

describe("home summary API", () => {
  afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  it.each(["ru", "en"] as const)("reads v2 without changing v1 and translates stable message codes in %s", async (locale) => {
    vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
    setLocale(locale);
    const freshness: HomeSummary["freshness"][number] = {
      key: "ad.infrastructure", title: "Synthetic report", href: "/app/report/ad.infrastructure?domain=7",
      state: "partial", observed_at_utc: null, limitation: "Synthetic source is incomplete.",
      event_at_utc: "2026-09-01T00:00:00Z", snapshot_at_utc: "2026-09-02T00:00:00Z",
      published_at_utc: "2026-10-07T00:00:00Z",
      state_details: { reason: "coverage_incomplete", source_issues: [
        { source: "synthetic-source", reason: "source_failed", since_utc: null },
      ] },
    };
    const summary: HomeSummaryV2 = {
      contract_id: "sli.home-summary.v2", context: { scope: "domain", domain_id: 7, time_zone: "UTC", period: { preset: "current", kind: "snapshot", as_of_utc: "2026-10-07T00:00:00Z" } },
      generated_at_utc: "2026-10-07T00:00:00Z", freshness: [freshness], reports: [], pinned: [], deviations: [],
      readers: [{ ...freshness, message_code: "home.state.partial", period_kind: "snapshot",
        scope: { mode: "domain", domain_ids: [7] } }],
      observation_health: { state: "partial", message_code: "home.observation.partial" },
      problems_found: { state: "partial", count: 3, message_code: "home.problems.known", href: "/app/report/security.problems?domain=7&population=attention" },
      action_queue: { state: "partial", has_more: true, items: [{
        id: "problem:123", problem_id: 123, kind: "problem", priority_group: 0, severity: "high", needs_decision: true,
        repeat_count: 2, observed_at_utc: "2026-10-01T00:00:00Z", title: "Synthetic wording", title_code: "security.problems.presentation.audit_title",
        what_code: "security.problems.presentation.audit_what", why_code: "security.problems.presentation.audit_why", next_step_code: "security.problems.presentation.audit_next",
        object: "synthetic-object", message_code: "home.attention.problem", href: "/app/report/security.problems?domain=7&id=123",
      }, {
        id: "problem:124", problem_id: 124, kind: "problem", priority_group: 2, severity: "low", needs_decision: true,
        repeat_count: 0, observed_at_utc: null, title: "Synthetic source text", what: "Synthetic source observation",
        why: "Synthetic source reason", next_step: "Synthetic source action", message_code: "home.attention.problem", href: "/app/report/security.problems?id=124",
      }] },
    };
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => summary });
    vi.stubGlobal("fetch", fetchMock);
    const params = new URLSearchParams({ scope: "domain", domain: "7", tz: "UTC" });
    const result = await api.homeSummaryV2(params);
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/home/summary?scope=domain&domain=7&tz=UTC&contract=v2");
    expect(fetchMock.mock.calls[0][1].headers["Accept-Language"]).toBe(locale);
    expect(params.has("contract")).toBe(false);
    expect(result.context).toEqual(summary.context);
    expect(result.generated_at_utc).toBe(summary.generated_at_utc);
    const localizedFreshness = { ...freshness,
      title: locale === "en" ? t("reports.v2.ad.infrastructure.title") : freshness.title };
    expect(result.freshness[0]).toEqual(localizedFreshness);
    expect(result.readers[0]).toEqual({ ...summary.readers[0], ...localizedFreshness });
    expect(summary.freshness[0].title).toBe("Synthetic report");
    expect(result.observation_health.text).toBe(t("home.observation.partial"));
    expect(result.problems_found.text).toBe(t("home.problems.known", { count: 3 }));
    expect(result.action_queue.items[0]).toMatchObject({ title: t("security.problems.presentation.audit_title"), object: "synthetic-object",
      what: t("security.problems.presentation.audit_what"), why: t("security.problems.presentation.audit_why"), next_step: t("security.problems.presentation.audit_next"),
      href: summary.action_queue.items[0].href, observed_at_utc: summary.action_queue.items[0].observed_at_utc });
    expect(result.action_queue.items[1].title).toBe("Synthetic source text");
    expect(summary.action_queue.items[0].title).toBe("Synthetic wording");
  });

  it.each(["ru", "en"] as const)("preserves the summary contract and localizes report links in %s", async (locale) => {
    vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
    setLocale(locale);
    const report = { key: "vpn.connections", title: "Synthetic report", href: "/app/vpn-connections" };
    const summary: HomeSummary = {
      contract_id: "sli.home-summary.v1",
      freshness: [{ ...report, state: "empty", observed_at_utc: null, limitation: null,
        event_at_utc: "2026-10-01T00:00:00Z", snapshot_at_utc: "2026-10-02T00:00:00Z",
        published_at_utc: "2026-10-07T00:00:00Z",
        state_details: { reason: "coverage_incomplete", source_issues: [{ source: "synthetic-source", reason: "source_failed", since_utc: null }] },
      }],
      deviations: [], action_queue: { state: "empty", has_more: false, items: [] },
      reports: [report], pinned: [report],
    };
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => summary });
    vi.stubGlobal("fetch", fetchMock);

    const result = await api.homeSummary();

    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/home/summary");
    expect(result.contract_id).toBe(summary.contract_id);
    expect(result.action_queue).toEqual(summary.action_queue);
    expect(result.freshness[0]).toMatchObject({ ...summary.freshness[0],
      title: locale === "en" ? t("reports.v2.vpn.connections.title") : report.title });
    for (const link of [...result.reports, ...result.pinned, ...result.freshness]) {
      expect(link).toMatchObject({ ...report, title: locale === "en" ? t("reports.v2.vpn.connections.title") : report.title });
    }
    expect(summary.reports[0].title).toBe("Synthetic report");
  });
});

it("accepts a successful operations response after more than twenty seconds", async () => {
  vi.useFakeTimers();
  const body = { workers: { status: "ok", items: [] } };
  vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>((resolve) => {
    setTimeout(() => resolve(new Response(JSON.stringify(body), { status: 200 })), 25_000);
  })));
  try {
    const pending = api.operationsWorkers();
    await vi.advanceTimersByTimeAsync(25_000);
    expect(await pending).toEqual(body);
  } finally { vi.useRealTimers(); vi.unstubAllGlobals(); }
});

describe("plugin state API", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("reads plugin state and sends only the desired flag and expected revision", async () => {
    const item = { plugin_id: "sli.remote-access", package_version: "0.1.0", installed: true, configured: true,
      enabled: true, receiving_data: false, component_runtime: "running", queue_state: "drained", revision: 4, last_data_at_utc: null };
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ item }) });
    vi.stubGlobal("fetch", fetchMock);
    await api.plugins();
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/plugins");
    await api.setPluginEnabled(item, false);
    const [url, options] = fetchMock.mock.calls[1];
    expect(url).toBe("/api/v1/plugins/sli.remote-access");
    expect(options).toMatchObject({ method: "POST", credentials: "same-origin" });
    expect(JSON.parse(options.body)).toEqual({ enabled: false, expected_revision: 4 });
  });
});

describe("semantic control API", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("preserves semantic control reads and version-scoped policy admission", async () => {
    const controls = { policies: [], suppressions: [], audit: [], limit: 200 };
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => controls });
    vi.stubGlobal("fetch", fetchMock);
    expect(await api.semanticControls()).toEqual(controls);
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/platform-settings/semantic-control");
    const change = { action: "policy_admission" as const, policy_id: "test-policy", policy_version: 2, enabled: true, reason: "Test admission" };
    await api.updateSemanticControl(change);
    const [url, options] = fetchMock.mock.calls[1];
    expect(url).toBe("/api/v1/platform-settings/semantic-control");
    expect(options).toMatchObject({ method: "POST", credentials: "same-origin" });
    expect(JSON.parse(options.body)).toEqual(change);
  });
});

describe("backup settings API", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("reads and saves the whole settings object with its revision", async () => {
    const initial = { enabled: true, path: "/mnt/backup/sli", revision: "backup-1", storage_status: "unavailable" };
    const saved = { ...initial, enabled: false, revision: "backup-2" };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce({ ok: true, json: async () => initial })
      .mockResolvedValueOnce({ ok: true, json: async () => saved });
    vi.stubGlobal("fetch", fetchMock);

    const signal = new AbortController().signal;
    expect(await api.backupSettings(signal)).toEqual(initial);
    expect(fetchMock.mock.calls[0]).toMatchObject(["/api/v1/admin/backup-settings", { credentials: "same-origin", signal }]);

    const update = { enabled: false, path: initial.path, revision: initial.revision };
    expect(await api.updateBackupSettings(update)).toEqual(saved);
    const [url, options] = fetchMock.mock.calls[1];
    expect(url).toBe("/api/v1/admin/backup-settings");
    expect(options).toMatchObject({ method: "PUT", credentials: "same-origin" });
    expect(JSON.parse(options.body)).toEqual(update);
  });
});

describe("finding risk acceptance API", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("uses the finding route and never supplies an author", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ status: "ok" }) });
    vi.stubGlobal("fetch", fetchMock);
    await api.riskResponsibles();
    expect(fetchMock.mock.calls[0][0]).toBe("/api/findings/risk-responsibles");
    const decision = { action: "create" as const, reason: "Fixture decision", responsible_user_id: 12, expires_at: "2026-10-08T00:00:00Z" };
    await api.changeFindingRisk(7, decision);
    expect(fetchMock.mock.calls[1][0]).toBe("/api/findings/7/risk-acceptance");
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual(decision);
    await api.changeFindingRisk(7, { action: "revoke", id: 31 });
    expect(JSON.parse(fetchMock.mock.calls[2][1].body)).toEqual({ action: "revoke", id: 31 });
    await api.findingRiskAudit(7, 31);
    expect(fetchMock.mock.calls[3][0]).toBe("/api/findings/7/risk-audit?before=31");
  });
});

describe("eventsBatch", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("hydrates up to 100 exact evidence IDs with one HTTP request", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ api_version: "v1", items: [], requested_event_db_ids: [], missing_event_db_ids: [], limit: 100 }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await api.eventsBatch(Array.from({ length: 105 }, (_, index) => index + 1));

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, options] = fetchMock.mock.calls[0];
    const parsed = new URL(String(url), "https://host20.example.invalid");
    expect(parsed.pathname).toBe("/api/v1/events/batch");
    expect(parsed.searchParams.get("event_db_id")?.split(",")).toHaveLength(100);
    expect(options).toMatchObject({ credentials: "same-origin" });
    expect(options.headers).toMatchObject({ "Accept-Language": "ru" });
  });

  it("checks a retained record without rounding its ID or requiring it to exist", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ items: [] }) });
    vi.stubGlobal("fetch", fetchMock);

    await expect(api.eventAvailable("9007199254740993")).resolves.toBe(false);
    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/events/batch?event_db_id=9007199254740993");
  });
});

describe("v4ReportExportUrl", () => {
  it("encodes the assigned report key into the controlled export endpoint", () => {
    expect(api.v4ReportExportUrl("events/../../admin")).toBe(
      "/api/v1/reports/events%2F..%2F..%2Fadmin/export.csv",
    );
  });

  it("keeps the visible filters but removes pagination from export", () => {
    const filters = new URLSearchParams({ q: "4624", server: "DC1", cursor: "next", limit: "50" });
    expect(api.v4ReportExportUrl("events.explorer", filters)).toBe(
      "/api/v1/reports/events.explorer/export.csv?q=4624&server=DC1",
    );
  });
});

describe("vpnAuthorizationTimeline", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("uses the bounded NPS authorization timeline endpoint and its explicit window", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ state: "available", items: [] }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await api.vpnAuthorizationTimeline(7, "2026-08-14T00:00:00Z", "2026-08-15T00:00:00Z", "Asia/Novosibirsk");

    const [url] = fetchMock.mock.calls[0];
    const parsed = new URL(String(url), "https://host20.example.invalid");
    expect(parsed.pathname).toBe("/api/v1/reports/vpn.audit/authorizations");
    expect(parsed.searchParams).toEqual(new URLSearchParams({
      domain_id: "7",
      time_from: "2026-08-14T00:00:00Z",
      time_to: "2026-08-15T00:00:00Z",
      timezone: "Asia/Novosibirsk",
    }));
  });
});

describe("vpnWindowsAuthentication", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("discovers only server-approved Windows authentication sources", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ state: "available", items: [] }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await api.vpnWindowsAuthenticationSources();

    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/reports/vpn.audit/windows-authentication-sources");
  });

  it("uses the bounded Windows authentication endpoint and preserves its explicit period", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ state: "available", items: [] }),
    });
    vi.stubGlobal("fetch", fetchMock);

    await api.vpnWindowsAuthentication(7, "2026-08-14T00:00", "2026-08-15T00:00", "Asia/Novosibirsk", 100);

    const [url] = fetchMock.mock.calls[0];
    const parsed = new URL(String(url), "https://host20.example.invalid");
    expect(parsed.pathname).toBe("/api/v1/reports/vpn.audit/windows-authentication");
    expect(parsed.searchParams).toEqual(new URLSearchParams({
      domain_id: "7",
      time_from: "2026-08-14T00:00",
      time_to: "2026-08-15T00:00",
      timezone: "Asia/Novosibirsk",
      limit: "100",
    }));
  });
});
