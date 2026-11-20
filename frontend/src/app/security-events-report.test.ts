import { describe, expect, it } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  SECURITY_EVENT_FAMILIES,
  securityEventRows,
  securityEntityHref,
  vpnAccountingRows,
  vpnAccountingCoverageText,
  vpnAccountingIsolatedByWindowsFilters,
  SecurityEventSourceContext,
  SecurityRelationsPanel,
  VpnAccountingIsolationNotice,
  vpnAccountingSessionParams,
  securityRelationParams,
  semanticRelationExplanation,
  semanticRelationIdentityBasis,
  semanticRelationPresentation,
  semanticRelationTitle,
  securityReportReturnHref,
  securityEventsParams,
  RelationCursorRestartNotice,
  semanticRelationsQueryKey,
  shouldRestartSemanticRelations,
  type SecurityEventsFilterState,
} from "./security-events-report";
import { ApiResponseError } from "../api/client";
import type { SecurityEventItem, VpnSessionReport } from "../api/client";

const event = (overrides: Partial<SecurityEventItem> = {}): SecurityEventItem => ({
  event_db_id: 517548,
  event_record_id: 901,
  event_id: 4728,
  event_family: "group_membership",
  time_created_utc: "2026-09-11T10:20:30.123456Z",
  actor: { state: "observed", sid: "S-1-5-21-actor", name: "operator", entity_id: 11 },
  affected_account: { state: "observed", sid: "S-1-5-21-group", name: "VPNl2tp", entity_id: 13 },
  member: { state: "observed", sid: "S-1-5-21-member", name: "evidence-reader", entity_id: 12 },
  group: { state: "observed", sid: "S-1-5-21-group", name: "VPNl2tp", entity_id: 13 },
  source_host: { state: "observed", hostname: "DC1.example.test" },
  outcome: { state: "unknown", reason: "event_outcome_not_proven_by_scoped_contract" },
  evidence: { state: "complete", missing_fields: [], event_db_id: 517548, event_record_id: 901 },
  ...overrides,
});

describe("security events report view model", () => {
  it("restarts relation pagination only after an expired or lost server cursor", () => {
    const filters: SecurityEventsFilterState = {
      domainId: 7, timeFrom: "2026-09-11T10:00:00Z", timeTo: "2026-09-11T11:00:00Z",
      timeZone: "UTC", category: "", eventId: "", outcome: "", actor: "", target: "",
      group: "", source: "", q: "", limit: 200,
    };

    expect(shouldRestartSemanticRelations(new ApiResponseError(400, "invalid_semantic_relation_filter"))).toBe(true);
    expect(shouldRestartSemanticRelations(new ApiResponseError(403, "insufficient_capability"))).toBe(false);
    expect(semanticRelationsQueryKey(filters, 0)).not.toEqual(semanticRelationsQueryKey(filters, 1));
    expect(renderToStaticMarkup(createElement(RelationCursorRestartNotice))).toContain(
      "Срок действия продолжения истёк. Цепочки загружены заново с начала выбранного периода.",
    );
  });

  it("offers authentication as an explicit category without making it the default", () => {
    expect(SECURITY_EVENT_FAMILIES[0]).toEqual(["", "Значимые действия (без обычных входов)"]);
    expect(SECURITY_EVENT_FAMILIES).toContainEqual(["authentication", "Аутентификация"]);
  });

  it("accepts the authentication family returned by the explicit API filter", () => {
    const [row] = securityEventRows([
      event({ event_id: 4624, event_family: "authentication" }),
    ], (value) => value);

    expect(row.action).toBe("Успешный вход");
  });

  it("preserves explicit authentication category and Event ID in URL parameters", () => {
    const params = securityEventsParams({
      domainId: 7,
      timeFrom: "2026-09-11T10:00:00Z",
      timeTo: "2026-09-11T11:00:00Z",
      timeZone: "Asia/Bangkok",
      category: "authentication",
      eventId: "4624",
      outcome: "",
      actor: "",
      target: "",
      group: "",
      source: "",
      q: "",
      limit: 200,
    });

    expect(params.toString()).toBe(
      "domain_id=7&time_from=2026-09-11T10%3A00%3A00Z&time_to=2026-09-11T11%3A00%3A00Z&timezone=Asia%2FBangkok&limit=200&category=authentication&event_id=4624",
    );
  });

  it("keeps actor, member and group as different observed roles", () => {
    const [row] = securityEventRows([event()], (value) => value);

    expect(row.action).toBe("Участник добавлен в глобальную группу");
    expect(row.actor).toBe("operator");
    expect(row.target).toBe("evidence-reader");
    expect(row.group).toBe("VPNl2tp");
    expect(row.actorEntityId).toBe(11);
    expect(row.targetEntityId).toBe(12);
    expect(row.groupEntityId).toBe(13);
    expect(row.result).toBe("Результат не подтверждён");
    expect(row.eventHref).toBe("/app/events/517548");
  });

  it("does not present a password reset attempt as a successful reset", () => {
    const [row] = securityEventRows([
      event({ event_id: 4724, event_family: "password_operation", member: { state: "unknown" }, group: { state: "unknown" } }),
    ], (value) => value);

    expect(row.action).toBe("Попытка сброса пароля");
    expect(row.result).toBe("Результат не подтверждён");
  });

  it("shows the shared account before-to-after meaning in the unified report", () => {
    const [row] = securityEventRows([
      event({
        event_id: 4722,
        event_family: "account_lifecycle",
        member: { state: "unknown" },
        group: { state: "unknown" },
        account_change: {
          change: { kind: "enabled" },
          observed_transition: {
            before: {
              state: "partial",
              last_observed: {
                value: "present",
                event_db_id: 517547,
                time_created_utc: "2026-09-11T10:19:30.123456Z",
              },
              reason: "intervening_account_state_not_proven",
            },
            after: { state: "observed", value: "enabled" },
          },
        },
      }),
    ], (value) => value);

    expect(row.before).toEqual({
      текст: "запись создана",
      уточнение: "по последнему наблюдению, не по этому событию · возможны непроверенные промежуточные изменения",
    });
    expect(row.after).toEqual({ текст: "включена" });
  });

  it("preserves precise bounds and every applied server filter", () => {
    const filters: SecurityEventsFilterState = {
      domainId: 7,
      timeFrom: "2026-09-11T10:20:30.123456Z",
      timeTo: "2026-09-11T11:20:30.987654Z",
      timeZone: "Asia/Bangkok",
      category: "group_membership",
      eventId: "4728",
      outcome: "unknown",
      actor: "operator",
      target: "evidence-reader",
      group: "VPNl2tp",
      source: "DC1",
      q: "VPN",
      limit: 200,
      cursor: "next-page",
    };

    expect(securityEventsParams(filters).toString()).toBe(
      "domain_id=7&time_from=2026-09-11T10%3A20%3A30.123456Z&time_to=2026-09-11T11%3A20%3A30.987654Z&timezone=Asia%2FBangkok&limit=200&category=group_membership&event_id=4728&outcome=unknown&actor=operator&target=evidence-reader&group=VPNl2tp&source=DC1&q=VPN&cursor=next-page",
    );
    expect(securityReportReturnHref(filters)).toBe(
      "/app/report/security.events.chains?domain=7&period=custom&from=2026-09-11T10%3A20%3A30.123456Z&to=2026-09-11T11%3A20%3A30.987654Z&tz=Asia%2FBangkok&category=group_membership&outcome=unknown&event_id=4728&actor=operator&target=evidence-reader&group=VPNl2tp&source=DC1&q=VPN",
    );
    expect(securityReportReturnHref(filters, "chains")).toContain("&tab=chains");
    expect(securityEntityHref(12, filters)).toContain("return_to=%2Fapp%2Freport%2Fsecurity.events.chains%3Fdomain%3D7");
    expect(securityRelationParams(filters).toString()).toBe(
      "domain_id=7&time_from=2026-09-11T10%3A20%3A30.123456Z&time_to=2026-09-11T11%3A20%3A30.987654Z&timezone=Asia%2FBangkok&limit=200&category=group_membership&event_id=4728&outcome=unknown&actor=operator&target=evidence-reader&group=VPNl2tp&source=DC1&q=VPN",
    );
    expect(vpnAccountingSessionParams(filters).toString()).toBe(
      "domain_id=7&time_from=2026-09-11T10%3A20%3A30.123456Z&time_to=2026-09-11T11%3A20%3A30.987654Z&timezone=Asia%2FBangkok&limit=200",
    );
  });

  it("forwards exact identity and every Windows filter to chains but isolates Accounting", () => {
    const filters: SecurityEventsFilterState = {
      domainId: 7,
      timeFrom: "2026-09-11T10:20:30.123456Z",
      timeTo: "2026-09-11T11:20:30.987654Z",
      timeZone: "Asia/Bangkok",
      category: "group_membership",
      eventId: "4728",
      outcome: "unknown",
      actor: "operator",
      target: "evidence-reader",
      group: "VPNl2tp",
      source: "DC1",
      q: "VPN",
      entityId: 12,
      eventDbId: 517548,
      limit: 200,
    };

    expect(securityRelationParams(filters).toString()).toBe(
      "domain_id=7&time_from=2026-09-11T10%3A20%3A30.123456Z&time_to=2026-09-11T11%3A20%3A30.987654Z&timezone=Asia%2FBangkok&limit=200&category=group_membership&event_id=4728&outcome=unknown&actor=operator&target=evidence-reader&group=VPNl2tp&source=DC1&q=VPN&entity_id=12&event_db_id=517548",
    );
    expect(securityReportReturnHref(filters, "chains")).toContain("entity_id=12");
    expect(securityReportReturnHref(filters, "chains")).toContain("event_db_id=517548");
    expect(vpnAccountingIsolatedByWindowsFilters(filters)).toBe(true);
  });

  it("renders caller/change, bounded chain coverage, and VPN isolation without a broad Accounting list", () => {
    const [row] = securityEventRows([event({
      event_id: 4738,
      event_family: "account_change",
      caller_computer: { state: "observed", hostname: "CLIENT-42" },
      change: {
        state: "observed",
        kind: "attributes_changed",
        attributes: { display_name: "Alice Example" },
        old_group_type: "Global",
        new_group_type: "Universal",
        new_description: "Changed without an old value",
      },
    })], (value) => value);
    const sourceHtml = renderToStaticMarkup(createElement(SecurityEventSourceContext, { source: row.sourceText }));
    const coverageHtml = renderToStaticMarkup(createElement(SecurityRelationsPanel, {
      items: [],
      state: "empty",
      coverage: {
        state: "available", matched_relation_count: 1, matched_relation_state: "bounded_page",
        supported_rules_state: "available",
        supported_rules: [{ rule_id: "investigation.account.unlock.after-lock", rule_version: 2, lifecycle_status: "shadow" }],
        observed_rules: [{ rule_id: "investigation.account.unlock.after-lock", rule_version: 2 }],
        limitations: ["Полнота retained-истории не доказана."],
      },
      loading: false,
      failed: false,
      hasMore: false,
      fetchingMore: false,
      fetchMore: () => {},
      filters: { domainId: 7, timeFrom: "2026-09-11T10:00:00Z", timeTo: "2026-09-11T11:00:00Z", timeZone: "UTC", category: "", eventId: "", outcome: "", actor: "", target: "", group: "", source: "", q: "", limit: 200 },
    }));
    const partialRow = securityEventRows([event({ change: { state: "partial", detail: { state: "partial", reason: "account_attributes_not_present" } } })], (value) => value)[0];
    const partialHtml = renderToStaticMarkup(createElement(SecurityEventSourceContext, { source: partialRow.sourceText }));
    const vpnHtml = renderToStaticMarkup(createElement(VpnAccountingIsolationNotice));

    expect(sourceHtml).toContain("Вызывающий компьютер: CLIENT-42");
    expect(sourceHtml).toContain("display name: Alice Example");
    expect(sourceHtml).toContain("group type: Global → Universal");
    expect(sourceHtml).toContain("description: Changed without an old value");
    expect(sourceHtml).not.toContain("undefined →");
    expect(partialHtml).toContain("часть атрибутов отсутствует в сохранённом доказательстве");
    expect(partialHtml).not.toContain("account_attributes_not_present");
    expect(coverageHtml).toContain("Покрытие цепочек");
    expect(coverageHtml).toContain("Поддерживаемые правила (test/shadow/enabled)");
    expect(coverageHtml).toContain("Правила наблюдаемых последовательностей");
    expect(coverageHtml).toContain("investigation.account.unlock.after-lock v2");
    expect(coverageHtml).not.toContain("Проверка active/supported правил сейчас недоступна");
    expect(coverageHtml).toContain("Полнота retained-истории не доказана.");
    expect(vpnHtml).toContain("VPN Accounting не показан");
    expect(vpnHtml).not.toContain("сессий");
  });

  it("keeps supported-rule coverage visible for an authorized empty chains result", () => {
    const filters: SecurityEventsFilterState = { domainId: 7, timeFrom: "2026-09-11T10:00:00Z", timeTo: "2026-09-11T11:00:00Z", timeZone: "UTC", category: "", eventId: "", outcome: "", actor: "", target: "", group: "", source: "", q: "", limit: 200 };
    const supportedHtml = renderToStaticMarkup(createElement(SecurityRelationsPanel, {
      items: [], state: "empty", loading: false, failed: false, hasMore: false, fetchingMore: false, fetchMore: () => {}, filters,
      coverage: { state: "empty", matched_relation_count: null, matched_relation_state: "empty", supported_rules_state: "available", supported_rules: [{ rule_id: "investigation.account.unlock.after-lock", rule_version: 2, lifecycle_status: "shadow" }], limitations: ["Проверка ограничена сохранённой историей."] },
    }));
    const unavailableHtml = renderToStaticMarkup(createElement(SecurityRelationsPanel, {
      items: [], state: "empty", loading: false, failed: false, hasMore: false, fetchingMore: false, fetchMore: () => {}, filters,
      coverage: { state: "empty", matched_relation_count: null, matched_relation_state: "empty", supported_rules_state: "check_unavailable", limitations: ["Проверка правил временно недоступна."] },
    }));

    expect(supportedHtml).toContain("Покрытие цепочек");
    expect(supportedHtml).toContain("Показано 0 цепочек");
    expect(supportedHtml).toContain("investigation.account.unlock.after-lock v2 (shadow)");
    expect(unavailableHtml).toContain("Проверка active/supported правил сейчас недоступна");
    expect(unavailableHtml).toContain("Проверка правил временно недоступна.");
  });

  it("presents VPN Accounting lifecycle without inventing a missing Stop", () => {
    const report: VpnSessionReport = {
      contract_id: "sli.vpn-session-report.v1",
      report_key: "vpn.audit",
      source_domain_id: 7,
      state: "available",
      branches: {},
      coverage: null,
      items: [
        {
          session_row_id: `radius-session-row:${"a".repeat(64)}`,
          entity_id: 42,
          domain_id: 7,
          generation: 1,
          lifecycle_state: "closed",
          completeness: "complete",
          started_at_utc: "2026-09-11T10:20:30.123456Z",
          last_observed_at_utc: "2026-09-11T10:40:30.123456Z",
          stopped_at_utc: "2026-09-11T10:40:30.123456Z",
          duration_seconds: 1200,
          observation_count: 3,
          anomalies: [],
        },
        {
          session_row_id: `radius-session-row:${"b".repeat(64)}`,
          entity_id: 43,
          domain_id: 7,
          generation: 1,
          lifecycle_state: "open_observed",
          completeness: "partial",
          started_at_utc: "2026-09-11T10:30:30.123456Z",
          last_observed_at_utc: "2026-09-11T10:31:30.123456Z",
          stopped_at_utc: null,
          duration_seconds: null,
          observation_count: 2,
          anomalies: ["missing_stop"],
        },
        {
          session_row_id: `radius-session-row:${"c".repeat(64)}`,
          entity_id: 44,
          domain_id: 7,
          generation: 1,
          lifecycle_state: "partial_closed",
          completeness: "missing_start",
          started_at_utc: null,
          last_observed_at_utc: "2026-09-11T10:42:30.123456Z",
          stopped_at_utc: "2026-09-11T10:42:30.123456Z",
          duration_seconds: null,
          observation_count: 1,
          anomalies: ["missing_start"],
        },
      ],
      page: { limit: 200, offset: 0, has_more: false },
    };

    const rows = vpnAccountingRows(report, (value) => value || "—");
    expect(rows[0].lifecycle).toBe("Start и Stop наблюдались");
    expect(rows[0].completion).toBe("Завершение наблюдалось");
    expect(rows[1].lifecycle).toBe("Start наблюдался, Stop отсутствует");
    expect(rows[1].completion).toBe("Конец и длительность не подтверждены");
    expect(rows[2].lifecycle).toBe("Stop наблюдался, Start отсутствует");
    expect(rows[2].stoppedAt).toBe("2026-09-11T10:42:30.123456Z");
    expect(rows[2].completion).toBe("Начало и длительность не подтверждены");
  });

  it("explains non-complete VPN source states independently from rows", () => {
    expect(vpnAccountingCoverageText({ state: "processing", coverage: null })).toContain("обрабатываются");
    expect(vpnAccountingCoverageText({ state: "not_collected", coverage: null })).toContain("не поступали");
    expect(vpnAccountingCoverageText({ state: "identity_incomplete", coverage: null })).toContain("идентичност");
    expect(vpnAccountingCoverageText({ state: "available", coverage: null })).toBeNull();
  });

  it("uses factual Russian titles for saved relation kinds", () => {
    expect(semanticRelationTitle("authentication.account.lockout_preceded_by_failures_observed"))
      .toBe("Отказы входа перед блокировкой учётной записи");
    expect(semanticRelationTitle("authentication.password_reset_followed_by_logon_observed"))
      .toBe("Сброс пароля и последующий успешный вход");
    expect(semanticRelationTitle("unknown.kind")).toBe("Наблюдаемая последовательность событий");
  });

  it("states in Russian that an ambiguous continuation is not established", () => {
    expect(semanticRelationPresentation({ continuation_state: "unique", possible_continuation_count: 1 }))
      .toBe("Наблюдалось одно допустимое последующее событие.");
    expect(semanticRelationPresentation({ continuation_state: "ambiguous", possible_continuation_count: 2 }))
      .toBe("Найдено 2 допустимых последующих события; конкретное продолжение не установлено.");
  });

  it("presents known relation explanations and exact identity basis in Russian", () => {
    expect(semanticRelationExplanation({
      relation_kind: "authentication.account.unlock_after_lock_observed",
      explanation: "A lockout observation strictly precedes an unlock observation.",
    })).toContain("точного SID учётной записи");
    expect(semanticRelationExplanation({
      relation_kind: "unknown.kind",
      explanation: "Сохранённое объяснение",
    })).toBe("Сохранённое объяснение");
    expect(semanticRelationIdentityBasis({
      kind: "exact_domain_account_sid",
      domain_id: 7,
      account_sid: "S-1-5-21-7-1001",
    })).toBe("Совпали домен 7 и точный SID учётной записи S-1-5-21-7-1001.");
    expect(semanticRelationIdentityBasis({
      kind: "exact_domain_member_group_sid",
      domain_id: 7,
      member_sid: "S-1-5-21-7-1002",
      group_sid: "S-1-5-21-7-512",
    })).toBe("Совпали домен 7, точный SID участника S-1-5-21-7-1002 и точный SID группы S-1-5-21-7-512.");
  });
});
