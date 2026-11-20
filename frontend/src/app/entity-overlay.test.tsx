import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type { V4ObjectDetail } from "../api/client";
import { availableEntityCardTabs, EntityCardView } from "./entity-overlay";

const detail = (tabs: V4ObjectDetail["tabs"]): V4ObjectDetail => ({
  api_version: "v4",
  state: "available",
  object: {
    object_type: "ad_user",
    object_id: "object-1",
    display_name: "Реальная учётная запись",
  },
  identity_links: [],
  identity_contract: "resolved",
  tabs,
  current_states: [],
  directory_context: { items: [] },
  findings: [],
  events: [],
  events_state: "available",
  has_more_events: false,
  actions: [],
  provenance: [],
  limitations: [],
});

describe("карточка сущности поверх отчёта", () => {
  it.each([
    ["critical", "danger"], ["high", "danger"], ["inactive", undefined],
    ["unknown", undefined], ["ok", "success"], ["incomplete", undefined],
  ])("использует точное состояние %s для цвета", (status, tone) => {
    const data = detail([]);
    data.provenance = [{ source: "fixture", freshness: status }];
    const html = renderToStaticMarkup(<EntityCardView data={data}/>);
    const badge = html.match(new RegExp(`<span class="sli-ds-badge"[^>]*>${status}</span>`))?.[0];
    expect(badge).toBeDefined();
    if (tone) expect(badge).toContain(`data-tone="${tone}"`);
    else expect(badge).not.toContain("data-tone");
  });

  it("не показывает вкладки, которые сервер не разрешил", () => {
    expect(availableEntityCardTabs(detail([
      { id: "overview", label: "Обзор", available: true },
      { id: "states", label: "Состояния", available: false },
      { id: "findings", label: "Находки", available: false },
      { id: "technical", label: "Технические данные", available: false },
    ]))).toEqual(["overview"]);
  });

  it("объединяет разрешённые группы и привилегии в один раздел связей", () => {
    expect(availableEntityCardTabs(detail([
      { id: "overview", label: "Обзор", available: true },
      { id: "groups", label: "Группы", available: true },
      { id: "privileges", label: "Привилегии", available: true },
      { id: "states", label: "Состояния", available: true },
      { id: "findings", label: "Находки", available: true },
      { id: "technical", label: "Технические данные", available: true },
    ]))).toEqual(["overview", "relations", "states", "findings", "technical"]);
  });

  it("показывает точный объект и происхождение без вымышленных атрибутов", () => {
    const data = detail([{ id: "overview", label: "Обзор", available: true }]);
    data.object.natural_key = "EXAMPLE\\account";
    data.provenance = [{ source: "directory_accounts", observed_at_utc: "2026-07-23T12:00:00Z", freshness: "complete" }];
    data.directory_context.items = [{
      context_kind: "entity",
      attributes: { department: "ИТ", enabled: true, operating_system: null, inactive_threshold_days: 180 },
    }];
    const html = renderToStaticMarkup(<EntityCardView data={data}/>);
    expect(html).toContain("EXAMPLE\\account");
    expect(html).toContain("directory_accounts");
    expect(html).toContain("Подразделение");
    expect(html).not.toContain("<dt>Операционная система</dt>");
    expect(html).not.toContain("Порог неактивности, дней");
    expect(html).not.toContain("CORP");
  });
});
