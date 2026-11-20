import { describe, expect, it } from "vitest";
import { entityEventTimeline } from "./entity-timeline";

describe("entity event timeline", () => {
  it("counts events per local day, fills empty days and stacks by event kind", () => {
    const spec = entityEventTimeline([
      // 23:30 UTC on the 10th is already the 11th in Novosibirsk (UTC+7).
      { time_utc: "2026-09-10T23:30:00Z", label: "Вход", event_id: 4624 },
      { time_utc: "2026-09-11T02:00:00Z", label: "Вход", event_id: 4624 },
      { time_utc: "2026-09-13T08:00:00Z", label: "Отказ", event_id: 4625 },
      { time_utc: null, label: "Без времени", event_id: 1 },
    ], "Asia/Novosibirsk");
    expect(spec).toEqual({ kind: "timeseries", stacked: true, series: [
      { name: "Вход", points: [{ x: "2026-09-11", y: 2 }, { x: "2026-09-12", y: 0 }, { x: "2026-09-13", y: 0 }] },
      { name: "Отказ", points: [{ x: "2026-09-11", y: 0 }, { x: "2026-09-12", y: 0 }, { x: "2026-09-13", y: 1 }] },
    ] });
  });

  it("keeps the five most frequent kinds and folds the rest into one series", () => {
    const events = ["a", "a", "b", "b", "c", "c", "d", "d", "e", "e", "f", "g"].map((label) => ({ time_utc: "2026-09-10T10:00:00Z", label }));
    const spec = entityEventTimeline(events, "UTC");
    expect(spec?.kind === "timeseries" && spec.series.map((series) => [series.name, series.points[0].y])).toEqual([
      ["a", 2], ["b", 2], ["c", 2], ["d", 2], ["e", 2], ["Прочие события", 2],
    ]);
  });

  it("returns nothing without timed events", () => {
    expect(entityEventTimeline([{ time_utc: null }], "UTC")).toBeNull();
  });
});

it("uses a neutral event series for missing and null event IDs", () => {
  const spec = entityEventTimeline([
    { time_utc: "2026-10-21T00:00:00Z" },
    { time_utc: "2026-10-21T01:00:00Z", event_id: null },
  ], "UTC");
  expect(spec?.kind === "timeseries" && spec.series).toEqual([
    { name: "Событие", points: [{ x: "2026-10-21", y: 2 }] },
  ]);
});
