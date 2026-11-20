import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { activityDays, VpnActivityStrip } from "./vpn-activity-strip";

const window = { local_from_date: "2026-09-13", local_to_date: "2026-09-15", timezone: "Asia/Novosibirsk" };

describe("VPN activity strip", () => {
  it("places sessions on office-time-zone days and ranks violation over open over closed", () => {
    const days = activityDays([
      { session_row_id: "a", started_at_utc: "2026-09-12T18:00:00Z", stopped_at_utc: "2026-09-12T19:00:00Z", lifecycle_state: "closed" },
      { session_row_id: "b", started_at_utc: "2026-09-14T03:00:00Z", stopped_at_utc: null, lifecycle_state: "open" },
      { session_row_id: "c", started_at_utc: "2026-09-15T03:00:00Z", stopped_at_utc: "2026-09-15T04:00:00Z", lifecycle_state: "closed", overlap_violation: true },
    ], window, false);
    expect(days.map((day) => [day.date, day.tone])).toEqual([["2026-09-13", "confirmed"], ["2026-09-14", "pending"], ["2026-09-15", "violation"]]);
  });

  it("marks empty days unknown when the session list is incomplete", () => {
    expect(activityDays([], window, true).map((day) => day.tone)).toEqual(["unknown", "unknown", "unknown"]);
    expect(activityDays([], window, false).map((day) => day.tone)).toEqual(["empty", "empty", "empty"]);
  });

  it("falls back to a count without a window and labels every day", () => {
    expect(renderToStaticMarkup(<VpnActivityStrip row={{ sessions: [{}, {}] }}/>)).toContain("2 сессии");
    const html = renderToStaticMarkup(<VpnActivityStrip row={{ display_name: "Иванов", sessions: [] }} window={window}/>);
    expect(html.match(/role="img"/g)).toHaveLength(3);
    expect(html).toContain("13.09: сессий нет");
  });
});
