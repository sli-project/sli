import { describe, expect, it } from "vitest";
import { eventSemanticLookupPresentation, eventSemanticLookupRequest } from "./event-card";

describe("семантический поиск точного события", () => {
  it("переносит из URL только проверенный временной контекст в API и query key", () => {
    const request = eventSemanticLookupRequest(
      42,
      "http://localhost/events/42?event_db_id=42&time_from=2026-09-10T00%3A00Z&time_to=2026-09-11T00%3A00Z&timezone=Asia%2FBangkok&q=ignored",
    );

    expect(request).toEqual({
      error: null,
      queryKey: "event_db_id=42&time_from=2026-09-10T00%3A00Z&time_to=2026-09-11T00%3A00Z&timezone=Asia%2FBangkok",
      parameters: "event_db_id=42&time_from=2026-09-10T00%3A00Z&time_to=2026-09-11T00%3A00Z&timezone=Asia%2FBangkok",
    });
  });

  it("не отправляет широкий запрос при повреждённом временном контексте", () => {
    expect(eventSemanticLookupRequest(42, "http://localhost/events/42?time_from=broken")).toEqual({
      error: "invalid_time",
      queryKey: "invalid-context",
      parameters: null,
    });
  });

  it("не выдаёт недоступную схему или отказ за пустой результат", () => {
    expect(eventSemanticLookupPresentation({ actions: "schema_unavailable", scenarios: "empty" })).toBe("schema_unavailable");
    expect(eventSemanticLookupPresentation({ actions: "unavailable", scenarios: "available" })).toBe("unavailable");
    expect(eventSemanticLookupPresentation({ actions: "error", scenarios: "available" })).toBe("error");
    expect(eventSemanticLookupPresentation({ actions: "empty", scenarios: "empty" })).toBe("no_results");
  });
});
