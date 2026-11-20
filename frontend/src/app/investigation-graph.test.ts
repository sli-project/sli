import { describe, expect, it } from "vitest";
import { evidenceGraphRelations } from "./case-page";

describe("investigation evidence graph", () => {
  it("does not infer causal edges from the order evidence was added", () => {
    expect(evidenceGraphRelations([
      { event_db_id: 101, relation_status: "confirmed" },
      { event_db_id: 202, relation_status: "confirmed" },
    ])).toEqual([]);
  });
});
