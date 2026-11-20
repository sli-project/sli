import { describe, expect, it } from "vitest";
import { shouldRetryQuery } from "./retry-policy";

describe("shouldRetryQuery", () => {
  it("не повторяет детерминированные ответы 4xx", () => {
    for (const status of [400, 403, 404, 409]) expect(shouldRetryQuery(0, { status })).toBe(false);
  });
  it("повторяет сетевые сбои и 5xx ограниченное число раз", () => {
    expect(shouldRetryQuery(0, { status: 503 })).toBe(true);
    expect(shouldRetryQuery(1, new Error("network"))).toBe(true);
    expect(shouldRetryQuery(2, { status: 503 })).toBe(false);
  });
});
