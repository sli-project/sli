import { describe, expect, it } from "vitest";
import type { V4ReportAccessTrace } from "../api/client";
import { reportTraceGrantLabel, reportTraceScopeLabel } from "./report-access-trace";

describe("fresh report access trace presentation", () => {
  it("keeps one grant scope intact and labels it in Russian", () => {
    expect(reportTraceScopeLabel({ kind: "server", ids: [4, 7] })).toBe("серверы: 4, 7");
    expect(reportTraceScopeLabel({ kind: "all" })).toBe("вся разрешённая область");
  });

  it("labels the source, fields and actions without combining grants", () => {
    const grant = {
      source_type: "direct", source: "current_subject", scope: { kind: "domain", ids: [2] },
      field_categories: ["identity_basic", "security"], allowed_actions: ["view", "export"],
    } as V4ReportAccessTrace["grants"][number];
    expect(reportTraceGrantLabel(grant)).toEqual({
      title: "прямое назначение",
      fields: "базовая идентификация, сведения безопасности",
      actions: "просмотр, экспорт",
    });
  });
});
