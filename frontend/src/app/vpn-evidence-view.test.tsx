import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { VpnSessionEvidence } from "../api/client";
import { VpnSessionEvidenceView } from "./vpn-evidence-view";

const formatTime = (value?: string | null) => value?.replace("T", " ").replace("Z", "") ?? "не зафиксировано";

describe("VpnSessionEvidenceView (drill-down доказательств Accounting session)", () => {
  const baseEvidence: VpnSessionEvidence = {
    contract_id: "sli.vpn-session-evidence.v1",
    report_key: "vpn.audit",
    source_domain_id: 7,
    session_row_id: "radius-session-row:open",
    state: "available",
    branch: { branch: "session_evidence", state: "available", reason: "", dataset_or_resource_group: "vpn.sessions", required_capability: "vpn.session.evidence.read" },
    lifecycle: {
      lifecycle_state: "open_observed",
      completeness: "partial",
      started_at_utc: "2026-08-15T08:20:27Z",
      last_observed_at_utc: "2026-08-15T08:24:02Z",
      stopped_at_utc: null,
      duration_seconds: null,
      observation_count: 1,
      anomalies: [],
      stop_evidence: [],
      incomplete_reason: "missing_stop",
    },
    observations: [{
      observation_id: "obs-1",
      lifecycle_event: "start",
      observed_at_utc: "2026-08-15T08:20:27Z",
      evidence: {
        evidence_uid: "ev-1",
        source_instance_id: "nps-01",
        stream_id: "stream-1",
        transport_binding: "syslog",
        object_reference: "s3://bucket/obj-1",
        canonical_record_sha256: "abc123",
        object_sha256: "def456",
        object_size_bytes: 512,
        verified_at_utc: "2026-08-15T08:21:00Z",
      },
    }],
    limits: { observation_limit: 10000, bounded: true },
  };

  it("для OPEN/INCOMPLETE сессии явно сообщает, что завершение не подтверждено, не показывает Stop evidence и не выдумывает длительность", () => {
    const html = renderToStaticMarkup(<VpnSessionEvidenceView evidence={baseEvidence} formatTime={formatTime}/>);
    expect(html).toContain("Завершение сессии не подтверждено");
    // No <dt>Длительность</dt> detail row — the explanatory callout mentioning the word is fine, a fabricated value is not.
    expect(html).not.toContain("<dt>Длительность</dt>");
    // The only observation is a "start" — exactly one observation card rendered, no separate stop-evidence entry fabricated.
    expect(html.match(/class="sli-ds-list__item"/g)?.length).toBe(1);
  });

  it("для закрытой сессии со Stop-observation показывает Stop-время и длительность", () => {
    const closed: VpnSessionEvidence = {
      ...baseEvidence,
      session_row_id: "radius-session-row:closed",
      lifecycle: {
        ...baseEvidence.lifecycle!,
        lifecycle_state: "closed",
        completeness: "complete",
        stopped_at_utc: "2026-08-15T08:30:00Z",
        duration_seconds: 573,
        incomplete_reason: null,
        stop_evidence: [baseEvidence.observations[0].evidence],
      },
    };
    const html = renderToStaticMarkup(<VpnSessionEvidenceView evidence={closed} formatTime={formatTime}/>);
    expect(html).not.toContain("Завершение сессии не подтверждено");
    expect(html).toContain("Длительность");
  });

  it("not_authorized показывает отсутствие права, а не пустой результат", () => {
    const notAuthorized: VpnSessionEvidence = {
      ...baseEvidence,
      state: "not_authorized",
      branch: { branch: "session_evidence", state: "not_authorized", reason: "Нет назначенной возможности vpn.session.evidence.read", dataset_or_resource_group: "vpn.sessions", required_capability: "vpn.session.evidence.read" },
      lifecycle: null,
      observations: [],
    };
    const html = renderToStaticMarkup(<VpnSessionEvidenceView evidence={notAuthorized} formatTime={formatTime}/>);
    expect(html).toContain("Нет права на просмотр доказательств");
    expect(html).not.toContain("report-empty-compact");
    expect(html).not.toContain("не опубликованы");
  });

  it("никогда не показывает exact_principal_key или session_identity_key", () => {
    const html = renderToStaticMarkup(<VpnSessionEvidenceView evidence={baseEvidence} formatTime={formatTime}/>);
    expect(html).not.toContain("exact_principal_key");
    expect(html).not.toContain("session_identity_key");
  });
});
