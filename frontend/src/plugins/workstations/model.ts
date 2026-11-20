import { selectedDomain } from "../../app/domain-navigation";

export type Station = {
  station_id: string; agent_key: string | null; ad_computer_id: number | null;
  station_type: string; metadata: Record<string, unknown>; observed_checks: number;
  protection?: unknown; health?: unknown; last_interactive_login?: unknown; devices?: unknown;
};
export type Selection = { station: string | null; finding: string | null; evidence: number | null };

export function paging(rows: Array<Record<string, unknown>> | undefined) {
  const row = rows?.[0];
  return { start: typeof row?.start === "number" && Number.isSafeInteger(row.start) && row.start > 0 ? row.start : 1,
    hasPrevious: row?.has_previous === true,
    previousCursor: typeof row?.previous_cursor === "string" ? row.previous_cursor : null };
}

export function stationRows(items: Array<Record<string, unknown>>): Station[] {
  return items.map((row) => {
    if (typeof row.station_id !== "string" || !row.station_id || typeof row.metadata !== "object" || row.metadata === null) {
      throw new Error("workstation_response_invalid");
    }
    return { ...row, station_id: row.station_id, metadata: row.metadata as Record<string, unknown>,
      agent_key: typeof row.agent_key === "string" ? row.agent_key : null,
      ad_computer_id: typeof row.ad_computer_id === "number" ? row.ad_computer_id : null,
      station_type: typeof row.station_type === "string" ? row.station_type : "unknown",
      observed_checks: typeof row.observed_checks === "number" ? row.observed_checks : 0 };
  });
}

export function countText(count: unknown, unknown: string): string {
  if (!count || typeof count !== "object") return unknown;
  const value = count as { value?: unknown; relation?: unknown };
  if (typeof value.value !== "number" || value.relation === "unknown") return unknown;
  return value.relation === "at_least" ? `≥ ${value.value}` : String(value.value);
}

export function selection(search: URLSearchParams): Selection {
  const station = search.get("station");
  const finding = search.get("finding");
  const raw = search.get("evidence");
  return { station: station && station.length <= 256 ? station : null,
    finding: finding && /^[a-f0-9]{64}$/.test(finding) ? finding : null,
    evidence: raw !== null && /^\d{1,2}$/.test(raw) ? Number(raw) : null };
}

export function requestParams(search: URLSearchParams, timeZone: string): URLSearchParams {
  const params = new URLSearchParams();
  for (const key of ["period", "from", "to", "search", "ou", "check_id", "cursor"]) {
    const value = search.get(key);
    if (value) params.set(key, value);
  }
  const domain = selectedDomain(search.toString());
  if (domain !== null) params.set("domain", domain);
  if (!params.has("period")) params.set("period", "7d");
  params.set("tz", timeZone);
  params.set("limit", search.get("tab") === "checks" && search.has("check_id") ? "5" : "50");
  return params;
}


export function lastInteractiveLogin(value: unknown): { at: string; type: 2 | 10 | 11; name: string | null; sid: string | null } | null {
  if (!value || typeof value !== "object") return null;
  const row = value as Record<string, unknown>;
  if (typeof row.observed_at !== "string" || !/(Z|[+-]\d{2}:\d{2})$/.test(row.observed_at) || !Number.isFinite(Date.parse(row.observed_at))
    || row.logon_type !== 2 && row.logon_type !== 10 && row.logon_type !== 11) return null;
  const account = row.account && typeof row.account === "object" ? row.account as Record<string, unknown> : {};
  const label = (value: unknown) => typeof value === "string" && value.trim() && value.length <= 256 ? value : null;
  const name = label(account.name), domain = label(account.domain);
  return { at: row.observed_at, type: row.logon_type, name: name && domain ? `${domain}\\${name}` : name, sid: label(account.sid) };
}


export function processDetails(finding: Record<string, unknown>): { path: string | null; pid: string | null; signature: "not_received" | "unknown"; measurement?: { status: "signed" | "unsigned" | "unavailable"; at: string; hash: string | null } } | null {
  const value = finding.process_details;
  if (finding.check_id !== "C04" || !value || typeof value !== "object") return null;
  const row = value as Record<string, unknown>;
  const path = typeof row.path === "string" && row.path.trim() && new TextEncoder().encode(row.path).length <= 512 ? row.path : null;
  const pid = typeof row.process_id === "string" && /^[1-9]\d{0,9}$/.test(row.process_id) && Number(row.process_id) <= 4294967295 ? row.process_id : null;
  const raw = row.file_measurement;
  const valueMeasurement = raw && typeof raw === "object" ? raw as Record<string, unknown> : {};
  const hash = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
  const status = valueMeasurement.status;
  const at = valueMeasurement.observed_at_utc;
  const stable = hash(valueMeasurement.sha256_before) && valueMeasurement.sha256_before === valueMeasurement.sha256_after
    && hash(valueMeasurement.identity_before) && valueMeasurement.identity_before === valueMeasurement.identity_after;
  const valid = valueMeasurement.scope === "file_at_measurement" && typeof at === "string" && at.length <= 40
    && /(?:Z|[+-]\d\d:\d\d)$/.test(at) && Number.isFinite(Date.parse(at))
    && ((status === "signed" && stable && hash(valueMeasurement.signer_sha256) && ["embedded", "catalog"].includes(String(valueMeasurement.kind)))
      || (status === "unsigned" && stable && valueMeasurement.kind === "none" && valueMeasurement.signer_sha256 === null)
      || (status === "unavailable" && valueMeasurement.sha256_before === null && valueMeasurement.sha256_after === null
        && valueMeasurement.identity_before === null && valueMeasurement.identity_after === null
        && valueMeasurement.kind === null && valueMeasurement.signer_sha256 === null));
  const measurement = valid ? { status: status as "signed" | "unsigned" | "unavailable", at: at as string,
    hash: hash(valueMeasurement.sha256_before) ? valueMeasurement.sha256_before : null } : undefined;
  return { path, pid, ...(measurement ? { measurement } : {}), signature: row.signature_status === "not_received" ? "not_received" : "unknown" };
}
