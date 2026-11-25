import type { ReportResultDto } from "../../api/report-v2-types";

export type FileAuditAce = {
  ordinal: number; type: "allow" | "deny" | "audit" | "unknown"; ace_type: string; sid: string;
  name?: string | null; mask: number | null; mask_raw: string; flags: string[]; flags_raw: string;
  inherited: boolean; inherit_only: boolean; raw: string;
};
export type FileAuditAcl = { state: "complete" | "partial" | "missing" | "unsupported"; raw: string | null; flags_raw?: string; aces: FileAuditAce[] };
export type FileAuditObject = { path: string; object_type: string; owner_sid: string | null; file_id: string | null;
  dacl: FileAuditAcl; sacl: FileAuditAcl; sacl_protected: boolean | null };
export type FileAuditShare = { name: string; path: string; complete: boolean; dacl: FileAuditAcl };
export type FileAuditSnapshot = { id: string; observed_at: string; policy_revision: string; scan_id: string;
  page_number: number; has_more: boolean; completeness: string; unread_objects: number };
export type FileAuditObservation = { snapshot: FileAuditSnapshot; share: FileAuditShare; object: FileAuditObject | null };
export type FileAuditComparison = { state: "available" | "unavailable" | "not_requested"; reason: string | null;
  identity_basis: "file_id" | "path" | null; before?: FileAuditObservation; after?: FileAuditObservation };
export type FileAuditDetailResult = ReportResultDto & { detail?: FileAuditObservation & { comparison: FileAuditComparison } };
export type AceFilter = "all" | "explicit" | "inherited" | "deny";
export type AclDifference = { id: string; change: "added" | "removed" | "changed" | "unchanged"; before?: FileAuditAce; after?: FileAuditAce };

/** The endpoint returns one whole bounded descriptor; filtering never scans only a displayed page. */
export function filterAces(aces: FileAuditAce[], search: string, filter: AceFilter) {
  const needle = search.trim().toLocaleLowerCase();
  return aces.filter(ace => (!needle || [ace.sid, ace.name, ace.mask_raw, ace.raw].some(value => value?.toLocaleLowerCase().includes(needle)))
    && (filter === "all" || filter === "deny" && ace.type === "deny"
      || filter === "inherited" && ace.inherited || filter === "explicit" && !ace.inherited));
}

/** Compare retained entries, including multiplicity and source positions; never calculate effective access. */
export function aclDifferences(before?: FileAuditAcl, after?: FileAuditAcl): AclDifference[] | null {
  if (before?.state !== "complete" || after?.state !== "complete") return null;
  const remaining = new Set(before.aces.map((_, index) => index));
  const matches = new Map<number, number>();
  // Reserve exact matches before pairing modified entries of the same subject/type.
  for (const [index, ace] of after.aces.entries()) {
    const old = [...remaining].find(candidate => before.aces[candidate].raw === ace.raw);
    if (old !== undefined) { matches.set(index, old); remaining.delete(old); }
  }
  for (const [index, ace] of after.aces.entries()) {
    if (matches.has(index)) continue;
    const old = [...remaining].find(candidate => before.aces[candidate].sid === ace.sid && before.aces[candidate].ace_type === ace.ace_type);
    if (old !== undefined) { matches.set(index, old); remaining.delete(old); }
  }
  const differences = after.aces.map((ace, index): AclDifference => {
    const old = matches.has(index) ? before.aces[matches.get(index)!] : undefined;
    return { id: `${old?.ordinal ?? "added"}:${ace.ordinal}`, before: old, after: ace,
      change: !old ? "added" : old.raw === ace.raw && old.ordinal === ace.ordinal ? "unchanged" : "changed" };
  });
  for (const index of remaining) differences.push({ id: `${before.aces[index].ordinal}:removed`, before: before.aces[index], change: "removed" });
  return differences;
}
