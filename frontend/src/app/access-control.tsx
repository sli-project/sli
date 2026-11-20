import type { ReactNode } from "react";
import type { Bootstrap } from "../api/client";

export type PrincipalRole = "viewer" | "operator" | "admin";

export type InvestigationMutationAction =
  | "create_case"
  | "add_evidence"
  | "update_case_status"
  | "add_case_note"
  | "update_evidence_relation";

/**
 * Executable mirror of the backend mutation boundary in
 * `RequestHandler._authorize_mutation`: investigation writes require at least
 * the viewer (ИБ analyst) role. The server remains authoritative; this matrix prevents
 * the React UI from advertising or activating actions it will reject.
 */
export const INVESTIGATION_MUTATION_ROLE_MATRIX: Readonly<Record<InvestigationMutationAction, readonly PrincipalRole[]>> = {
  create_case: ["viewer", "operator", "admin"],
  add_evidence: ["viewer", "operator", "admin"],
  update_case_status: ["viewer", "operator", "admin"],
  add_case_note: ["viewer", "operator", "admin"],
  update_evidence_relation: ["viewer", "operator", "admin"],
};

/** Prefer the server-computed authorization view; principal is a rollout fallback only. */
export function bootstrapEffectiveRole(bootstrap: Bootstrap | null | undefined): string | undefined {
  return bootstrap?.effective_role ?? bootstrap?.principal?.role;
}

export function canPerformInvestigationMutation(role: string | null | undefined, action: InvestigationMutationAction): boolean {
  return INVESTIGATION_MUTATION_ROLE_MATRIX[action].includes(role as PrincipalRole);
}

export function InvestigationMutationGate({ role, action, children }: { role: string | null | undefined; action: InvestigationMutationAction; children: ReactNode }) {
  return canPerformInvestigationMutation(role, action) ? children : null;
}
