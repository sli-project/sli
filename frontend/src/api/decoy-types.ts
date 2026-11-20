export type DecoyIdentity = { domain_id: number; entity_id: number; sid: string; guid: string }
  | { agent_id: string; source_instance_id: string; collection_scope_id: string; path: string };
export type DecoyInput = { kind: "account" | "file"; identity: DecoyIdentity; owner: string; reason: string; active: boolean; revision: number };
export type DecoyLabel = DecoyInput & { id: string; active_from: string; active_to: string | null;
  actor_type: string; actor_id: number; can_manage: boolean;
  readiness: { state: "ready" | "not_ready"; reasons: string[]; checked_at: string; last_observation_at: string | null } };
export type DecoyRegistry = { items: DecoyLabel[]; has_more: boolean; next_cursor: string | null };
export type DecoyTouch = { id: string; mode: "test" | "shadow" | "enabled"; revision: number; path: string;
  observed_at: string; event_id: number; meaning: "access_check" | "access_denied" | "read" | "file_action" | "deleted" | "permissions_changed";
  outcome: "success" | "failure"; denial_layer: "smb" | "ntfs" | null; subject_sid: string | null;
  access_mask: number | null; evidence_key: string; sha256: string };
export type DecoyTouches = { items: DecoyTouch[]; has_more: boolean; next_cursor: string | null };
