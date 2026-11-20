export type WatchInput = { entity_id: number; owner: string; reason: string; expires_at: string; active: boolean; revision: number };
export type WatchEntry = Omit<WatchInput, "entity_id"> & { id: string;
  identity: { entity_id: number; domain_id: number; sid: string; guid: string };
  active_from: string; valid_from: string; valid_to: string | null; actor_type: string; actor_id: number;
  status: "active" | "expired" | "disabled"; can_manage: boolean };
export type WatchRegistry = { items: WatchEntry[]; has_more: boolean; next_cursor: string | null; can_manage: boolean };
