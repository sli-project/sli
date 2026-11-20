/** Sequence counters are bigint strings, never JavaScript numbers. */
export function recoveryRange(value: { expected_sequence: string; received_sequence: string; missing_packets: string }): { first: string; last: string; count: string } | null {
  const fields = [value.expected_sequence, value.received_sequence, value.missing_packets];
  if (fields.some((field) => typeof field !== "string" || !/^[1-9][0-9]{0,18}$/.test(field))) return null;
  const [expected, received, missing] = fields.map((field) => BigInt(field));
  if (received > 9223372036854775807n || expected >= received || missing !== received - expected) return null;
  return { first: expected.toString(), last: (received - 1n).toString(), count: missing.toString() };
}

/** Validate the server's exact eligible set; never infer candidates from history. */
export function validRecoveryPreview(value: unknown, agentId: string): boolean {
  if (!value || typeof value !== "object") return false;
  const preview = value as { agent_id?: unknown; preview_token?: unknown; observation_ids?: unknown; streams?: unknown };
  if (preview.agent_id !== agentId || typeof preview.preview_token !== "string" || !/^[0-9a-f]{64}$/.test(preview.preview_token) || !Array.isArray(preview.observation_ids) || !Array.isArray(preview.streams)
      || preview.streams.length > 100 || preview.observation_ids.length !== preview.streams.length) return false;
  const ids = preview.observation_ids;
  if (ids.some((id) => typeof id !== "string" || !id) || new Set(ids).size !== ids.length) return false;
  const modules = new Set<string>();
  const seen = new Set<string>();
  return preview.streams.every((value) => {
    if (!value || typeof value !== "object") return false;
    const stream = value as { id?: unknown; agent_id?: unknown; module_id?: unknown; status?: unknown; expected_sequence: string; received_sequence: string; missing_packets: string };
    if (typeof stream.id !== "string" || !ids.includes(stream.id) || seen.has(stream.id) || stream.agent_id !== agentId || typeof stream.module_id !== "string" || !stream.module_id
        || modules.has(stream.module_id) || !["pending", "authorized"].includes(String(stream.status)) || !recoveryRange(stream)) return false;
    modules.add(stream.module_id); seen.add(stream.id); return true;
  });
}
