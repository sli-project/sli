function requireInput(value: boolean): asserts value {
  if (!value) throw new Error("agent_registration_invalid");
}

export function registrationConfiguration(origin: string, fingerprint: string) {
  const source = origin.trim(), pin = fingerprint.trim();
  requireInput(source.length >= 9 && source.length < 4096);
  requireInput(/^https:\/\/(?:\[[^\]]+\]|[^/:]+)(?::[0-9]{1,5})?\/?$/i.test(source));
  requireInput(!/[\u0000-\u0020\u007f\\@?#]/.test(source));
  let url: URL;
  try { url = new URL(source); } catch { throw new Error("agent_registration_invalid"); }
  requireInput(url.protocol === "https:" && !!url.hostname && (!url.port || Number(url.port) > 0));
  requireInput(pin.length === 64 && /^[a-f0-9]+$/i.test(pin));
  const serverUrl = url.origin + "/";
  requireInput(serverUrl.length < 4096);
  return { server_url: serverUrl, ca_sha256: pin.toLowerCase() };
}

export function registrationFile(origin: string, fingerprint: string, issued: { token: string; expires_at: string }, computerId: number, now = Date.now()): string {
  const configuration = registrationConfiguration(origin, fingerprint);
  requireInput(Number.isSafeInteger(computerId) && computerId > 0);
  requireInput(issued.token.length === 43 && /^[A-Za-z0-9_-]+$/.test(issued.token));
  const expiry = Date.parse(issued.expires_at);
  requireInput(Number.isFinite(expiry) && expiry > now && expiry - now <= 604800000);
  const bytes = JSON.stringify({ contract_id: "sli.agent-registration.v1", ...configuration,
    enrollment: { kind: "group", token: issued.token, computer_entity_id: computerId, expires_at: new Date(expiry).toISOString() } });
  requireInput(new TextEncoder().encode(bytes).length <= 16384);
  return bytes;
}

export function downloadRegistration(contents: string, computerId: number): void {
  const url = URL.createObjectURL(new Blob([contents], { type: "application/json" }));
  const anchor = document.createElement("a");
  try {
    anchor.href = url; anchor.download = `SLI-Agent-${computerId}.registration.json`;
    document.body.append(anchor); anchor.click();
  } finally { anchor.remove(); URL.revokeObjectURL(url); }
}
