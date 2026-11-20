// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { registrationConfiguration, registrationFile, downloadRegistration } from "./registration-file";

const now = Date.parse("2030-01-01T12:00:00Z");
const issued = { token: "g".repeat(43), expires_at: "2030-01-01T13:00:00Z" };
afterEach(() => vi.restoreAllMocks());
it("exports only the narrow native envelope with the selected computer", () => {
  const value = JSON.parse(registrationFile("HTTPS://SLI.example.test:443/", "A".repeat(64), issued, 7, now));
  expect(value).toEqual({ contract_id: "sli.agent-registration.v1", server_url: "https://sli.example.test/", ca_sha256: "a".repeat(64),
    enrollment: { kind: "group", token: issued.token, computer_entity_id: 7, expires_at: "2030-01-01T13:00:00.000Z" } });
});
// Concatenation preserves the malformed authority backslash and avoids a static host guard false positive.
it.each(["", "http://sli.example.test", "https://user:password@sli.example.test", "https://sli.example.test/path/../", "https://sli.example.test/?", "https://sli.example.test/#", "https://sli.example.test" + "\\x", "https://sli.example.test:0", "https://sli.example.test:65536"])("rejects an unsupported origin: %s", (origin) => {
  expect(() => registrationConfiguration(origin, "a".repeat(64))).toThrow("agent_registration_invalid");
});
it.each(["", "x".repeat(64), "a".repeat(63), "SHA256:" + "a".repeat(64)])("rejects malformed public fingerprints", (pin) => {
  expect(() => registrationConfiguration("https://sli.example.test", pin)).toThrow("agent_registration_invalid");
});
it.each([0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1])("rejects invalid directory identities", (id) => {
  expect(() => registrationFile("https://sli.example.test", "a".repeat(64), issued, id, now)).toThrow();
});
it.each(["2030-01-01T12:00:00Z", "2030-01-08T12:00:00.001Z", "broken"])("rejects expired or unsupported lifetimes", (expires_at) => {
  expect(() => registrationFile("https://sli.example.test", "a".repeat(64), { ...issued, expires_at }, 7, now)).toThrow();
});
it("rejects malformed secret without including it in the error", () => {
  expect(() => registrationFile("https://sli.example.test", "a".repeat(64), { ...issued, token: issued.token + "\n" }, 7, now)).toThrow("agent_registration_invalid");
});
it.each([false, true])("revokes the local object URL even when the click fails (%s)", (fails) => {
  const create = vi.fn(() => "blob:synthetic-local-id"), revoke = vi.fn();
  Object.defineProperty(URL, "createObjectURL", { configurable: true, value: create });
  Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revoke });
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => { if (fails) throw new Error("synthetic-click"); });
  const run = () => downloadRegistration("synthetic-file", 7);
  if (fails) expect(run).toThrow(); else run();
  expect(click).toHaveBeenCalledOnce(); expect(revoke).toHaveBeenCalledExactlyOnceWith("blob:synthetic-local-id");
  expect(document.querySelector("a[download]")).toBeNull();
});

function originOfLength(length: number, slash = true) {
  return "https://" + "a".repeat(length - 8 - Number(slash)) + (slash ? "/" : "");
}
it.each([4094, 4095])("native origin bound: accepts %i serialized UTF-16 units", (length) => {
  const value = JSON.parse(registrationFile(originOfLength(length), "a".repeat(64), issued, 7, now));
  expect(value.server_url).toHaveLength(length);
});
it.each([4096, 4097])("native origin bound: rejects %i input UTF-16 units", (length) => {
  expect(() => registrationConfiguration(originOfLength(length), "a".repeat(64))).toThrow("agent_registration_invalid");
});
it("native origin bound: accepts normalization to the last allowed unit", () => {
  expect(registrationConfiguration(originOfLength(4094, false), "a".repeat(64)).server_url).toHaveLength(4095);
});
it("native origin bound: rejects normalization that adds a 4096th unit", () => {
  expect(() => registrationFile(originOfLength(4095, false), "a".repeat(64), issued, 7, now)).toThrow("agent_registration_invalid");
});
it("native origin bound: trims before measuring like the native reader", () => {
  expect(registrationConfiguration(" \t" + originOfLength(4095) + "\r\n", "a".repeat(64)).server_url).toHaveLength(4095);
});
