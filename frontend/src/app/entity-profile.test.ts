import { expect, it } from "vitest";
import { entityProfileFields } from "./entity-card";
import { entityProfileValue, shortEntityProfile } from "./entity-profile";
import { formatDateTime } from "../shared/date-time";

it("selects user fields by importance and removes duplicate contact attributes", () => {
  const fields = entityProfileFields([{ context_kind: "entity", attributes: {
    technical_inventory_status: "observed", email: "user@example.invalid", mail: "user@example.invalid",
    password_last_set_utc: "2026-10-01T10:00:00Z", department: "Example unit", enabled: false,
    last_logon_utc: "2026-10-02T10:00:00Z", display_name: "Example account", sam_account_name: "test-account",
    member_of: ["group-a", "group-a", "group-b"], locked_out: true,
  } }]);
  const profile = shortEntityProfile("ad_user", fields, "fallback");
  expect(profile.selected.map((field) => field.key)).toEqual([
    "display_name", "sam_account_name", "enabled", "locked", "department", "last_logon", "password_last_set", "groups_count",
  ]);
  expect(profile.technical.map((field) => field.key)).toEqual(["technical_inventory_status", "mail"]);
  const format = (value: string) => formatDateTime(value, "UTC");
  expect(entityProfileValue("enabled", false, format)).toBe("Отключено");
  expect(entityProfileValue("locked", true, format)).toBe("Да");
  expect(entityProfileValue("last_logon", "2026-10-02T10:00:00Z", format)).toBe(format("2026-10-02T10:00:00Z"));
  expect(entityProfileValue("groups_count", ["a", "a", "b"], format)).toBe("2");
});

it("uses separate computer and group profiles without dropping technical attributes", () => {
  const fields = entityProfileFields([{ context_kind: "entity", attributes: {
    display_name: "Example object", operating_system: "Example OS", enabled: true,
    distinguished_name: "CN=Example,OU=Devices,DC=example,DC=invalid", group_category: "Security", group_scope: "Global", member_count: 4,
  } }]);
  const computer = shortEntityProfile("ad_computer", fields, "fallback");
  expect(computer.selected.map((field) => field.key)).toEqual(["display_name", "operating_system", "enabled", "ou"]);
  expect(computer.selected.find((field) => field.key === "ou")?.value).toBe("OU=Devices,DC=example,DC=invalid");
  expect(computer.technical.some((field) => field.key === "distinguished_name")).toBe(true);
  expect(shortEntityProfile("ad_group", fields, "fallback").selected.map((field) => field.key)).toEqual(["display_name", "group_category", "group_scope", "members_count"]);
  expect(shortEntityProfile("ad_group", fields, "fallback").selected.at(-1)?.value).toBe(4);
});

it("keeps distinct alias values as technical attributes and never infers a zero count", () => {
  const fields = entityProfileFields([{ context_kind: "entity", attributes: { sam_account_name: "test-account", user_principal_name: "test-account@example.invalid" } }]);
  const profile = shortEntityProfile("ad_user", fields, "Example account");
  expect(profile.technical.find((field) => field.key === "user_principal_name")?.value).toBe("test-account@example.invalid");
  expect(profile.selected.find((field) => field.key === "groups_count")?.value).toBeNull();
  expect(entityProfileValue("ou", "OU=Devices,OU=Test unit,DC=example,DC=invalid", String)).toBe("Test unit / Devices");
  expect(entityProfileValue("group_category", "Security", String)).toBe("Безопасность");
  expect(entityProfileValue("group_scope", "DomainLocal", String)).toBe("Локальная в домене");
});
