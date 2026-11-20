// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { getLocale, localeRuntime, setLocale, t } from "../../i18n";
import { setupSourceName } from "./setup-source-labels";

afterEach(() => vi.restoreAllMocks());
it.each(["ru", "en"] as const)("translates builtin source names by id and preserves external values (%s)", (locale) => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  const previous = getLocale(); setLocale(locale);
  try {
    for (const [id, key] of [
      ["sli.windows.ad-context", "setup.source.name.adContext"],
      ["sli.windows.ad-dc", "setup.source.name.domainController"],
      ["sli.windows.file-audit", "setup.source.name.fileAudit"],
      ["sli.windows.vpn-radius", "setup.source.name.vpnRadius"],
      ["sli.windows.workstations", "setup.source.name.workstations"],
    ] as const) {
      expect(setupSourceName({ pack_id: id, display_name: "Old system fallback" })).toBe(t(key));
    }
    for (const id of ["custom.pack", "toString", "__proto__"]) {
      expect(setupSourceName({ pack_id: id, display_name: "Исходное имя" })).toBe("Исходное имя");
    }
  } finally { setLocale(previous); }
});
