// @vitest-environment jsdom
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { en } from "./en";
import { ru } from "./ru";

afterEach(() => { document.body.replaceChildren(); localStorage.clear(); vi.restoreAllMocks(); });

describe("AI draft authority label", () => {
  it("identifies AI output as a draft in both locales", () => {
    expect(ru["reports.ai.draft_only"]).toBe("черновик ИИ, не решение");
    expect(en["reports.ai.draft_only"]).toBe("AI draft, not a decision");
  });

  it("labels server HTML after the head bootstrap has run, using the saved language", () => {
    localStorage.setItem("sli.lang", "en");
    vi.spyOn(document, "readyState", "get").mockReturnValue("loading");
    const source = readFileSync(resolve(import.meta.dirname, "../../../server-dotnet/src/Sli.Server/Legacy/report-template.html"), "utf8");
    const bootstrap = source.match(/<script>([\s\S]*?)<\/script>/)?.[1];
    expect(bootstrap).toBeDefined();
    window.eval(bootstrap!);
    const label = document.createElement("span");
    label.setAttribute("data-ai-draft-label-ru", ru["reports.ai.draft_only"]);
    label.setAttribute("data-ai-draft-label-en", en["reports.ai.draft_only"]);
    label.textContent = ru["reports.ai.draft_only"];
    document.body.append(label);
    document.dispatchEvent(new Event("DOMContentLoaded"));
    expect(label.textContent).toBe(en["reports.ai.draft_only"]);
  });
});
