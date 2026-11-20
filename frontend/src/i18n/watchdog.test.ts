// @vitest-environment jsdom
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ru } from "./ru";
import { en } from "./en";

const source = resolve(import.meta.dirname, "../../../scripts/maintenance/watchdog");
const app = readFileSync(`${source}/dashboard/app.js`, "utf8").replaceAll("export ", "");
// Exercise the installed standalone panel, which is outside Vite's source root.
const { mount } = new Function(`${app}\nreturn { mount };`)();
const messages = JSON.parse(readFileSync(`${source}/dashboard/ru.json`, "utf8"));
const controllers: Array<{ destroy(): void }> = [];
afterEach(() => { for (const item of controllers.splice(0)) item.destroy(); document.body.replaceChildren(); });

describe("watchdog network status", () => {
  it("keeps installed text aligned with product translations", () => {
    expect(messages.networkOffline).toBe(ru["operations.watchdog.networkOffline"]);
    const english = JSON.parse(readFileSync(`${source}/dashboard/en.json`, "utf8"));
    expect(english.networkOffline).toBe(en["operations.watchdog.networkOffline"]);
  });
  it.each(["offline", "online", "unknown"])("renders the offline banner only for %s", async network => {
    const root = document.createElement("main"); document.body.append(root);
    const controller = mount(root, messages, async () => ({ schema_version: 1, last_pass: Date.now() / 1000, network }));
    controllers.push(controller);
    await controller.refresh();
    await Promise.resolve();
    expect(root.textContent?.includes(messages.networkOffline)).toBe(network === "offline");
    if (network === "offline") expect(root.querySelector('[role="status"]')?.textContent).toContain(messages.networkOffline);
  });
});
