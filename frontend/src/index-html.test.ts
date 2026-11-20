import { readFileSync } from "node:fs";
import { expect, it } from "vitest";

it("index.html объявляет значок вкладки, чтобы браузер не запрашивал отсутствующий /favicon.ico (404 в консоли)", () => {
  const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
  expect(html).toMatch(/<link rel="icon" href="data:image\/svg\+xml,/);
});
