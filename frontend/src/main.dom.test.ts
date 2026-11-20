// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";

vi.mock("./product-main", () => ({}));
vi.mock("./sli-v4/fixture-main", () => ({}));

afterEach(() => { document.head.replaceChildren(); vi.resetModules(); });

it("makes the server nonce available to generated accessibility styles", async () => {
  const script = document.createElement("script");
  script.nonce = "synthetic-csp-nonce";
  document.head.append(script);
  await import("./main");
  expect(document.querySelector<HTMLMetaElement>('meta[property="csp-nonce"]')?.nonce).toBe(script.nonce);
});

it("keeps a server-provided nonce and needs none on the local dev server", async () => {
  await import("./main");
  expect(document.querySelector('meta[property="csp-nonce"]')).toBeNull();
  vi.resetModules();
  const script = document.createElement("script"); script.nonce = "synthetic-script-nonce";
  const meta = document.createElement("meta"); meta.setAttribute("property", "csp-nonce"); meta.nonce = "synthetic-server-nonce";
  document.head.append(script, meta);
  await import("./main");
  expect(document.querySelector<HTMLMetaElement>('meta[property="csp-nonce"]')?.nonce).toBe("synthetic-server-nonce");
});
