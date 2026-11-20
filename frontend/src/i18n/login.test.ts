// @vitest-environment jsdom
import { fireEvent, waitFor } from "@testing-library/dom";
import { existsSync, readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { en } from "./en";
import { ru } from "./ru";
import { getLocale, LOCALE_STORAGE_KEY, localeRuntime, setLocale } from "./index";
import { setTheme, storedTheme, THEME_STORAGE_KEY } from "../app/theme";

const web = existsSync("web/app/login.html") ? "web/app" : "../web/app";
const html = readFileSync(`${web}/login.html`, "utf8");
const script = readFileSync(`${web}/sli-login.js`, "utf8");
const css = readFileSync(`${web}/sli-login.css`, "utf8");

function loadLogin() {
  const parsed = new DOMParser().parseFromString(html, "text/html");
  document.head.innerHTML = parsed.head.innerHTML;
  const style = document.createElement("style");
  style.textContent = css;
  document.head.append(style);
  document.body.innerHTML = parsed.body.innerHTML;
  for (const attribute of parsed.documentElement.attributes) {
    document.documentElement.setAttribute(attribute.name, attribute.value);
  }
  window.eval(script);
}

function choose(id: string, value: string) {
  const select = document.getElementById(id) as HTMLSelectElement;
  expect(select).not.toBeNull();
  select.value = value;
  fireEvent.change(select);
}

beforeEach(() => {
  localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
});
afterEach(() => {
  document.body.innerHTML = "";
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  localStorage.clear();
});

describe("standalone login preferences", () => {
  it("shares the language preference while preserving the application's light theme", async () => {
    vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
    setLocale("en");
    setTheme("light");
    loadLogin();
    expect(document.documentElement.lang).toBe("en");
    expect(getComputedStyle(document.documentElement).colorScheme).toBe("dark");
    expect(getComputedStyle(document.documentElement).getPropertyValue("--sli-text")).toBe("#f7f9fd");
    expect(document.querySelector("h1")?.textContent).toBe("Sign in");
    expect(document.getElementById("sli-theme")).toBeNull();
    expect(document.querySelectorAll(".sli-preferences select")).toHaveLength(1);
    choose("sli-locale", "ru");
    expect(localStorage.getItem(LOCALE_STORAGE_KEY)).toBe("ru");
    expect(document.querySelector("h1")?.textContent).toBe("Вход в систему");
    expect(storedTheme()).toBe("light");
    vi.resetModules();
    expect((await import("./index")).getLocale()).toBe("ru");
    setLocale("ru");
    expect(getLocale()).toBe("ru");
  });

  it.each(["ru", "en"] as const)("uses canonical %s translations for text and accessible attributes", (locale) => {
    localStorage.setItem(LOCALE_STORAGE_KEY, locale);
    loadLogin();
    const dictionary: Record<string, string> = locale === "en" ? en : ru;
    expect(document.documentElement.lang).toBe(locale);
    for (const [marker, attribute] of [["data-i18n", null], ["data-i18n-placeholder", "placeholder"], ["data-i18n-aria-label", "aria-label"]] as const) {
      const elements = document.querySelectorAll(`[${marker}]`);
      expect(elements.length).toBeGreaterThan(0);
      for (const element of elements) {
        const key = element.getAttribute(marker)!;
        expect(dictionary[key], key).toBeDefined();
        expect(attribute ? element.getAttribute(attribute) : element.textContent, key).toBe(dictionary[key]);
      }
    }
    expect(document.title).toBe(dictionary["login.documentTitle"]);
    expect(document.getElementById("sli-transport-note")?.textContent).toBe(dictionary["login.transport.http"]);
  });

  it.each([null, "light", "dark", "unsupported"])("keeps login dark without changing stored theme %s", (theme) => {
    localStorage.setItem(LOCALE_STORAGE_KEY, "unsupported");
    if (theme !== null) localStorage.setItem(THEME_STORAGE_KEY, theme);
    loadLogin();
    expect(document.documentElement.lang).toBe("ru");
    expect(getComputedStyle(document.documentElement).colorScheme).toBe("dark");
    expect(getComputedStyle(document.documentElement).getPropertyValue("--sli-text")).toBe("#f7f9fd");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe(theme);
  });

  it("keeps preferences usable when storage is blocked", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new Error("blocked"); });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("blocked"); });
    vi.spyOn(Storage.prototype, "removeItem").mockImplementation(() => { throw new Error("blocked"); });
    loadLogin();
    choose("sli-locale", "en");
    expect(document.querySelector("h1")?.textContent).toBe("Sign in");
    expect(getComputedStyle(document.documentElement).colorScheme).toBe("dark");
  });
});

describe("login form translations", () => {
  it("sends the optional console code only in the login body and clears it after failure", async () => {
    loadLogin();
    const fetchMock = vi.fn().mockResolvedValue({ ok: false, status: 401, json: async () => ({ error: "invalid_credentials" }) });
    vi.stubGlobal("fetch", fetchMock);
    (document.getElementById("username") as HTMLInputElement).value = "owner";
    (document.getElementById("password") as HTMLInputElement).value = "synthetic-password";
    const recovery = document.getElementById("recovery-code") as HTMLInputElement;
    expect(recovery).not.toBeNull();
    expect(recovery.type).toBe("password");
    expect(recovery.autocomplete).toBe("off");
    recovery.value = "synthetic-console-code";
    fireEvent.submit(document.querySelector("form")!);
    await waitFor(() => expect(recovery.value).toBe(""));
    expect(JSON.parse(fetchMock.mock.calls[0][1].body).recovery_code).toBe("synthetic-console-code");
    expect(localStorage.getItem("recovery_code")).toBeNull();
    fireEvent.submit(document.querySelector("form")!);
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).not.toHaveProperty("recovery_code");
  });

  it.each(["ru", "en"] as const)("translates network failures and timeouts in %s", async (locale) => {
    localStorage.setItem(LOCALE_STORAGE_KEY, locale);
    loadLogin();
    const dictionary = locale === "en" ? en : ru;
    const fetchMock = vi.fn().mockRejectedValueOnce(new TypeError("test network failure"))
      .mockRejectedValueOnce(new DOMException("test timeout", "AbortError"));
    vi.stubGlobal("fetch", fetchMock);
    (document.getElementById("username") as HTMLInputElement).value = "test-account";
    (document.getElementById("password") as HTMLInputElement).value = "test-only-password";
    fireEvent.submit(document.querySelector("form")!);
    await waitFor(() => expect(document.getElementById("sli-login-message")?.textContent).toBe(dictionary["login.error.generic"]));
    fireEvent.submit(document.querySelector("form")!);
    await waitFor(() => expect(document.getElementById("sli-login-message")?.textContent).toBe(dictionary["login.error.timeout"]));
  });

  it("preserves busy state and the current request when switching language", async () => {
    loadLogin();
    let respond!: (response: unknown) => void;
    const fetchMock = vi.fn(() => new Promise((resolve) => { respond = resolve; }));
    vi.stubGlobal("fetch", fetchMock);
    (document.getElementById("username") as HTMLInputElement).value = "test-account";
    (document.getElementById("password") as HTMLInputElement).value = "test-only-password";
    fireEvent.submit(document.querySelector("form")!);
    expect(document.getElementById("sli-login-submit")?.textContent).toContain(ru["login.busy"]);
    choose("sli-locale", "en");
    expect(document.getElementById("sli-login-submit")?.textContent).toContain(en["login.busy"]);
    expect((document.getElementById("sli-login-submit") as HTMLButtonElement).disabled).toBe(true);
    expect(fetchMock).toHaveBeenCalledOnce();
    respond({ ok: false, status: 401, json: async () => ({ error: "invalid_credentials" }) });
    await waitFor(() => expect(document.getElementById("sli-login-message")?.textContent).toBe(en["login.error.credentials"]));
    expect((document.getElementById("sli-login-submit") as HTMLButtonElement).disabled).toBe(false);
  });

  it("updates validation and password visibility labels when switching languages", () => {
    loadLogin();
    const form = document.querySelector("form")!;
    fireEvent.submit(form);
    expect(document.getElementById("sli-login-message")?.textContent).toBe("Введите логин и пароль.");
    choose("sli-locale", "en");
    expect(document.getElementById("sli-login-message")?.textContent).toBe("Enter your username and password.");
    fireEvent.click(document.querySelector(".sli-password-toggle")!);
    expect(document.querySelector(".sli-password-toggle")?.getAttribute("aria-label")).toBe("Hide password");
    choose("sli-locale", "ru");
    expect(document.querySelector(".sli-password-toggle")?.getAttribute("aria-label")).toBe("Скрыть пароль");
    expect((document.getElementById("password") as HTMLInputElement).type).toBe("text");
  });

  it.each([
    [401, { error: "invalid_credentials" }, "login.error.credentials"],
    [429, { error: "login_temporarily_locked", retry_after_seconds: 2.1 }, "login.error.retryAfter"],
    [429, { error: "login_temporarily_locked" }, "login.error.locked"],
    [403, { error: "secure_transport_required" }, "login.error.https"],
    [403, { error: "authentication_not_enabled" }, "login.error.disabled"],
    [503, {}, "login.error.unavailable"],
    [400, {}, "login.error.generic"],
  ] as const)("translates server error %s and preserves the submission contract", async (status, payload, key) => {
    localStorage.setItem(LOCALE_STORAGE_KEY, "en");
    loadLogin();
    const fetchMock = vi.fn().mockResolvedValue({ ok: false, status, json: async () => payload });
    vi.stubGlobal("fetch", fetchMock);
    (document.getElementById("username") as HTMLInputElement).value = " test-account ";
    (document.getElementById("password") as HTMLInputElement).value = "test-only-password";
    fireEvent.submit(document.querySelector("form")!);
    await waitFor(() => expect(document.getElementById("sli-login-message")?.textContent).toBe(en[key].replace("{seconds}", "3")));
    const [path, request] = fetchMock.mock.calls[0];
    expect(path).toBe("/api/auth/login");
    expect(request.method).toBe("POST");
    expect(request.credentials).toBe("same-origin");
    expect(request.headers["Accept-Language"]).toBe("en");
    expect(JSON.parse(request.body)).toEqual({ username: "test-account", password: "test-only-password", remember: true });
    expect(Object.keys(localStorage)).toEqual([LOCALE_STORAGE_KEY]);
    choose("sli-locale", "ru");
    expect(document.getElementById("sli-login-message")?.textContent).toBe(ru[key].replace("{seconds}", "3"));
  });

  it.each(["ru", "en"] as const)("resolves coded login messages in %s and re-resolves them on language changes", async (locale) => {
    localStorage.setItem(LOCALE_STORAGE_KEY, locale);
    loadLogin();
    const fetchMock = vi.fn().mockResolvedValue({ ok: false, status: 429, json: async () => ({
      error: "login_temporarily_locked", retry_after_seconds: 20,
      message: { code: "login.error.retryAfter", params: { seconds: 3 }, text: "other locale" },
    }) });
    vi.stubGlobal("fetch", fetchMock);
    (document.getElementById("username") as HTMLInputElement).value = "synthetic-user";
    (document.getElementById("password") as HTMLInputElement).value = "fixture-placeholder";
    fireEvent.submit(document.querySelector("form")!);
    const dictionary = locale === "ru" ? ru : en;
    await waitFor(() => expect(document.getElementById("sli-login-message")?.textContent).toBe(dictionary["login.error.retryAfter"].replace("{seconds}", "3")));
    expect(fetchMock.mock.calls[0][1].headers["Accept-Language"]).toBe(locale);
    const next = locale === "ru" ? "en" : "ru";
    choose("sli-locale", next);
    expect(document.getElementById("sli-login-message")?.textContent).toBe((next === "ru" ? ru : en)["login.error.retryAfter"].replace("{seconds}", "3"));
  });

  it.each(["login.error.origin", "login.error.authenticationRequired"] as const)("resolves %s from the canonical catalog", async (code) => {
    localStorage.setItem(LOCALE_STORAGE_KEY, "en");
    loadLogin();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 403, json: async () => ({ message: { code, params: {} } }) }));
    (document.getElementById("username") as HTMLInputElement).value = "synthetic-user";
    (document.getElementById("password") as HTMLInputElement).value = "fixture-placeholder";
    fireEvent.submit(document.querySelector("form")!);
    await waitFor(() => expect(document.getElementById("sli-login-message")?.textContent).toBe(en[code]));
    choose("sli-locale", "ru");
    expect(document.getElementById("sli-login-message")?.textContent).toBe(ru[code]);
  });

  it("keeps the legacy fallback when a newer server sends an unknown login code", async () => {
    loadLogin();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 401, json: async () => ({
      error: "invalid_credentials", message: { code: "future.code", params: {}, text: "future text" },
    }) }));
    (document.getElementById("username") as HTMLInputElement).value = "synthetic-user";
    (document.getElementById("password") as HTMLInputElement).value = "fixture-placeholder";
    fireEvent.submit(document.querySelector("form")!);
    await waitFor(() => expect(document.getElementById("sli-login-message")?.textContent).toBe(ru["login.error.credentials"]));
  });
});
