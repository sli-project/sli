// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildNavigation, isActivePath, reportWorkspace, type NavAccess } from "./navigation";
import fixture from "../../../config/navigation_v3.json";
import type { NavigationRegistryDto } from "../api/report-v2-types";
import { localeRuntime, setLocale } from "../i18n";

const registry = fixture as NavigationRegistryDto;
const entries = registry.sections.flatMap((section) => section.groups.flatMap((group) => group.entries));
const access = (reports: string[], capabilities: string[] = []): NavAccess => ({ reports: new Set(reports), capabilities: new Set(capabilities) });
const allAccess = access(entries.flatMap((entry) => entry.reports ?? []), entries.flatMap((entry) => entry.capabilities ?? []));
const items = (sections: ReturnType<typeof buildNavigation>) => sections.flatMap((section) => section.groups.flatMap((group) => group.items));
const workPaths = ["/", "/report/security.problems", "/report/security.events.chains", "/report/events.journal", "/report/ad.infrastructure", "/report/ad.users.v2", "/report/ad.computers.v6", "/report/ad.gpo.v2", "/report/file-audit.actions"];
const adminPaths = ["/admin/status", "/agents", "/access", "/notifications", "/operations", "/settings", "/plugins"];

afterEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  setLocale("ru");
  vi.restoreAllMocks();
});

describe("buildNavigation for beta", () => {
  it("keeps preview modules off both menus unless the server opts in", () => {
    const defaultPaths = items(buildNavigation(allAccess, registry)).map((item) => item.path);
    const previewPaths = items(buildNavigation(allAccess, { ...registry, modules_preview: true })).map((item) => item.path);
    expect(defaultPaths).toContain("/report/file-audit.actions");
    expect(previewPaths.filter(path => path.startsWith("/report/file-audit."))).toEqual(["/report/file-audit.actions"]);
    for (const path of ["/report/workstations.overview", "/report/vpn.connections",
      "/admin/plugins/sli.file-audit", "/admin/plugins/sli.workstations", "/admin/plugins/sli.remote-access", "/admin/plugins/sli.sigma"]) {
      expect(defaultPaths).not.toContain(path);
      expect(previewPaths).toContain(path);
    }
  });

  it.each([
    ["ru", ["Главная", "Проблемы", "Изменения в домене", "Журнал событий", "Состояние AD", "Пользователи", "Компьютеры", "Групповые политики", "Файловые серверы"], ["Состояние системы", "Агенты", "Пользователи и роли", "Оповещения", "Хранение", "Язык и время", "Все плагины"]],
    ["en", ["Home", "Problems", "Domain changes", "Event journal", "AD state", "Users", "Computers", "Group policies", "File servers"], ["System status", "Agents", "Users & roles", "Notifications", "Storage", "Language & time", "All plugins"]],
  ] as const)("shows only the ordered beta destinations in %s even with all grants", (locale, workLabels, adminLabels) => {
    vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
    setLocale(locale);
    const nav = buildNavigation(allAccess, registry);
    const work = items(nav.filter((section) => section.id !== "admin"));
    const admin = items(nav.filter((section) => section.id === "admin"));
    expect(work.map((item) => item.path)).toEqual(workPaths);
    expect(admin.map((item) => item.path)).toEqual(adminPaths);
    expect(work.map((item) => item.label)).toEqual(workLabels);
    expect(admin.map((item) => item.label)).toEqual(adminLabels);
    expect(nav.every((section) => section.groups.length && section.groups.every((group) => group.items.length))).toBe(true);
  });

  it("opens the only granted File Servers view from its single menu item", () => {
    const links = items(buildNavigation(access(["file-audit.permissions"]), registry));
    expect(links.filter(link => link.id === "file-audit").map(link => link.path)).toEqual(["/report/file-audit.permissions"]);
    expect(isActivePath("/report/file-audit.permissions", "/report/file-audit.permission-changes")).toBe(true);
  });

  it("keeps beta order when the registry is reordered and excludes unlisted additions", () => {
    const reordered = { ...registry, sections: [...registry.sections].reverse().map((section) => ({ ...section,
      groups: [...section.groups].reverse().map((group) => ({ ...group, entries: [...group.entries].reverse() })),
    })) };
    reordered.sections[0].groups[0].entries.push({ id: "extra", label: "shell.nav.workspace", path: "/extra", icon: "grid", always: true });
    expect(items(buildNavigation(allAccess, reordered)).map((item) => item.path)).toEqual([...workPaths, ...adminPaths]);
  });

  it("waits for the registry and shows only home without grants", () => {
    expect(buildNavigation(allAccess)).toEqual([]);
    expect(items(buildNavigation(access([]), registry)).map((item) => item.path)).toEqual(["/"]);
  });

  it("keeps existing report and capability visibility checks", () => {
    expect(items(buildNavigation(access(["security.queue"]), registry)).map((item) => item.id)).toContain("problems");
    expect(items(buildNavigation(access([], ["events.view"]), registry)).map((item) => item.id)).toContain("events");
    expect(items(buildNavigation(access(["notifications.deliveries"]), registry)).map((item) => item.path)).toEqual(["/", "/notifications"]);
    expect(items(buildNavigation(access([], ["access.manage"]), registry))).toContainEqual(expect.objectContaining({ id: "agents", path: "/agents" }));
  });

  it("hides disabled AD while keeping independently enabled GPO and no empty sections", () => {
    const nav = buildNavigation(access(["ad.users.v2", "ad.gpo.v2", "vpn.audit"]), { ...registry, enabled_plugins: ["sli.gpo"] });
    expect(items(nav).map((item) => item.path)).toEqual(["/", "/report/ad.gpo.v2"]);
    expect(nav.map((section) => section.id)).toEqual(["overview", "group-policies"]);
  });

  it("preserves implemented status destinations for scoped users", () => {
    expect(items(buildNavigation(access([], ["access.manage"]), registry))).toContainEqual(expect.objectContaining({ id: "admin-status", path: "/admin/status", label: "Состояние системы" }));
    for (const grant of ["watch.registry", "decoys.registry"]) {
      expect(items(buildNavigation(access([grant]), registry)).map((item) => item.path)).toEqual(["/", "/admin/status"]);
    }
  });
});

describe("reportWorkspace", () => {
  it.each([
    ["ad.computers.v6", ["ad.computers.v6", "ad.computer-logons"]],
    ["vpn.connections", ["vpn.connections"]],
  ] as const)("uses the available report views for %s", (reportKey, keys) => {
    expect(reportWorkspace(reportKey)?.views?.map((view) => view.report_key)).toEqual(keys);
  });
  it("returns no workspace for standalone or unknown reports", () => {
    expect(reportWorkspace("ad.users.v2")).toBeUndefined();
    expect(reportWorkspace("synthetic.unknown")).toBeUndefined();
  });
});

describe("isActivePath", () => {
  it("matches sub-pages and keeps home exact", () => {
    expect(isActivePath("/objects", "/objects/ad_user/42")).toBe(true);
    expect(isActivePath("/", "/objects")).toBe(false);
    expect(isActivePath("/", "/")).toBe(true);
    expect(isActivePath("/events", "/events-archive")).toBe(false);
  });
});
