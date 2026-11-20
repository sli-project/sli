// @vitest-environment jsdom
import { StrictMode } from "react";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { UI_API, type PluginHostApi, type PluginUiDescriptor, type PluginUiModule } from "./contract";

const mocks = vi.hoisted(() => ({ descriptor: vi.fn(), module: vi.fn() }));
vi.mock("./loader", async (original) => ({ ...await original<typeof import("./loader")>(), loadDescriptor: mocks.descriptor, loadModule: mocks.module }));
import { PluginHost } from "./PluginHost";
import { PluginUiError } from "./loader";

const descriptor: PluginUiDescriptor = { plugin_id: "sli.remote-access", ui_api: UI_API, version: "1.0.0",
  routes: ["/extensions/sli.remote-access/accounts"], entry: { path: "entry.js", sha256: "a".repeat(64) }, required_capabilities: ["reports.catalog"] };
const props = { pluginId: descriptor.plugin_id, route: descriptor.routes[0], sessionKey: "session-1", capabilities: ["reports.catalog"], navigate: vi.fn() };
beforeEach(() => { mocks.descriptor.mockResolvedValue(descriptor); vi.spyOn(console, "error").mockImplementation(() => undefined); });
afterEach(() => { cleanup(); vi.resetAllMocks(); vi.restoreAllMocks(); });

it("mounts once and removes owned listeners, timers and cache on unmount", async () => {
  const listener = vi.fn();
  const tick = vi.fn();
  const unmount = vi.fn();
  const onCleanup = vi.fn();
  const mount = vi.fn((container: HTMLElement, api: PluginHostApi) => {
    api.resources.listen(window, "fixture-plugin-event", listener);
    api.resources.interval(tick, 60_000);
    api.resources.timeout(tick, 60_000);
    void api.cache.query(["rows"], async () => 1).catch(() => undefined);
    api.render(container, api.react.createElement("p", null, "Fixture plugin"));
  });
  mocks.module.mockResolvedValue({ createPlugin: () => ({ mount, unmount }) });
  const view = render(<PluginHost {...props} onCleanup={onCleanup}/>);
  await screen.findByText("Fixture plugin");
  window.dispatchEvent(new Event("fixture-plugin-event"));
  expect(listener).toHaveBeenCalledTimes(1);
  view.unmount();
  expect(mount).toHaveBeenCalledTimes(1);
  expect(unmount).toHaveBeenCalledTimes(1);
  expect(onCleanup).toHaveBeenCalledWith({ listeners: 0, timers: 0, queries: 0, errors: 0 });
  window.dispatchEvent(new Event("fixture-plugin-event"));
  expect(listener).toHaveBeenCalledTimes(1);
  expect(tick).not.toHaveBeenCalled();
});

it.each(["mount", "render", "listener"])("contains %s errors and cleans the failing plugin", async (kind) => {
  const onCleanup = vi.fn();
  const unmount = vi.fn();
  const Broken = () => { throw new Error("fixture render failure"); };
  mocks.module.mockResolvedValue({ createPlugin: () => ({ unmount, mount: (container: HTMLElement, api: PluginHostApi) => {
    api.resources.interval(() => undefined, 60_000);
    if (kind === "mount") throw new Error("fixture mount failure");
    if (kind === "listener") api.resources.listen(window, "fixture-failure", () => { throw new Error("fixture callback failure"); });
    api.render(container, kind === "render" ? api.react.createElement(Broken) : api.react.createElement("p", null, "Ready"));
  } }) });
  render(<><p>Core still running</p><PluginHost {...props} onCleanup={onCleanup}/></>);
  if (kind === "listener") {
    await screen.findByText("Ready");
    act(() => { window.dispatchEvent(new Event("fixture-failure")); });
  }
  expect((await screen.findByRole("alert")).getAttribute("data-state")).toBe("unavailable");
  expect(screen.getByText("Core still running")).toBeTruthy();
  await waitFor(() => expect(unmount).toHaveBeenCalledTimes(1));
  expect(onCleanup).toHaveBeenCalledWith({ listeners: 0, timers: 0, queries: 0, errors: 0 });
});

it("shows integrity failure without mounting or pretending the report is empty", async () => {
  mocks.module.mockRejectedValue(new PluginUiError("integrity"));
  render(<PluginHost {...props}/>);
  const alert = await screen.findByRole("alert");
  expect(alert.textContent).toContain("не прошли проверку целостности");
  expect(alert.getAttribute("data-state")).toBe("unavailable");
  expect(document.querySelector('[data-state="empty"]')).toBeNull();
});

it("checks route and capabilities before loading executable code", async () => {
  const view = render(<PluginHost {...props} capabilities={[]}/>);
  expect((await screen.findByRole("alert")).getAttribute("data-state")).toBe("denied");
  expect(mocks.module).not.toHaveBeenCalled();
  view.rerender(<PluginHost {...props} route="/settings"/>);
  await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("Некорректный дескриптор"));
  expect(mocks.module).not.toHaveBeenCalled();
});

it("does not mount a late import after navigation away", async () => {
  let resolve!: (module: PluginUiModule) => void;
  mocks.module.mockReturnValue(new Promise<PluginUiModule>((done) => { resolve = done; }));
  const mount = vi.fn();
  const view = render(<PluginHost {...props}/>);
  await waitFor(() => expect(mocks.module).toHaveBeenCalledTimes(1));
  view.unmount();
  await act(async () => { resolve({ createPlugin: () => ({ mount, unmount: vi.fn() }) }); });
  expect(mount).not.toHaveBeenCalled();
  expect(mocks.module.mock.calls[0][1].aborted).toBe(true);
});

it("creates a fresh lifecycle on rights/session change, including under StrictMode", async () => {
  const unmount = vi.fn();
  const createPlugin = vi.fn(() => ({ unmount, mount: (container: HTMLElement, api: PluginHostApi) => {
    api.render(container, api.react.createElement("p", null, "Ready"));
  } }));
  mocks.module.mockResolvedValue({ createPlugin });
  const onCleanup = vi.fn();
  const view = render(<StrictMode><PluginHost {...props} onCleanup={onCleanup}/></StrictMode>);
  await screen.findByText("Ready");
  expect(createPlugin).toHaveBeenCalledTimes(1);
  // Equivalent capabilities arrays must not cause another mount.
  view.rerender(<StrictMode><PluginHost {...props} capabilities={["reports.catalog"]} onCleanup={onCleanup}/></StrictMode>);
  expect(createPlugin).toHaveBeenCalledTimes(1);
  view.rerender(<StrictMode><PluginHost {...props} sessionKey="session-2" onCleanup={onCleanup}/></StrictMode>);
  await waitFor(() => expect(createPlugin).toHaveBeenCalledTimes(2));
  expect(unmount).toHaveBeenCalledTimes(1);
  view.unmount();
  expect(unmount).toHaveBeenCalledTimes(2);
  expect(onCleanup).toHaveBeenCalledTimes(2);
});

it("still releases resources if the plugin's unmount throws", async () => {
  const onCleanup = vi.fn();
  mocks.module.mockResolvedValue({ createPlugin: () => ({
    mount: (container: HTMLElement, api: PluginHostApi) => {
      api.resources.interval(() => undefined, 60_000);
      api.render(container, api.react.createElement("p", null, "Ready"));
    },
    unmount: () => { throw new Error("fixture unmount failure"); },
  }) });
  const view = render(<PluginHost {...props} onCleanup={onCleanup}/>);
  await screen.findByText("Ready");
  view.unmount();
  expect(onCleanup).toHaveBeenCalledWith({ listeners: 0, timers: 0, queries: 0, errors: 1 });
});

it.each(["version", "integrity"])("disposes a mounted plugin on %s change and asks to reload", async (kind) => {
  const unmount = vi.fn();
  const onCleanup = vi.fn();
  mocks.module.mockResolvedValue({ createPlugin: () => ({ unmount, mount: (container: HTMLElement, api: PluginHostApi) => {
    api.resources.interval(() => undefined, 60_000);
    api.render(container, api.react.createElement("p", null, "Old plugin"));
  } }) });
  render(<><p>Core still running</p><PluginHost {...props} onCleanup={onCleanup}/></>);
  await screen.findByText("Old plugin");
  mocks.descriptor.mockResolvedValue(kind === "version" ? { ...descriptor, version: "1.1.0" }
    : { ...descriptor, entry: { ...descriptor.entry, sha256: "b".repeat(64) } });
  act(() => window.dispatchEvent(new Event("focus")));
  await screen.findByRole("button", { name: /Перезагрузить вкладку|Reload tab/ });
  expect(screen.queryByText("Old plugin")).toBeNull();
  expect(screen.getByText("Core still running")).toBeTruthy();
  expect(unmount).toHaveBeenCalledTimes(1);
  expect(onCleanup).toHaveBeenCalledWith({ listeners: 0, timers: 0, queries: 0, errors: 0 });
  expect(mocks.module).toHaveBeenCalledTimes(1);
  act(() => window.dispatchEvent(new Event("focus")));
  expect(unmount).toHaveBeenCalledTimes(1);
});

it("does not mount an entry when its version changed during import", async () => {
  mocks.descriptor.mockResolvedValueOnce(descriptor).mockResolvedValue({ ...descriptor, version: "1.1.0" });
  const createPlugin = vi.fn();
  mocks.module.mockResolvedValue({ createPlugin });
  render(<PluginHost {...props}/>);
  await screen.findByRole("button", { name: /Перезагрузить вкладку|Reload tab/ });
  expect(createPlugin).not.toHaveBeenCalled();
});

it("keeps the mounted plugin when a version recheck returns the same descriptor", async () => {
  const unmount = vi.fn();
  mocks.module.mockResolvedValue({ createPlugin: () => ({ unmount, mount: (container: HTMLElement, api: PluginHostApi) => {
    api.render(container, api.react.createElement("p", null, "Same plugin"));
  } }) });
  render(<PluginHost {...props}/>);
  await screen.findByText("Same plugin");
  act(() => window.dispatchEvent(new Event("focus")));
  await waitFor(() => expect(mocks.descriptor).toHaveBeenCalledTimes(3));
  expect(unmount).not.toHaveBeenCalled();
  expect(screen.getByText("Same plugin")).toBeTruthy();
});
