import { Component, useEffect, useRef, useState, type ComponentType, type ReactNode } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { StateView } from "../design-system/StateView";
import { t } from "../i18n";
import type { PluginUiInstance } from "./contract";
import { loadDescriptor, loadModule, PluginUiError, sameVersion } from "./loader";
import { createScope, type CleanupResult } from "./scope";

type HostProps = {
  pluginId: string;
  route: string;
  /** Changes with identity/rights; never sent to the plugin or the server. */
  sessionKey: string;
  capabilities: readonly string[];
  navigate: (href: string) => void;
  Page?: ComponentType;
  onCleanup?: (result: CleanupResult) => void;
};

function Failure({ error }: { error: unknown }) {
  const code = error instanceof PluginUiError ? error.code : "unavailable";
  if (code === "version") return <StateView state="unavailable" detail={<>
    <p>{t("plugins.ui.versionChanged")}</p>
    <button type="button" onClick={() => window.location.reload()}>{t("plugins.ui.reload")}</button>
  </>}/>;
  const messages = { integrity: "plugins.ui.integrity", unsupported: "plugins.ui.unsupported", denied: "plugins.ui.denied",
    invalid: "plugins.ui.invalid", unavailable: "plugins.ui.unavailable" } as const;
  return <StateView state={code === "denied" ? "denied" : "unavailable"} detail={t(messages[code])}/>;
}

class PluginBoundary extends Component<{ children: ReactNode }, { failed: boolean; error?: unknown }> {
  state: { failed: boolean; error?: unknown } = { failed: false };
  static getDerivedStateFromError(error: unknown) { return { failed: true, error }; }
  render() { return this.state.failed ? <Failure error={this.state.error}/> : this.props.children; }
}

export function PluginHost(props: HostProps) {
  // A boundary cannot carry a previous plugin's failure across route/session changes.
  const key = JSON.stringify([props.pluginId, props.route, props.sessionKey, props.capabilities]);
  return <PluginBoundary key={key}><PluginMount {...props}/></PluginBoundary>;
}

function PluginMount({ pluginId, route, sessionKey, capabilities, navigate, Page, onCleanup }: HostProps) {
  const container = useRef<HTMLDivElement>(null);
  const [scope, setScope] = useState<ReturnType<typeof createScope>>();
  const [content, setContent] = useState<ReactNode>(null);
  const [mounted, setMounted] = useState(false);
  const [failure, setFailure] = useState<{ error: unknown }>();
  // Props are part of the outer boundary key; callbacks remain stable for this
  // mount. StrictMode disposes the first pending load before starting another.
  const callbacks = useRef({ navigate, Page, onCleanup });
  useEffect(() => {
    const controller = new AbortController();
    let disposed = false;
    let instance: PluginUiInstance | undefined;
    let owned: ReturnType<typeof createScope> | undefined;
    let cancelWatch = () => {};
    const dispose = () => {
      if (disposed) return;
      disposed = true;
      controller.abort();
      cancelWatch();
      let errors = 0;
      try { instance?.unmount(); } catch { errors++; }
      if (owned) {
        const result = owned.dispose();
        callbacks.current.onCleanup?.({ ...result, errors: result.errors + errors });
      }
    };
    void (async () => {
      const descriptor = await loadDescriptor(pluginId, controller.signal);
      if (disposed) return;
      if (!descriptor.routes.includes(route)) throw new PluginUiError("invalid");
      if (descriptor.required_capabilities.some((capability) => !capabilities.includes(capability))) throw new PluginUiError("denied");
      const module = await loadModule(descriptor, controller.signal);
      if (disposed) return;
      const assertVersion = async () => {
        const next = await loadDescriptor(pluginId, controller.signal);
        if (!sameVersion(descriptor, next)) throw new PluginUiError("version");
      };
      // Recheck after ESM import as well as while mounted. Never mount an old
      // entry against a descriptor which changed during the download.
      await assertVersion();
      if (disposed) return;
      if (!container.current) throw new PluginUiError("unavailable");
      owned = createScope(descriptor, sessionKey, container.current, setContent,
        (error) => { dispose(); setFailure({ error: error ?? new PluginUiError("unavailable") }); },
        callbacks.current.navigate, callbacks.current.Page);
      setScope(owned);
      instance = module.createPlugin();
      if (!instance || typeof instance.mount !== "function" || typeof instance.unmount !== "function") throw new PluginUiError("invalid");
      instance.mount(container.current, owned.api);
      if (disposed) return;
      setMounted(true);
      let checking = false;
      const check = () => {
        if (disposed || checking) return;
        checking = true;
        void assertVersion().catch((error: unknown) => {
          if (!disposed) { dispose(); setFailure({ error }); }
        }).finally(() => { checking = false; });
      };
      const timer = window.setInterval(check, 30_000);
      window.addEventListener("focus", check);
      document.addEventListener("visibilitychange", check);
      cancelWatch = () => {
        window.clearInterval(timer);
        window.removeEventListener("focus", check);
        document.removeEventListener("visibilitychange", check);
      };
    })().catch((error: unknown) => {
      if (!disposed) { dispose(); setFailure({ error }); }
    });
    return dispose;
  }, []);
  // Throwing here lets the same boundary handle asynchronous mount/resource
  // errors and React render errors, unmounting the entire plugin subtree.
  if (failure) throw failure.error;
  return <>
    {!mounted ? <StateView state="loading"/> : null}
    <div ref={container} data-plugin-id={pluginId}>
      {scope ? <QueryClientProvider client={scope.client}>{content}</QueryClientProvider> : null}
    </div>
  </>;
}
