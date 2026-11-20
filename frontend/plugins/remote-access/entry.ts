import type { PluginUiInstance } from "../../src/plugins/contract";

/** UI API v1: no runtime imports, globals, or private core modules. */
export function createPlugin(): PluginUiInstance {
  let clear: (() => void) | undefined;
  return {
    mount(container, api) {
      if (api.ui_api !== "sli.plugin-ui.v1" || !api.Page) {
        throw new Error("plugin_ui_unsupported_api");
      }
      api.render(container, api.react.createElement(api.Page));
      clear = () => api.render(container, null);
    },
    unmount() {
      clear?.();
      clear = undefined;
    },
  };
}
