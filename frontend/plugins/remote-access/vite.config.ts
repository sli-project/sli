import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

const entry = fileURLToPath(new URL("./entry.ts", import.meta.url));
const descriptor = JSON.parse(readFileSync(new URL("./descriptor.json", import.meta.url), "utf8"));

// Independent of the core build. Publish the resulting package directory to
// SLI_PLUGIN_UI_DIR/<plugin_id>; the core and its React runtime stay unchanged.
export default defineConfig({
  publicDir: false,
  build: {
    outDir: fileURLToPath(new URL("../../../artifacts/plugin-ui/sli.remote-access", import.meta.url)),
    emptyOutDir: true,
    lib: { entry, formats: ["es"], fileName: () => "entry.js" },
    minify: false,
    modulePreload: false,
    rollupOptions: { output: { inlineDynamicImports: true } },
  },
  plugins: [{
    name: "sli-plugin-ui-package",
    generateBundle(_options, bundle) {
      const output = bundle["entry.js"];
      if (!output || output.type !== "chunk" || Object.keys(bundle).length !== 1
        || output.imports.length || output.dynamicImports.length || Object.keys(output.modules).some((path) => path !== entry)) {
        this.error("UI plugins must be one self-contained module using the host React runtime");
      }
      this.emitFile({ type: "asset", fileName: "descriptor.json", source: JSON.stringify({ ...descriptor,
        entry: { path: "entry.js", sha256: createHash("sha256").update(output.code).digest("hex") },
      }, null, 2) });
    },
  }],
});
