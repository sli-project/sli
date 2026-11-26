/// <reference types="vitest/config" />
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import { configDefaults } from "vitest/config";
import react from "@vitejs/plugin-react";

function fingerprintTree(root: string): string {
  const digest = createHash("sha256");
  const visit = (directory: string) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        visit(path);
      } else if (entry.isFile()) {
        digest.update(relative(root, path).replaceAll("\\", "/"));
        digest.update("\0");
        digest.update(readFileSync(path));
        digest.update("\0");
      }
    }
  };
  visit(root);
  return digest.digest("hex").slice(0, 12);
}

const frontendRoot = dirname(fileURLToPath(import.meta.url));
// Sources plus the build inputs that change chunk wiring (chunking rules,
// locked dependencies). Without them a chunk could keep its filename while
// its imports change, and an immutable cached copy breaks the page (08.10).
const productSourceFingerprint = createHash("sha256")
  .update(fingerprintTree(join(frontendRoot, "src")))
  .update(readFileSync(join(frontendRoot, "vite.config.ts")))
  .update(readFileSync(join(frontendRoot, "package-lock.json")))
  .digest("hex")
  .slice(0, 12);

export default defineConfig({
  base: "/app/",
  plugins: [react()],
  test: {
    setupFiles: ["./tests/setup-dom.ts"],
    exclude: [...configDefaults.exclude, "tests/geometry/**"],
    css: {
      // Preserve raw CSS contracts without injecting viewport styles into jsdom.
      include: [/\/design-system\/ds\.css\?raw(?:&.*)?$/],
    },
  },
  server: {
    host: "127.0.0.1",
    // Keep local visual testing on plain HTTP while forwarding API reads to
    // the production-like HTTPS runtime with its local self-signed cert.
    proxy: {
      "/api": { target: "https://127.0.0.1:8080", changeOrigin: true, secure: false },
    },
  },
  // Never build directly into the directory served by a running runtime.
  // Vite clears outDir before writing; a later EPERM would otherwise remove
  // the last good publication. The publisher copies this verified staging
  // build through scripts/maintenance/publish_react_build.py.
  build: {
    outDir: "../artifacts/frontend/react-build",
    emptyOutDir: true,
    rollupOptions: {
      output: {
        // main.tsx is a stable mode switch with a dynamic product import. Add
        // the source fingerprint so its URL changes when that import target
        // changes; otherwise a browser can retain the old bootstrap filename.
        entryFileNames: `assets/[name]-[hash]-${productSourceFingerprint}.js`,
        chunkFileNames: `assets/[name]-[hash]-${productSourceFingerprint}.js`,
        manualChunks(id) {
          if (id.includes("node_modules/echarts") || id.includes("node_modules/zrender")) return "echarts";
          // @tanstack and React packages import each other; separate chunks form an
          // import cycle and TanStack evaluates before React (blank page, 08.10).
          if (id.includes("node_modules/@tanstack")) return "react-vendor";
          if (id.includes("node_modules/react") || id.includes("node_modules/scheduler")) return "react-vendor";
          if (id.includes("node_modules/react-aria") || id.includes("node_modules/@react-aria")) return "react-aria";
          return undefined;
        },
      },
    },
  },
});
