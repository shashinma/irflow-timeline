import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Inject a strict Content-Security-Policy ONLY into the production build's index.html
// (the file:// page in the packaged app). Dev (vite serve) is left untouched so HMR
// keeps working. The renderer makes no fetch/eval and loads only its own same-origin
// bundle; 'unsafe-inline' style is required for the inline <style> in index.html, and
// frame-src 'self' permits the Sigma HTML-report srcDoc iframe.
const cspMetaPlugin = {
  name: "irflow-csp-meta",
  apply: "build",
  transformIndexHtml() {
    return [{
      tag: "meta",
      injectTo: "head-prepend",
      attrs: {
        "http-equiv": "Content-Security-Policy",
        content: [
          "default-src 'self'",
          "script-src 'self'",
          "style-src 'self' 'unsafe-inline'",
          "img-src 'self' data: blob:",
          "font-src 'self' data:",
          "media-src 'self' data: blob:",
          "connect-src 'self'",
          "frame-src 'self'",
          "object-src 'none'",
          "base-uri 'self'",
          "form-action 'self'",
        ].join("; "),
      },
    }];
  },
};

export default defineConfig({
  plugins: [react(), cspMetaPlugin],
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
  },
});
