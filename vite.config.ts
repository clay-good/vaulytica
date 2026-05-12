import { defineConfig, type Plugin } from "vite";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";

const REPO_ROOT = resolve(__dirname);
const DIST = resolve(REPO_ROOT, "dist");

/**
 * Dev middleware that serves directories that live outside the Vite
 * root (`site/`) as virtual public paths. Production builds copy the
 * same content into `dist/` via {@link deployAssets}.
 */
function serveExtras(): Plugin {
  const mounts: Record<string, string> = {
    "/playbooks": resolve(REPO_ROOT, "playbooks"),
    "/dkb": pickLatestDkb(resolve(REPO_ROOT, "dkb", "dist")),
  };
  return {
    name: "vaulytica-serve-extras",
    apply: "serve",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = req.url ?? "";
        for (const prefix of Object.keys(mounts)) {
          if (!url.startsWith(prefix + "/")) continue;
          const tail = url.slice(prefix.length + 1).split("?")[0]!;
          const path = resolve(mounts[prefix]!, tail);
          if (!existsSync(path) || !statSync(path).isFile()) continue;
          res.setHeader("Content-Type", contentType(path));
          res.end(readFileSync(path));
          return;
        }
        next();
      });
    },
  };
}

/**
 * Production-build hook (Step 14). After Vite emits the hashed
 * `dist/`, copy in:
 *   - `site/sw.js` → `dist/sw.js`              (service worker)
 *   - `playbooks/*.json` → `dist/playbooks/`   (12 launch playbooks)
 *   - `dkb/dist/<latest>/*` → `dist/dkb/`     (latest DKB artifacts)
 *   - icons + manifest + favicon → `dist/`     (PWA assets)
 *
 * Then write the Cloudflare Pages headers/redirects files.
 */
function deployAssets(): Plugin {
  return {
    name: "vaulytica-deploy-assets",
    apply: "build",
    closeBundle() {
      const sitePublic = ["sw.js", "manifest.webmanifest", "favicon.svg", "og-image.svg", "icon-192.png", "icon-512.png", "icon-maskable-512.png"];
      for (const name of sitePublic) {
        const src = resolve(REPO_ROOT, "site", name);
        if (existsSync(src)) copyFileSync(src, resolve(DIST, name));
      }

      const playbooks = resolve(REPO_ROOT, "playbooks");
      if (existsSync(playbooks)) {
        cpSync(playbooks, resolve(DIST, "playbooks"), { recursive: true });
      }

      const latestDkb = pickLatestDkb(resolve(REPO_ROOT, "dkb", "dist"));
      if (existsSync(latestDkb) && statSync(latestDkb).isDirectory()) {
        cpSync(latestDkb, resolve(DIST, "dkb"), { recursive: true });
      }

      mkdirSync(DIST, { recursive: true });
      writeFileSync(resolve(DIST, "_headers"), buildHeadersFile(), "utf8");
      writeFileSync(resolve(DIST, "_redirects"), buildRedirectsFile(), "utf8");
    },
  };
}

/**
 * Subresource Integrity (SRI) — rewrite `dist/index.html` so every
 * `<script src=…>` and `<link rel="modulepreload" href=…>` carries
 * an `integrity="sha384-…" crossorigin="anonymous"` attribute pair.
 *
 * Same-origin assets don't strictly require SRI today (the strict CSP
 * already blocks cross-origin loads), but SRI gives the browser a
 * self-check: if a CDN cache, a misconfigured edge, or a supply-chain
 * attacker swaps a JS chunk, the browser refuses to execute it and
 * the page goes blank instead of silently running the tampered code.
 *
 * Tracked as a hardening-roadmap item in [`docs/threat-model.md`].
 */
function subresourceIntegrity(): Plugin {
  return {
    name: "vaulytica-sri",
    apply: "build",
    // Run after `deployAssets`'s closeBundle so the HTML is final.
    enforce: "post",
    closeBundle() {
      const html = resolve(DIST, "index.html");
      if (!existsSync(html)) return;
      const original = readFileSync(html, "utf8");
      const rewritten = original.replace(
        /<(script|link)\b([^>]*)>/gi,
        (full, tag: string, attrs: string) => {
          if (/\sintegrity=/i.test(attrs)) return full;
          if (tag.toLowerCase() === "link" && !/\brel=["']?(modulepreload|preload|stylesheet)\b/i.test(attrs)) {
            return full;
          }
          const refMatch = /\b(?:src|href)\s*=\s*["']([^"']+)["']/i.exec(attrs);
          if (!refMatch) return full;
          const ref = refMatch[1]!;
          if (!ref.startsWith("/") && !ref.startsWith("./") && !ref.startsWith("../")) {
            return full;
          }
          const localPath = resolveLocalAsset(ref);
          if (!localPath || !existsSync(localPath) || !statSync(localPath).isFile()) return full;
          const sha = createHash("sha384").update(readFileSync(localPath)).digest("base64");
          return `<${tag}${attrs} integrity="sha384-${sha}" crossorigin="anonymous">`;
        },
      );
      if (rewritten !== original) writeFileSync(html, rewritten);
    },
  };
}

function resolveLocalAsset(ref: string): string | null {
  const cleaned = ref.replace(/[?#].*$/, "");
  if (cleaned.startsWith("/")) return resolve(DIST, cleaned.slice(1));
  if (cleaned.startsWith("./") || cleaned.startsWith("../")) {
    return resolve(DIST, cleaned);
  }
  return null;
}

/**
 * Produce the `dist/_headers` content per spec §26 step 14. Strict
 * CSP with no external connect-src is the whole privacy story; if
 * this ever needs to relax, that should be a deliberate PR.
 */
export function buildHeadersFile(): string {
  const csp = [
    "default-src 'self'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "manifest-src 'self'",
    "worker-src 'self' blob:",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'none'",
  ].join("; ");

  const permissionsPolicy = [
    "accelerometer=()",
    "camera=()",
    "geolocation=()",
    "gyroscope=()",
    "magnetometer=()",
    "microphone=()",
    "payment=()",
    "usb=()",
  ].join(", ");

  return [
    "/*",
    `  Content-Security-Policy: ${csp}`,
    "  Referrer-Policy: no-referrer",
    "  X-Content-Type-Options: nosniff",
    "  X-Frame-Options: DENY",
    `  Permissions-Policy: ${permissionsPolicy}`,
    "  Cross-Origin-Opener-Policy: same-origin",
    "  Cross-Origin-Resource-Policy: same-origin",
    "  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    "",
    "/sw.js",
    "  Service-Worker-Allowed: /",
    "  Cache-Control: no-cache",
    "",
    "/assets/*",
    "  Cache-Control: public, max-age=31536000, immutable",
    "",
    "/dkb/*",
    "  Cache-Control: public, max-age=300, must-revalidate",
    "",
    "/playbooks/*",
    "  Cache-Control: public, max-age=86400, must-revalidate",
    "",
  ].join("\n");
}

/** SPA fallback. Vaulytica is single-page, so this is mostly courtesy. */
export function buildRedirectsFile(): string {
  return "/*    /index.html   200\n";
}

function pickLatestDkb(distRoot: string): string {
  if (!existsSync(distRoot)) return distRoot;
  const entries = readdirSync(distRoot)
    .map((name) => ({ name, path: resolve(distRoot, name) }))
    .filter((e) => statSync(e.path).isDirectory())
    .sort((a, b) => a.name.localeCompare(b.name));
  return entries.length > 0 ? entries[entries.length - 1]!.path : distRoot;
}

function contentType(path: string): string {
  if (path.endsWith(".json")) return "application/json";
  if (path.endsWith(".js")) return "application/javascript";
  return "application/octet-stream";
}

export default defineConfig({
  root: "site",
  publicDir: resolve(__dirname, "site/public"),
  build: {
    outDir: DIST,
    emptyOutDir: true,
    target: "es2022",
    sourcemap: true,
    rollupOptions: {
      input: {
        main: resolve(__dirname, "site/index.html"),
      },
      output: {
        /**
         * Manual chunk groups so a bump to one heavy dependency does
         * not invalidate the cache for the others. With the
         * `Cache-Control: public, max-age=31536000, immutable`
         * policy on `/assets/*` from Step 14, this means a
         * docx-only update lets returning users keep their cached
         * pdfjs + tesseract chunks. Anything not named here joins
         * the default `pipeline-*` chunk.
         */
        manualChunks: (id) => {
          if (id.includes("node_modules/pdfjs-dist")) return "vendor-pdfjs";
          if (id.includes("node_modules/mammoth")) return "vendor-mammoth";
          if (id.includes("node_modules/docx")) return "vendor-docx";
          if (id.includes("node_modules/tesseract.js")) return "vendor-tesseract";
          if (id.includes("node_modules/decimal.js")) return "vendor-decimal";
          if (id.includes("node_modules/zod")) return "vendor-zod";
          return undefined;
        },
      },
    },
    chunkSizeWarningLimit: 600,
  },
  server: {
    port: 5173,
    strictPort: false,
    fs: {
      allow: [resolve(__dirname)],
    },
  },
  resolve: {
    alias: {
      "@": resolve(__dirname, "src"),
    },
  },
  plugins: [serveExtras(), deployAssets(), subresourceIntegrity()],
});
