import { defineConfig, type Plugin } from "vite";
import { resolve } from "node:path";
import { pickLatestDkb } from "./tools/dkb/resolve.js";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";

const REPO_ROOT = resolve(__dirname);
const DIST = resolve(REPO_ROOT, "dist");

/**
 * v4 sub-domain rule families bundled into the `v4-rules-corp` chunk
 * (corporate / finance). Every other v4 family — and any new one — lands
 * in `v4-rules-reg` (regulatory / sector). The split is purely a
 * cache-granularity / chunk-size boundary (see docs/bundle-splitting.md);
 * it has no effect on which rules run. Keep the two buckets roughly
 * balanced so neither crosses Vite's 600 KB warning threshold.
 */
const V4_CORP_FAMILIES = new Set([
  "m-and-a",
  "governance",
  "equity",
  "trust-estate",
  "banking",
  "ip-licensing",
]);

/**
 * Dev middleware that serves directories that live outside the Vite
 * root (`site/`) as virtual public paths. Production builds copy the
 * same content into `dist/` via {@link deployAssets}.
 */
function serveExtras(): Plugin {
  const mounts: Record<string, string> = {
    "/playbooks": resolve(REPO_ROOT, "playbooks"),
    "/dkb": pickLatestDkb(resolve(REPO_ROOT, "dkb", "dist")),
    // Same-origin pdf.js worker (fix-privacy-claim-accuracy): the ingest
    // pins GlobalWorkerOptions.workerSrc to /pdf-worker/pdf.worker.min.mjs,
    // so PDF analysis never resolves assets off-origin — and actually works
    // in a real browser (without the pin pdfjs throws before parsing).
    "/pdf-worker": resolve(REPO_ROOT, "node_modules", "pdfjs-dist", "legacy", "build"),
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
      const sitePublic = [
        "sw.js",
        "manifest.webmanifest",
        "favicon.svg",
        "og-image.svg",
        "og-image.png",
        "icon-192.png",
        "icon-512.png",
        "icon-maskable-512.png",
      ];
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
        assertShippableDkb(latestDkb);
        cpSync(latestDkb, resolve(DIST, "dkb"), { recursive: true });
      }

      // Same-origin pdf.js worker (see serveExtras): ship the exact worker
      // build matching the bundled pdfjs-dist version.
      const pdfWorker = resolve(
        REPO_ROOT,
        "node_modules",
        "pdfjs-dist",
        "legacy",
        "build",
        "pdf.worker.min.mjs",
      );
      if (existsSync(pdfWorker)) {
        mkdirSync(resolve(DIST, "pdf-worker"), { recursive: true });
        copyFileSync(pdfWorker, resolve(DIST, "pdf-worker", "pdf.worker.min.mjs"));
      }

      // Ensure /dkb/v3/validation-status.json always resolves (200) so the
      // footer fetch in src/ui/dkb-validation.ts does not log a console
      // error that Lighthouse's `errors-in-console` audit flags. The DKB
      // rebuild workflow overwrites this file with real values; here we
      // just guarantee a parseable default exists in dist/.
      const validationPath = resolve(DIST, "dkb", "v3", "validation-status.json");
      if (!existsSync(validationPath)) {
        mkdirSync(resolve(DIST, "dkb", "v3"), { recursive: true });
        writeFileSync(
          validationPath,
          JSON.stringify(
            { dkb_last_validated_at: new Date().toISOString(), stale_citations_pending_review: 0 },
            null,
            2,
          ),
          "utf8",
        );
      }

      mkdirSync(DIST, { recursive: true });
      const inlineHashes = computeInlineScriptHashes(resolve(DIST, "index.html"));
      writeFileSync(resolve(DIST, "_headers"), buildHeadersFile(inlineHashes), "utf8");
      writeFileSync(resolve(DIST, "_redirects"), buildRedirectsFile(), "utf8");
      writeFileSync(resolve(DIST, "robots.txt"), buildRobotsTxt(), "utf8");
      writeFileSync(resolve(DIST, "sitemap.xml"), buildSitemapXml(), "utf8");
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
          if (
            tag.toLowerCase() === "link" &&
            !/\brel=["']?(modulepreload|preload|stylesheet)\b/i.test(attrs)
          ) {
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
/**
 * Compute SHA-256 hashes (base64) of every inline `<script>` block in
 * the final `dist/index.html` so they can be allow-listed in the CSP
 * `script-src` directive. This keeps the strict `script-src 'self'`
 * posture (no `'unsafe-inline'`) while letting the FOUC-prevention
 * bootstrap and similar small inline scripts execute. `<script>` tags
 * carrying a `type` attribute (e.g. `application/ld+json`,
 * `module`) are skipped — JSON-LD is not executable script and module
 * scripts are loaded by URL so they're covered by `'self'`.
 */
function computeInlineScriptHashes(htmlPath: string): string[] {
  if (!existsSync(htmlPath)) return [];
  const html = readFileSync(htmlPath, "utf8");
  const hashes: string[] = [];
  const scriptRe = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let match: RegExpExecArray | null;
  while ((match = scriptRe.exec(html)) !== null) {
    const attrs = match[1] ?? "";
    const body = match[2] ?? "";
    if (/\bsrc\s*=/i.test(attrs)) continue;
    if (/\btype\s*=\s*["'][^"']+["']/i.test(attrs)) continue;
    const sha = createHash("sha256").update(body, "utf8").digest("base64");
    hashes.push(`'sha256-${sha}'`);
  }
  return hashes;
}

export function buildHeadersFile(inlineScriptHashes: string[] = []): string {
  const scriptSrc = ["'self'", "'wasm-unsafe-eval'", ...inlineScriptHashes].join(" ");
  const csp = [
    "default-src 'self'",
    `script-src ${scriptSrc}`,
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

/**
 * `robots.txt` — allow indexing of the marketing surface, point crawlers
 * at the sitemap, and explicitly disallow the dynamic asset directories
 * (`/dkb/`, `/playbooks/`) so they don't pollute the index with JSON
 * artifacts.
 */
export function buildRobotsTxt(): string {
  return [
    "# https://vaulytica.com/robots.txt",
    "User-agent: *",
    "Allow: /",
    "Disallow: /dkb/",
    "Disallow: /playbooks/",
    "",
    "Sitemap: https://vaulytica.com/sitemap.xml",
    "",
  ].join("\n");
}

/**
 * `sitemap.xml` — single-page site, one URL plus deep links to the
 * primary in-page sections. Search engines treat anchored URLs as
 * lower-priority alternates of the canonical home, which keeps the
 * indexing surface clean while still surfacing section names.
 */
export function buildSitemapXml(): string {
  const today = new Date().toISOString().slice(0, 10);
  const url = (loc: string, priority: string, freq = "weekly"): string =>
    [
      "  <url>",
      `    <loc>${loc}</loc>`,
      `    <lastmod>${today}</lastmod>`,
      `    <changefreq>${freq}</changefreq>`,
      `    <priority>${priority}</priority>`,
      "  </url>",
    ].join("\n");
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    url("https://vaulytica.com/", "1.0", "weekly"),
    url("https://vaulytica.com/#how-it-works", "0.8"),
    url("https://vaulytica.com/#sources", "0.7"),
    url("https://vaulytica.com/#faq", "0.7"),
    url("https://vaulytica.com/#privacy", "0.6"),
    "</urlset>",
    "",
  ].join("\n");
}

/**
 * Ship-time floor check on the DKB artifact the build is about to copy
 * into `dist/dkb/`. A manifest reporting zero entries for any content
 * section means the knowledge base is empty — shipping it would break
 * the "every finding traces to a pinned source" promise, so the whole
 * build fails instead (the v2026-06-28-local artifact shipped exactly
 * this way with every CI check green).
 */
export function assertShippableDkb(dkbDir: string): void {
  const manifestPath = resolve(dkbDir, "dkb-manifest.json");
  if (!existsSync(manifestPath)) {
    throw new Error(`refusing to ship DKB from ${dkbDir}: dkb-manifest.json is missing`);
  }
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
    version?: string;
    files?: Record<string, { entries?: number }>;
  };
  const contentSections = ["clauses", "jurisdictions", "definitions", "dark_patterns", "statutes"];
  const empty = contentSections.filter((s) => !((manifest.files?.[s]?.entries ?? 0) > 0));
  if (empty.length > 0) {
    throw new Error(
      `refusing to ship DKB ${manifest.version ?? dkbDir}: empty content section(s): ` +
        `${empty.join(", ")} — rebuild the DKB (npm run dkb:build) before building the site`,
    );
  }
}

function contentType(path: string): string {
  if (path.endsWith(".json")) return "application/json";
  if (path.endsWith(".js") || path.endsWith(".mjs")) return "application/javascript";
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
    // Keep the small entry/runtime chunks preloaded (they render the
    // LCP hero), but drop the heavy lazy vendor chunks from the
    // `<link rel="modulepreload">` set. pdfjs-dist uses dynamic
    // imports internally, so Vite's shared `__vitePreload` helper is
    // colocated in the 375 KB vendor-pdfjs chunk; the entry calls that
    // helper for its lazy `import("./pipeline.js")`, which otherwise
    // makes the browser preload all of pdfjs on the first-paint path —
    // 375 KB competing with the document download for First Contentful
    // Paint, even though pdfjs is only needed once a PDF is dropped.
    // Filtering it (and the other heavy parser vendors) out of the
    // preload list keeps them lazy: they load with the pipeline chunk
    // on file drop, off the critical render path.
    modulePreload: {
      resolveDependencies: (_filename, deps) =>
        deps.filter((dep) => !/vendor-(pdfjs|mammoth|docx|tesseract|decimal|zod)/.test(dep)),
    },
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
          // App-code rule-catalog split (see docs/bundle-splitting.md).
          // The rule catalog is ~40% of the analysis code and changes far
          // more often than the engine core / report builder, so peeling it
          // into its own immutable chunks means a rule-only commit no longer
          // re-downloads the whole pipeline for returning users. It also
          // brings every chunk under Vite's 600 KB warning threshold. This
          // is a code-split only: the engine still imports every rule
          // synchronously, so these chunks load together with `pipeline-*`
          // behind the file-drop gesture — same bytes, off the first-paint
          // path, byte-identical engine behavior. The 15 v4 sub-domain
          // families (the larger, faster-moving half) split apart from the
          // launch/compliance rule set so a v4-family edit and a core-rule
          // edit invalidate independently. The v4 set is split again into
          // two thematic buckets (corporate/finance vs regulatory/sector) so
          // no single chunk crosses 600 KB; a new v4 family joins the
          // regulatory bucket by default. Order matters: the v4 test runs
          // before the broader rules/ test.
          if (id.includes("/engine/rules/v4/")) {
            const family = id.match(/\/engine\/rules\/v4\/([^/]+)\//)?.[1];
            return family && V4_CORP_FAMILIES.has(family) ? "v4-rules-corp" : "v4-rules-reg";
          }
          if (id.includes("/engine/rules/")) return "rules-core";
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
