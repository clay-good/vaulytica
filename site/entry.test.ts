/**
 * Entry-script resolvability guard.
 *
 * `vite.config.ts` sets `root: "site"`. A production build happily
 * resolves an out-of-root `<script src="../src/ui/main.ts">`, but the
 * dev server does not rewrite it — the browser asks for
 * `/src/ui/main.ts`, the SPA fallback answers with `index.html` as
 * `text/html`, and the module is refused on MIME type. `npm run dev`
 * then serves a page with no app on it, and nothing in the build or
 * the test suite notices.
 *
 * These tests pin the invariant that made dev work again: the entry
 * tag resolves to a real file *inside* the Vite root, and that file
 * still leads to the real UI entry.
 */

import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const SITE = join(process.cwd(), "site");
const html = readFileSync(join(SITE, "index.html"), "utf8");

/** Every `<script type="module" src=…>` in the page, in document order. */
function moduleScriptSrcs(): string[] {
  const srcs: string[] = [];
  const re = /<script\b([^>]*)>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const attrs = m[1] ?? "";
    if (!/\btype\s*=\s*["']module["']/i.test(attrs)) continue;
    const src = /\bsrc\s*=\s*["']([^"']+)["']/i.exec(attrs)?.[1];
    if (src) srcs.push(src);
  }
  return srcs;
}

describe("site entry script", () => {
  it("declares exactly one module entry", () => {
    expect(moduleScriptSrcs()).toHaveLength(1);
  });

  it("is a root-absolute path, so the dev server resolves it", () => {
    const [src] = moduleScriptSrcs();
    expect(src).toMatch(/^\//);
    // A `../`-escaping src is precisely the shape that 404s in dev.
    expect(src).not.toContain("..");
  });

  it("points at a file that exists inside the Vite root", () => {
    const [src] = moduleScriptSrcs();
    expect(existsSync(join(SITE, src!.replace(/^\//, "")))).toBe(true);
  });

  it("reaches the real UI entry", () => {
    const [src] = moduleScriptSrcs();
    const shim = readFileSync(join(SITE, src!.replace(/^\//, "")), "utf8");
    expect(shim).toContain("../src/ui/main.js");
  });
});
