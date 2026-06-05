/**
 * Documentation link-integrity guard.
 *
 * Every relative `[text](path)` link in the repo's markdown must resolve to a
 * file that exists. A one-off audit (commit 21bbf7b) fixed 29 links that had
 * gone stale when the spec files moved into `docs/`; without a guard they creep
 * straight back. This test is that guard — it walks every tracked-style `.md`
 * file (build/vendor dirs excluded), resolves each relative link against the
 * file's own directory (leading-slash links resolve from the repo root, the way
 * GitHub renders them), and fails listing any that don't exist.
 *
 * Code is stripped first: fenced blocks and inline-code spans routinely contain
 * *illustrative* link syntax (e.g. `[text](path)` as an example), which is not a
 * real link and must not be flagged. External links (http/mailto/tel) and pure
 * `#anchor` links are out of scope (no filesystem target to check).
 */

import { describe, expect, it } from "vitest";
import { existsSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..", "..");

/** Directories whose markdown is not authored by us (vendored, generated, cached). */
const SKIP_RELDIRS = new Set(["node_modules", ".git", "dist", "dkb/dist", "dkb/build/cache", ".lighthouseci"]);

function walkMarkdown(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const rel = full.slice(REPO_ROOT.length + 1);
    if (SKIP_RELDIRS.has(rel) || SKIP_RELDIRS.has(entry)) continue;
    const st = statSync(full);
    if (st.isDirectory()) out.push(...walkMarkdown(full));
    else if (entry.endsWith(".md")) out.push(full);
  }
  return out;
}

/** Remove fenced code blocks and inline-code spans so example link syntax isn't matched. */
function stripCode(text: string): string {
  return text
    .replace(/```[\s\S]*?```/g, "")
    .replace(/~~~[\s\S]*?~~~/g, "")
    .replace(/`[^`]*`/g, "");
}

/** Relative link destinations (anchors stripped, titles stripped, externals skipped). */
function relativeLinkTargets(text: string): string[] {
  const targets: string[] = [];
  const re = /\[(?:[^\]]*)\]\(([^)]+)\)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    let dest = m[1]!.trim();
    if (/^(https?:|mailto:|tel:|#)/.test(dest)) continue;
    // `<dest>` form, or `dest "title"` form — take just the destination.
    if (dest.startsWith("<")) {
      const close = dest.indexOf(">");
      dest = close >= 0 ? dest.slice(1, close) : dest.slice(1);
    } else {
      dest = dest.split(/\s+/)[0]!;
    }
    dest = dest.split("#")[0]!;
    if (dest) targets.push(dest);
  }
  return targets;
}

describe("documentation link integrity", () => {
  it("every relative markdown link resolves to an existing file", () => {
    const files = walkMarkdown(REPO_ROOT);
    expect(files.length).toBeGreaterThan(40); // sanity: we're actually scanning the docs
    const broken: string[] = [];
    for (const file of files) {
      const dir = dirname(file);
      for (const dest of relativeLinkTargets(stripCode(readFileSync(file, "utf8")))) {
        const target = dest.startsWith("/") ? join(REPO_ROOT, dest) : resolve(dir, dest);
        const rel = file.slice(REPO_ROOT.length + 1);
        if (!existsSync(target)) {
          broken.push(`${rel}  →  ${dest}  (not found)`);
          continue;
        }
        // existsSync is case-insensitive on macOS; GitHub + Linux CI are
        // case-sensitive, so a wrong-case link "resolves" locally yet 404s in
        // production. Compare the on-disk canonical case to catch it anywhere.
        try {
          if (realpathSync.native(target) !== target) {
            broken.push(`${rel}  →  ${dest}  (case mismatch vs on-disk name)`);
          }
        } catch {
          // realpath can fail on exotic paths; existsSync already passed.
        }
      }
    }
    expect(broken, `broken relative markdown links:\n  ${broken.join("\n  ")}`).toEqual([]);
  });
});
