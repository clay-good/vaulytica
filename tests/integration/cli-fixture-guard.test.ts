/**
 * CLI ⟂ test fixtures (fix-cli-browser-parity).
 *
 * The CLI once loaded its knowledge base through
 * `src/engine/_test-fixtures.ts` (`loadStarterDkbSync`) — a test-fixture
 * module — so every headless run analyzed under a DIFFERENT DKB than the
 * deployed browser app, and `dkb_version` sits inside `result_hash`.
 * This guard keeps the shipped tool surfaces off test fixtures for good
 * (mirrors the accuracy-corpus-guard pattern).
 */

import { describe, expect, it } from "vitest";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..", "..");

function walk(dir: string, pred: (p: string) => boolean): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full, pred));
    else if (pred(full)) out.push(full);
  }
  return out;
}

describe("CLI fixture guard", () => {
  it("no non-test file under tools/cli/ or tools/accuracy/ imports _test-fixtures", () => {
    const files = [
      ...walk(join(REPO_ROOT, "tools", "cli"), (p) => p.endsWith(".ts") && !p.endsWith(".test.ts")),
      ...walk(
        join(REPO_ROOT, "tools", "accuracy"),
        (p) => p.endsWith(".ts") && !p.endsWith(".test.ts"),
      ),
    ];
    expect(files.length).toBeGreaterThan(0);
    const offenders = files.filter((f) =>
      /from\s+["'][^"']*_test-fixtures/.test(readFileSync(f, "utf8")),
    );
    expect(offenders.map((f) => f.replace(REPO_ROOT + "/", ""))).toEqual([]);
  });
});
