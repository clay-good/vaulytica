/**
 * README version drift-guard.
 *
 * The README advertises the released version in its header badge
 * (`… · v9.41.0 · MIT`). That token is hand-maintained, so a version bump
 * that forgets the README leaves the shopfront claiming a stale release —
 * the same manual-sync drift class that let the passing-test count sit two
 * behind reality. `ENGINE_VERSION` already has a provenance guard tying it
 * to `package.json` (see src/engine/engine-version.test.ts); this is its
 * documentation-facing complement: the number a reader sees must be the
 * number that shipped. Read from the filesystem so the assertion depends on
 * the file on disk, not a bundler-resolved copy.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

describe("README version badge", () => {
  const root = process.cwd();
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { version: string };
  const readme = readFileSync(join(root, "README.md"), "utf8");

  it("carries the released package version", () => {
    // The badge writes the version as a `v`-prefixed token delimited by
    // word boundaries ("· v9.41.0 ·"); require that exact form so a bare
    // substring inside an unrelated number can never satisfy the guard.
    // A version bump that forgets the README drops this token and fails here.
    const badge = new RegExp(`\\bv${pkg.version.replace(/\./g, "\\.")}\\b`);
    expect(readme).toMatch(badge);
  });
});
