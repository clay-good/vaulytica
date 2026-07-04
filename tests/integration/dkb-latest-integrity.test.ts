/**
 * Integrity of the *latest* DKB artifact — the exact directory
 * `pickLatestDkb` (vite.config.ts) resolves and ships to `dist/dkb/`
 * (fix-dkb-build-integrity).
 *
 * Before this test existed, CI validated only the starter fixture while
 * the site shipped whatever sorted last in `dkb/dist/` — which is how
 * v2026-06-28-local went live with 0 statutes, 0 clauses, 0 definitions,
 * 0 jurisdictions, and 0 dark patterns under a fully green gate.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { assertShippableDkb } from "../../vite.config.js";

const DIST_ROOT = join(process.cwd(), "dkb", "dist");
const STARTER = join(DIST_ROOT, "v0.0.1-starter");

const CONTENT_SECTIONS = [
  "clauses",
  "jurisdictions",
  "definitions",
  "dark_patterns",
  "statutes",
] as const;

type Manifest = {
  version: string;
  files: Record<string, { filename: string; sha256: string; entries?: number }>;
};

/** Same resolution as `pickLatestDkb`: last directory in localeCompare order. */
function latestDkbDir(): string {
  const dirs = readdirSync(DIST_ROOT)
    .map((name) => join(DIST_ROOT, name))
    .filter((path) => statSync(path).isDirectory())
    .sort((a, b) => a.localeCompare(b));
  expect(dirs.length).toBeGreaterThan(0);
  return dirs[dirs.length - 1]!;
}

function readManifest(dir: string): Manifest {
  return JSON.parse(readFileSync(join(dir, "dkb-manifest.json"), "utf8")) as Manifest;
}

describe("latest DKB artifact (the one the site ships)", () => {
  const latest = latestDkbDir();
  const manifest = readManifest(latest);
  const starter = readManifest(STARTER);

  it("carries at least the starter's knowledge content in every section", () => {
    for (const section of CONTENT_SECTIONS) {
      const entries = manifest.files[section]?.entries ?? 0;
      const floor = starter.files[section]?.entries ?? 0;
      expect(entries, `${manifest.version} section ${section}`).toBeGreaterThanOrEqual(floor);
      expect(entries, `${manifest.version} section ${section}`).toBeGreaterThan(0);
    }
  });

  it("records a sha256 and entry count matching the bytes of every file", () => {
    for (const [section, ref] of Object.entries(manifest.files)) {
      const path = join(latest, ref.filename);
      expect(existsSync(path), `${manifest.version} ${section}: ${ref.filename} missing`).toBe(
        true,
      );
      const bytes = readFileSync(path);
      const actual = createHash("sha256").update(bytes).digest("hex");
      expect(actual, `${manifest.version} ${section}: sha256 mismatch`).toBe(ref.sha256);
      const parsed = JSON.parse(bytes.toString("utf8")) as unknown[];
      expect(parsed.length, `${manifest.version} ${section}: entry count lies`).toBe(
        ref.entries ?? 0,
      );
    }
  });

  it("passes the ship-time gate the site build runs", () => {
    expect(() => assertShippableDkb(latest)).not.toThrow();
  });
});

describe("assertShippableDkb (site build gate)", () => {
  const tmp = mkdtempSync(join(tmpdir(), "vaul-dkb-gate-"));
  afterAll(() => rmSync(tmp, { recursive: true, force: true }));

  it("rejects a content-empty artifact, naming version and sections", () => {
    const manifest = {
      version: "v9999-empty",
      files: Object.fromEntries(
        [...CONTENT_SECTIONS, "classifier_vocab", "classifier_patterns"].map((s) => [
          s,
          { filename: `dkb-${s}.json`, sha256: "0".repeat(64), entries: 0 },
        ]),
      ),
    };
    writeFileSync(join(tmp, "dkb-manifest.json"), JSON.stringify(manifest), "utf8");
    expect(() => assertShippableDkb(tmp)).toThrow(/v9999-empty.*statutes/s);
  });

  it("rejects a directory with no manifest at all", () => {
    expect(() => assertShippableDkb(join(tmp, "nope"))).toThrow(/dkb-manifest\.json is missing/);
  });
});
