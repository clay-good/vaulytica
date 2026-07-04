/**
 * DKB resolution contract (fix-cli-browser-parity): explicit `--dkb` →
 * report-pinned version → latest, hard error on an invalid explicit
 * path, and validated loading through the browser's schemas.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { cpSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { loadDkbDirSync, pickLatestDkb, resolveDkbDir } from "./resolve.js";

const REAL_DIST = join(process.cwd(), "dkb", "dist");
const STARTER = join(REAL_DIST, "v0.0.1-starter");

const tmp = mkdtempSync(join(tmpdir(), "vaul-dkb-resolve-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

/** A fake dist root with starter copies under the given version names. */
function makeDistRoot(versions: string[]): string {
  const root = join(tmp, `dist-${versions.join("_")}`);
  mkdirSync(root, { recursive: true });
  for (const v of versions) cpSync(STARTER, join(root, v), { recursive: true });
  return root;
}

describe("resolveDkbDir", () => {
  it("explicit path wins and must carry a manifest", () => {
    expect(resolveDkbDir({ explicit: STARTER })).toBe(STARTER);
    const empty = join(tmp, "not-a-dkb");
    mkdirSync(empty, { recursive: true });
    expect(() => resolveDkbDir({ explicit: empty })).toThrow(/no dkb-manifest\.json/);
  });

  it("report-pinned version resolves when still present", () => {
    const root = makeDistRoot(["v0001-old", "v0002-new"]);
    expect(basename(resolveDkbDir({ pinnedVersion: "v0001-old", distRoot: root }))).toBe(
      "v0001-old",
    );
  });

  it("absent pinned version falls back to latest", () => {
    const root = makeDistRoot(["v0001-old", "v0002-new"]);
    expect(basename(resolveDkbDir({ pinnedVersion: "v9999-gone", distRoot: root }))).toBe(
      "v0002-new",
    );
  });

  it("default resolves the latest version directory (what the site ships)", () => {
    const root = makeDistRoot(["v0001-old", "v0002-new"]);
    expect(basename(resolveDkbDir({ distRoot: root }))).toBe("v0002-new");
    expect(resolveDkbDir({ distRoot: root })).toBe(pickLatestDkb(root));
  });

  it("a dist root with no artifact is a hard error", () => {
    const root = join(tmp, "empty-root");
    mkdirSync(root, { recursive: true });
    expect(() => resolveDkbDir({ distRoot: root })).toThrow(/no DKB artifact/);
  });
});

describe("loadDkbDirSync", () => {
  it("loads and validates a real artifact", () => {
    const dkb = loadDkbDirSync(resolveDkbDir({ distRoot: REAL_DIST }));
    expect(dkb.manifest.version.length).toBeGreaterThan(0);
    expect(dkb.clauses.length).toBeGreaterThan(0);
    expect(dkb.statutes.length).toBeGreaterThan(0);
  });

  it("rejects an artifact that fails the browser's schema validation", () => {
    const dir = join(tmp, "bad-artifact");
    cpSync(STARTER, dir, { recursive: true });
    writeFileSync(join(dir, "dkb-clauses.json"), JSON.stringify([{ id: "" }]), "utf8");
    expect(() => loadDkbDirSync(dir)).toThrow();
  });
});
