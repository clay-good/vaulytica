/**
 * Engine-version provenance guard (fix-engine-version-provenance).
 *
 * `ENGINE_VERSION` sat frozen at "0.1.0" from the first commit through
 * ~40 behavior-changing releases (112 → 1,065 rules), so every report
 * ever produced carried identical engine provenance — the one field an
 * attorney's receipt needs to never lie. This guard makes a frozen stamp
 * impossible to reintroduce: the stamp must equal the released package
 * version, read here from `package.json` via the filesystem (an import
 * would share the same module graph it is guarding).
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ENGINE_VERSION } from "./runner.js";

describe("ENGINE_VERSION provenance", () => {
  it("equals the released package version", () => {
    const pkg = JSON.parse(readFileSync(join(process.cwd(), "package.json"), "utf8")) as {
      version: string;
    };
    expect(ENGINE_VERSION).toBe(pkg.version);
  });

  it("is a real semver, not the frozen 0.1.0 stamp", () => {
    expect(ENGINE_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
    expect(ENGINE_VERSION).not.toBe("0.1.0");
  });
});
