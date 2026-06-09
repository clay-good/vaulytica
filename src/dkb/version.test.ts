import { describe, expect, it } from "vitest";
import { compareDkbVersions, isValidDkbVersion, parseDkbVersion } from "./version.js";

describe("parseDkbVersion", () => {
  it("parses dated versions", () => {
    const v = parseDkbVersion("v2026-05-11-a1b2c3d");
    expect(v?.date).toEqual({ year: 2026, month: 5, day: 11 });
    expect(v?.suffix).toBe("a1b2c3d");
  });

  it("parses starter versions", () => {
    const v = parseDkbVersion("v0.0.1-starter");
    expect(v?.date).toBeNull();
    expect(v?.suffix).toBe("starter");
  });

  it("rejects malformed versions", () => {
    expect(parseDkbVersion("nope")).toBeNull();
    expect(parseDkbVersion("v2026")).toBeNull();
  });
});

describe("compareDkbVersions", () => {
  it("orders starter < dated", () => {
    expect(compareDkbVersions("v0.0.1-starter", "v2026-05-11-a")).toBeLessThan(0);
  });

  it("orders dated versions by date then suffix", () => {
    expect(compareDkbVersions("v2026-05-11-a", "v2026-05-12-a")).toBeLessThan(0);
    expect(compareDkbVersions("v2026-05-11-a", "v2026-05-11-b")).toBeLessThan(0);
    expect(compareDkbVersions("v2026-05-11-b", "v2026-05-11-b")).toBe(0);
  });

  it("treats an unparseable version as oldest (cache-corruption safety)", () => {
    // The loader sorts cached DKB records by this comparator and serves the
    // max. A corrupt/garbage version string must therefore never outrank a
    // valid one — a string sort would put "zzz-corrupt" *after* "v2026-…".
    expect(compareDkbVersions("zzz-corrupt", "v2026-06-07-local")).toBeLessThan(0);
    expect(compareDkbVersions("v2026-06-07-local", "zzz-corrupt")).toBeGreaterThan(0);
    const records = ["zzz-corrupt", "v0.0.1-starter", "v2026-06-07-local"];
    records.sort(compareDkbVersions);
    expect(records[records.length - 1]).toBe("v2026-06-07-local");
  });
});

describe("isValidDkbVersion", () => {
  it("accepts both dated and starter forms", () => {
    expect(isValidDkbVersion("v2026-05-11-a1b2c3d")).toBe(true);
    expect(isValidDkbVersion("v0.0.1-starter")).toBe(true);
    expect(isValidDkbVersion("garbage")).toBe(false);
  });
});
