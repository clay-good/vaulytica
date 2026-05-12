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
});

describe("isValidDkbVersion", () => {
  it("accepts both dated and starter forms", () => {
    expect(isValidDkbVersion("v2026-05-11-a1b2c3d")).toBe(true);
    expect(isValidDkbVersion("v0.0.1-starter")).toBe(true);
    expect(isValidDkbVersion("garbage")).toBe(false);
  });
});
