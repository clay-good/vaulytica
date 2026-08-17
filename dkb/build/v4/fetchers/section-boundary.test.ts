/**
 * Section-number boundary guard for the v4 statute fetchers.
 *
 * Each fetcher gates node emission on a `detect` regex, and several of those
 * offered a bare section number as an alternative (`§\s*251`, `3-?305`,
 * `rule 41`). With no boundary after the digits, a numerically adjacent but
 * unrelated section in the fetched snapshot satisfied the gate: a page citing
 * `§ 2510` emitted the `§ 251` node, so the DKB recorded a statutory
 * requirement whose citation had never actually been confirmed present in the
 * pinned source. That silently breaks the build's provenance guarantee.
 *
 * These fetchers only ever see official statute snapshots, so the blast radius
 * is small — but a node emitted on a superstring match is exactly the kind of
 * wrong-by-construction data the DKB exists to prevent.
 */

import { describe, expect, it } from "vitest";

import { parseDgcl } from "./dgcl.js";

const NOW = "2026-01-01T00:00:00Z";

describe("v4 fetcher section-number boundaries", () => {
  it("does not emit the § 251 node for an unrelated § 2510 citation", () => {
    const text =
      "Under some unrelated provision, § 2510, of a different title entirely, " +
      "with no merger language at all.";
    const nodes = parseDgcl(text, NOW);
    expect(nodes.map((n) => n.id)).not.toContain("dgcl-251-merger-consolidation");
  });

  it("still emits the § 251 node for a genuine § 251 citation", () => {
    const text =
      "The constituent corporations have entered into an agreement pursuant to " +
      "8 Del. C. § 251, providing for the merger.";
    const nodes = parseDgcl(text, NOW);
    expect(nodes.map((n) => n.id)).toContain("dgcl-251-merger-consolidation");
  });

  it("leaves no bare, unbounded section number in any v4 detect regex", async () => {
    // A structural guard so a new fetcher cannot reintroduce the class. Every
    // `detect` alternative ending in digits must be followed by a boundary.
    const { readdirSync, readFileSync } = await import("node:fs");
    const { join } = await import("node:path");
    const dir = join(process.cwd(), "dkb", "build", "v4", "fetchers");
    const offenders: string[] = [];
    for (const file of readdirSync(dir).filter((f) => f.endsWith(".ts") && !f.includes(".test."))) {
      const source = readFileSync(join(dir, file), "utf8");
      for (const line of source.split("\n")) {
        if (!line.includes("detect:")) continue;
        // A digit run ending an alternative (before `|` or the closing `)`/`/`)
        // with no lookahead, `\b`, or further pattern after it.
        if (/\d(?=\s*[|)]|\/[a-z]*\s*,?\s*$)/.test(line.replace(/\(\?!\\d\)/g, "X"))) {
          offenders.push(`${file}: ${line.trim()}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});
