import { afterAll, describe, expect, it } from "vitest";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, basename } from "node:path";
import {
  splitGlob,
  globToRegExp,
  resolveInputs,
  renderCoherenceSummary,
  renderCoherenceMovementSummary,
} from "./run.js";
import { bundlePostureCoherence } from "../../src/report/posture-coherence.js";
import { compareCoherence } from "../../src/report/coherence-movement.js";
import type { NegotiationPosture, NegotiationTier } from "../../src/playbooks/custom-interpreter.js";

describe("splitGlob (CLI glob resolution)", () => {
  it("resolves a bare glob against the current directory", () => {
    // Regression: the previous slice(0, lastIndexOf('/')) produced "*.doc"
    // for a bare "*.docx", so readdir failed and nothing matched.
    expect(splitGlob("*.docx")).toEqual({ dir: ".", pattern: "*.docx" });
  });

  it("splits a dir/pattern glob at the last slash", () => {
    expect(splitGlob("contracts/*.docx")).toEqual({ dir: "contracts", pattern: "*.docx" });
    expect(splitGlob("./deal-room/*.pdf")).toEqual({ dir: "./deal-room", pattern: "*.pdf" });
    expect(splitGlob("a/b/c/*.txt")).toEqual({ dir: "a/b/c", pattern: "*.txt" });
  });

  it("keeps an absolute root directory", () => {
    expect(splitGlob("/*.docx")).toEqual({ dir: "/", pattern: "*.docx" });
  });
});

describe("globToRegExp", () => {
  it("matches files by extension and treats dots literally", () => {
    const re = globToRegExp("*.docx");
    expect(re.test("nda.docx")).toBe(true);
    expect(re.test("nda.docxx")).toBe(false);
    expect(re.test("ndaXdocx")).toBe(false); // the dot is literal, not 'any char'
  });

  it("anchors so a prefix/suffix does not partial-match", () => {
    const re = globToRegExp("contract-*.pdf");
    expect(re.test("contract-2026.pdf")).toBe(true);
    expect(re.test("my-contract-2026.pdf")).toBe(false);
    expect(re.test("contract-2026.pdf.bak")).toBe(false);
  });
});

describe("resolveInputs (directory walk ordering)", () => {
  const dirs: string[] = [];
  afterAll(async () => {
    for (const d of dirs) await rm(d, { recursive: true, force: true });
  });

  it("orders directory files by code unit, not host locale", async () => {
    // Regression: `walkDir` sorted with bare `localeCompare`, which is
    // locale/ICU-dependent — a directory analysis could ingest files (and so
    // print its per-file report lines and evaluate `--fail-on`) in a different
    // order on a host with a different LANG. Code-unit ordering is stable
    // everywhere: uppercase (`A`=65) sorts before lowercase (`a`=97), which
    // `localeCompare` would not do.
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-walk-"));
    dirs.push(dir);
    // Distinct names (no case-only collisions — those collapse on a
    // case-insensitive filesystem) chosen so code-unit and locale orderings
    // *differ*: code-unit puts uppercase (`B`=66, `C`=67) before lowercase
    // (`a`=97, `d`=100), whereas an `"en"` `localeCompare` would interleave
    // them as apple < Banana < Cherry < date.
    const names = ["date.txt", "Banana.txt", "apple.txt", "Cherry.txt", "1.md", ".hidden.txt"];
    for (const n of names) await writeFile(join(dir, n), "x");
    await mkdir(join(dir, "sub"));
    await writeFile(join(dir, "sub", "z.txt"), "x");

    const got = (await resolveInputs(dir)).map((p) => p.slice(dir.length + 1));
    // Dotfiles skipped; nested files included; everything code-unit ordered
    // (digits < uppercase < lowercase), top-level before `sub/` content.
    expect(got).toEqual([
      "1.md",
      "Banana.txt",
      "Cherry.txt",
      "apple.txt",
      "date.txt",
      join("sub", "z.txt"),
    ]);
  });

  it("a single file resolves to itself", async () => {
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-walk-"));
    dirs.push(dir);
    const file = join(dir, "only.txt");
    await writeFile(file, "x");
    expect((await resolveInputs(file)).map((p) => basename(p))).toEqual(["only.txt"]);
  });
});

describe("renderCoherenceSummary (spec-v12 cross-document posture)", () => {
  function posture(map: Record<string, NegotiationTier>): NegotiationPosture {
    return {
      positions: Object.entries(map).map(([dimension, tier]) => ({ dimension, tier })),
      counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
      posture_hash: "test",
    };
  }

  it("prints the counts line, the coherence_hash, and a ⚠ line only for divergent fronts", async () => {
    const coherence = await bundlePostureCoherence([
      { document: "MSA.docx", posture: posture({ Cap: "ideal", Law: "ideal" }) },
      { document: "Order.docx", posture: posture({ Cap: "below-acceptable", Law: "ideal" }) },
    ]);
    const out = renderCoherenceSummary(coherence);
    expect(out).toContain("Cross-document posture coherence:");
    expect(out).toContain("1 aligned, 1 divergent");
    // The divergent front names the spread + the binding floor; the aligned one does not appear.
    expect(out).toContain("⚠ Cap: divergent (MSA.docx=ideal, Order.docx=below-acceptable); binding floor below-acceptable in Order.docx.");
    expect(out).not.toContain("⚠ Law");
    expect(out).toMatch(/coherence_hash: [0-9a-f]{64}/);
  });

  it("emits no ⚠ lines when every front is aligned, single, or unstated", async () => {
    const coherence = await bundlePostureCoherence([
      { document: "a.docx", posture: posture({ Cap: "ideal" }) },
      { document: "b.docx", posture: posture({ Cap: "ideal" }) },
    ]);
    const out = renderCoherenceSummary(coherence);
    expect(out).toContain("1 aligned, 0 divergent");
    expect(out).not.toContain("⚠");
  });
});

describe("renderCoherenceMovementSummary (spec-v13 cross-document posture movement)", () => {
  function posture(map: Record<string, NegotiationTier>): NegotiationPosture {
    return {
      positions: Object.entries(map).map(([dimension, tier]) => ({ dimension, tier })),
      counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
      posture_hash: "test",
    };
  }

  it("prints the floor/coherence counts, the movement_hash, and a line for each front that moved", async () => {
    // Cap regressed (acceptable → below-acceptable) and fractured (aligned → divergent);
    // Law held aligned at ideal (omitted from the per-front lines).
    const base = await bundlePostureCoherence([
      { document: "msa-v1.docx", posture: posture({ Cap: "acceptable", Law: "ideal" }) },
      { document: "order-v1.docx", posture: posture({ Cap: "acceptable", Law: "ideal" }) },
    ]);
    const revised = await bundlePostureCoherence([
      { document: "msa-v2.docx", posture: posture({ Cap: "ideal", Law: "ideal" }) },
      { document: "order-v2.docx", posture: posture({ Cap: "below-acceptable", Law: "ideal" }) },
    ]);
    const out = renderCoherenceMovementSummary(await compareCoherence(base, revised));
    expect(out).toContain("Cross-document posture movement (vs. baseline):");
    expect(out).toContain("1 regressed");
    expect(out).toContain("1 fractured");
    expect(out).toContain("⚠ Cap:");
    expect(out).toContain("binding floor ↓ regressed (acceptable → below-acceptable)");
    expect(out).toContain("fractured (aligned → divergent)");
    expect(out).not.toContain("Law:"); // an unmoved front is omitted
    expect(out).toMatch(/movement_hash: [0-9a-f]{64}/);
  });

  it("marks an improvement with a • and the up arrow", async () => {
    const base = await bundlePostureCoherence([
      { document: "a.docx", posture: posture({ Cap: "below-acceptable" }) },
      { document: "b.docx", posture: posture({ Cap: "below-acceptable" }) },
    ]);
    const revised = await bundlePostureCoherence([
      { document: "a.docx", posture: posture({ Cap: "acceptable" }) },
      { document: "b.docx", posture: posture({ Cap: "acceptable" }) },
    ]);
    const out = renderCoherenceMovementSummary(await compareCoherence(base, revised));
    expect(out).toContain("• Cap: binding floor ↑ improved (below-acceptable → acceptable)");
    expect(out).not.toContain("⚠");
  });
});
