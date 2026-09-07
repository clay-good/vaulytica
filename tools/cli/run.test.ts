import { afterAll, describe, expect, it, vi } from "vitest";
import { mkdtemp, mkdir, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, basename } from "node:path";
import {
  splitGlob,
  globToRegExp,
  resolveInputs,
  documentLabel,
  renderCoherenceSummary,
  renderCoherenceMovementSummary,
  runAnalyze,
} from "./run.js";
import {
  bundlePostureCoherence,
  buildPostureCoherenceJson,
  parsePostureCoherenceJson,
} from "../../src/report/posture-coherence.js";
import { compareCoherence, coherenceRegressed } from "../../src/report/coherence-movement.js";
import { ladderHash } from "../../src/playbooks/custom-interpreter.js";
import {
  validateCustomPlaybook,
  type CustomPlaybook,
} from "../../src/playbooks/custom-playbook.js";
import type {
  NegotiationPosture,
  NegotiationTier,
} from "../../src/playbooks/custom-interpreter.js";

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
    expect(out).toContain(
      "⚠ Cap: divergent (MSA.docx=ideal, Order.docx=below-acceptable); binding floor below-acceptable in Order.docx.",
    );
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

describe("documentLabel — portable coherence identifiers (fix-verify-receipt-depth)", () => {
  it("uses the basename, so the same bundle hashes identically from any directory", () => {
    // Two machines, two roots, one bundle — identical identifiers.
    const machineA = ["/home/alice/deals/acme/msa.docx", "/home/alice/deals/acme/order.docx"];
    const machineB = ["/Users/bob/work/msa.docx", "/Users/bob/work/order.docx"];
    expect(machineA.map((f) => documentLabel(f, machineA))).toEqual(["msa.docx", "order.docx"]);
    expect(machineB.map((f) => documentLabel(f, machineB))).toEqual(["msa.docx", "order.docx"]);
  });

  it("collision rule: colliding basenames keep their as-given paths", () => {
    const inputs = ["deals/acme/msa.docx", "deals/globex/msa.docx", "deals/order.docx"];
    expect(inputs.map((f) => documentLabel(f, inputs))).toEqual([
      "deals/acme/msa.docx",
      "deals/globex/msa.docx",
      "order.docx",
    ]);
  });
});

describe("saved coherence baseline (spec-v14 — --emit-coherence / --baseline-coherence)", () => {
  const dirs: string[] = [];
  afterAll(async () => {
    for (const d of dirs) await rm(d, { recursive: true, force: true });
  });
  function posture(map: Record<string, NegotiationTier>): NegotiationPosture {
    return {
      positions: Object.entries(map).map(([dimension, tier]) => ({ dimension, tier })),
      counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
      posture_hash: "test",
    };
  }

  it("a coherence emitted to disk then loaded yields the same movement as the in-memory path", async () => {
    // Round one (the baseline) — emitted as an artifact, then round-tripped through disk.
    const base = await bundlePostureCoherence([
      { document: "msa-v1.docx", posture: posture({ Cap: "acceptable", Law: "ideal" }) },
      { document: "order-v1.docx", posture: posture({ Cap: "acceptable", Law: "ideal" }) },
    ]);
    const revised = await bundlePostureCoherence([
      { document: "msa-v2.docx", posture: posture({ Cap: "ideal", Law: "ideal" }) },
      { document: "order-v2.docx", posture: posture({ Cap: "below-acceptable", Law: "ideal" }) },
    ]);

    const dir = await mkdtemp(join(tmpdir(), "vaulytica-coherence-"));
    dirs.push(dir);
    const artifact = join(dir, "round1.coherence.json");
    await writeFile(artifact, buildPostureCoherenceJson(base));

    const text = await readFile(artifact, "utf8");
    const parsed = await parsePostureCoherenceJson(text);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;

    // The movement computed from the disk artifact must be byte-identical to the
    // movement the v13 --baseline path computes from the in-memory coherence.
    const fromDisk = await compareCoherence(parsed.coherence, revised);
    const inMemory = await compareCoherence(base, revised);
    expect(fromDisk.movement_hash).toBe(inMemory.movement_hash);
    expect(coherenceRegressed(fromDisk)).toBe(true); // Cap floor dropped acceptable → below-acceptable
  });
});

describe("ladder-pinned coherence baseline (spec-v15 — cross-ladder guard)", () => {
  function posture(map: Record<string, NegotiationTier>): NegotiationPosture {
    return {
      positions: Object.entries(map).map(([dimension, tier]) => ({ dimension, tier })),
      counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
      posture_hash: "test",
    };
  }
  function ladder(capFloor: number): CustomPlaybook {
    const v = validateCustomPlaybook({
      schema_version: "1.0",
      catalog_version: "0.1.0",
      id: "team",
      name: "Team",
      description: "x",
      negotiation_positions: [
        {
          dimension: "Cap",
          ideal: {
            kind: "numeric_threshold",
            metric: "liability_cap_multiple",
            comparator: "gte",
            value: 2,
          },
          acceptable: {
            kind: "numeric_threshold",
            metric: "liability_cap_multiple",
            comparator: "gte",
            value: capFloor,
          },
        },
      ],
    });
    if (!v.ok) throw new Error(v.errors.join("; "));
    return v.playbook;
  }

  it("the emitting round's ladder hash round-trips on the artifact and matches the same ladder", async () => {
    const c = await bundlePostureCoherence([
      { document: "msa.docx", posture: posture({ Cap: "ideal" }) },
      { document: "order.docx", posture: posture({ Cap: "acceptable" }) },
    ]);
    const emitLadder = await ladderHash(ladder(1));
    const parsed = await parsePostureCoherenceJson(buildPostureCoherenceJson(c, emitLadder));
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    // The guard's accept path: a consuming round on the *same* ladder matches.
    expect(parsed.ladderHash).toBe(await ladderHash(ladder(1)));
    // The guard's reject path: a *different* ladder (looser floor) does not match.
    expect(parsed.ladderHash).not.toBe(await ladderHash(ladder(0.5)));
  });
});

/**
 * A value-taking flag written WITHOUT its value used to consume whatever came
 * next — including another flag. `analyze doc.txt --playbook --delivery` set
 * the playbook to the string "--delivery", skipped past it, and never enabled
 * `--delivery`: no error, exit 0, and a report with the delivery scan silently
 * missing. A gate the caller believes is on being quietly switched off is the
 * same failure the `--fail-on critcal` typo used to cause, so it gets the same
 * treatment — a usage error.
 *
 * The allowlist-validated flags (`--format`, `--fail-on`, `--court`,
 * `--deadline-profile`, `--service-method`, `--regime`, `--state`) already
 * reject a flag-shaped value on their own; these are the free-form ones.
 */
describe("value-taking flags reject a missing or flag-shaped value", () => {
  const doc = join(process.cwd(), "tests", "fixtures", "contracts", "pasted-mutual-nda.txt");
  const FREE_FORM = [
    "--playbook",
    "--out",
    "--playbook-file",
    "--role",
    "--deal-value",
    "--baseline",
    "--emit-coherence",
    "--emit-consistency",
    "--baseline-coherence",
    "--dkb",
  ];

  for (const flag of FREE_FORM) {
    it(`${flag} rejects a following flag instead of swallowing it`, async () => {
      await expect(runAnalyze([doc, flag, "--delivery"])).rejects.toThrow(
        new RegExp(`\\${flag} requires a value`),
      );
    });

    it(`${flag} rejects being the last argument`, async () => {
      await expect(runAnalyze([doc, flag])).rejects.toThrow(
        new RegExp(`\\${flag} requires a value`),
      );
    });
  }
});

/**
 * `--fail-on` is the CI gate. An unrecognized value used to be cast
 * straight to `Severity`, which left `SEVERITY_RANK[args.failOn]`
 * undefined and made the gate comparison always false: `analyze
 * --fail-on critcal` (typo) exited 0 on a document full of critical
 * findings, with nothing printed. A gate that silently stops gating is
 * worse than no gate, so a bad value must be a usage error — the same
 * way `compare` has always handled the identical flag.
 */
describe("analyze --fail-on validation", () => {
  const doc = join(process.cwd(), "tests", "fixtures", "contracts", "pasted-mutual-nda.txt");

  it("rejects an unrecognized severity instead of silently disabling the gate", async () => {
    await expect(runAnalyze([doc, "--fail-on", "bogus-severity"])).rejects.toThrow(
      /--fail-on must be critical\|warning\|info/,
    );
  });

  it("rejects a near-miss typo", async () => {
    await expect(runAnalyze([doc, "--fail-on", "critcal"])).rejects.toThrow(/--fail-on must be/);
  });

  it("rejects the flag with no value at all", async () => {
    await expect(runAnalyze([doc, "--fail-on"])).rejects.toThrow(/--fail-on must be/);
  });

  it("rejects a case variant rather than accepting it loosely", async () => {
    await expect(runAnalyze([doc, "--fail-on", "CRITICAL"])).rejects.toThrow(/--fail-on must be/);
  });
});

/**
 * The cross-document engine on the headless surface.
 *
 * The browser has run the CC-* / CROSS-* rules on every multi-document drop
 * since v3. The CLI — the surface a CI job actually calls — analyzed each file
 * alone and said nothing about the pair, so a bundle whose DPA contradicts its
 * own published privacy notice came back as two clean documents and exit 0.
 *
 * The gate is a SEPARATE flag from `--fail-on` on purpose: adding cross-document
 * checks must not change the exit code of a job that was already passing.
 */
describe("analyze — cross-document consistency over a bundle", () => {
  const BUNDLE = join(process.cwd(), "tests", "golden", "v4", "bundles", "privacy-notice-vs-dpa");
  const CLEAN = join(process.cwd(), "tests", "golden", "v4", "bundles", "clean-msa-baa");
  const dirs: string[] = [];

  afterAll(async () => {
    for (const d of dirs) await rm(d, { recursive: true, force: true });
  });

  async function analyze(argv: string[]): Promise<{ out: string; err: string; code: number }> {
    const out: string[] = [];
    const err: string[] = [];
    const so = vi
      .spyOn(process.stdout, "write")
      .mockImplementation((c) => (out.push(String(c)), true));
    const se = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((c) => (err.push(String(c)), true));
    const before = process.exitCode;
    process.exitCode = 0;
    try {
      await runAnalyze(argv);
      return { out: out.join(""), err: err.join(""), code: Number(process.exitCode ?? 0) };
    } finally {
      process.exitCode = before;
      so.mockRestore();
      se.mockRestore();
    }
  }

  it("reports the conflict and gates on it", async () => {
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-cross-"));
    dirs.push(dir);
    const artifact = join(dir, "consistency.json");
    const { out, err, code } = await analyze([
      BUNDLE,
      "--format",
      "json",
      "--out",
      dir,
      "--emit-consistency",
      artifact,
      "--fail-on-consistency",
      "critical",
    ]);
    const text = out + err;
    expect(text).toContain("Cross-document (2 documents)");
    expect(text).toContain("CC-008");
    expect(text).toContain("CC-009");
    // The finding is meaningless without knowing WHICH documents disagree.
    expect(text).toMatch(/privacy-notice\.txt ↔ dpa\.txt|dpa\.txt ↔ privacy-notice\.txt/);
    expect(code).toBe(2);

    const run = JSON.parse(await readFile(artifact, "utf8")) as {
      findings: { rule_id: string }[];
      result_hash: string;
    };
    expect(run.findings.map((f) => f.rule_id)).toEqual(
      expect.arrayContaining(["CC-008", "CC-009"]),
    );
    expect(run.result_hash).toMatch(/^[0-9a-f]{64}$/);
  }, 120_000);

  it("prints the header even when the bundle is clean, and does not gate", async () => {
    // Silence would be indistinguishable from the engine never having run —
    // which is exactly the state this surface was in.
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-cross-clean-"));
    dirs.push(dir);
    const { out, err, code } = await analyze([
      CLEAN,
      "--format",
      "json",
      "--out",
      dir,
      "--fail-on-consistency",
      "critical",
    ]);
    expect(out + err).toContain("Cross-document (2 documents)");
    expect(code).toBe(0);
  }, 120_000);

  it("puts each conflict in the SARIF of exactly one document", async () => {
    // SARIF is what the GitHub Action uploads by default, so a job gating on
    // --fail-on-consistency used to go red with nothing annotated. Each
    // conflict lands on the document its first excerpt names — once per
    // bundle, not once per document, or a conflict reads as two problems.
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-cross-sarif-"));
    dirs.push(dir);
    await analyze([BUNDLE, "--format", "sarif", "--out", dir, "--consistency"]);
    const seen: Record<string, string[]> = {};
    for (const name of ["dpa", "privacy-notice"]) {
      const log = JSON.parse(await readFile(join(dir, `${name}.sarif.json`), "utf8")) as {
        runs: { results: { ruleId: string; properties?: { surface?: string } }[] }[];
      };
      seen[name] = log.runs[0]!.results.filter(
        (r) => r.properties?.surface === "cross-document",
      ).map((r) => r.ruleId);
    }
    expect(seen["privacy-notice"]).toEqual(expect.arrayContaining(["CC-008", "CC-009"]));
    expect(seen["dpa"]).not.toContain("CC-008");
  }, 120_000);

  it("puts the appendix in the HTML report too", async () => {
    // The DOCX has rendered the consistency appendix since v3; the standalone
    // HTML did not, and that omission was not one of html.ts's deliberate ones.
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-cross-html-"));
    dirs.push(dir);
    await analyze([BUNDLE, "--format", "html", "--out", dir, "--consistency"]);
    const html = await readFile(join(dir, "privacy-notice.html"), "utf8");
    expect(html).toContain("Cross-document consistency");
    expect(html).toContain("CC-008");
  }, 120_000);

  it("stays silent — and byte-identical — without the assertion", async () => {
    // A DIRECTORY IS NOT A BUNDLE. Pointed at unrelated documents the engine
    // has hundreds of true-but-meaningless observations to make, so the pass is
    // assertion-gated and an existing job's output is unchanged.
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-cross-off-"));
    dirs.push(dir);
    const { out, err, code } = await analyze([BUNDLE, "--format", "json", "--out", dir]);
    expect(out + err).not.toContain("Cross-document");
    expect(code).toBe(0);
  }, 120_000);

  it("says so loudly when the assertion cannot be honored", async () => {
    // The asserted-pack silence trap: asking for cross-document checks and
    // getting a normal-looking report with none in it.
    const doc = join(process.cwd(), "tests", "fixtures", "contracts", "pasted-mutual-nda.txt");
    const { err } = await analyze([doc, "--format", "json", "--consistency"]);
    expect(err).toContain("--consistency needs at least two inputs");
  }, 120_000);

  it("rejects a bad severity rather than silently never gating", async () => {
    await expect(runAnalyze([BUNDLE, "--fail-on-consistency", "critcal"])).rejects.toThrow(
      /--fail-on-consistency must be/,
    );
  });
});
