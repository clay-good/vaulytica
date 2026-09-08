import { afterAll, describe, expect, it, vi } from "vitest";
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm } from "node:fs/promises";
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

  it("--consistency-only reports the bundle and writes no per-document file", async () => {
    // The pure use case: does this deal folder contradict itself? It used to be
    // blocked by a delivery check about a different thing — with two inputs the
    // default json format needs --out, so asking only for the cross-document
    // verdict meant writing N per-document reports into a directory nobody
    // wanted.
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-cross-only-"));
    dirs.push(dir);
    const artifact = join(dir, "consistency.json");
    const { out, err, code } = await analyze([
      BUNDLE,
      "--consistency-only",
      "--emit-consistency",
      artifact,
      "--fail-on-consistency",
      "critical",
    ]);
    expect(out + err).toContain("Cross-document (2 documents)");
    expect(code).toBe(2);
    const run = JSON.parse(await readFile(artifact, "utf8")) as { findings: unknown[] };
    expect(run.findings.length).toBeGreaterThan(0);
    // And nothing else: no --out was given, and none was needed.
    expect(await readdir(dir)).toEqual(["consistency.json"]);
  }, 120_000);

  it("--consistency-only refuses the contradictions rather than guessing", async () => {
    // An explicit --format asks for a per-document report; --consistency-only
    // says there is none. One input has no bundle to compare.
    await expect(runAnalyze([BUNDLE, "--consistency-only", "--format", "json"])).rejects.toThrow(
      /--consistency-only writes no per-document report/,
    );
    const doc = join(process.cwd(), "tests", "fixtures", "contracts", "pasted-mutual-nda.txt");
    await expect(runAnalyze([doc, "--consistency-only"])).rejects.toThrow(
      /needs at least two inputs/,
    );
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

/**
 * The four artifacts the browser has always offered and the headless surface
 * could not produce at all.
 *
 * `buildClosingChecklistMarkdown`, `buildClosingChecklistCsv`,
 * `buildCriticalDatesMarkdown` and `buildCriticalDatesIcs` are pure functions
 * that shipped with v9 and were tested from the day they landed. Nothing in
 * `tools/` ever called one. The README's own surface table says the register
 * renders as Markdown and as an `.ics` calendar and the checklist as Markdown
 * and CSV — true of the product, and unreachable from a script.
 */
describe("analyze — the closing checklist and critical-dates artifacts", () => {
  // A loan agreement with no signature block: one readiness item, one deadline.
  const WITH_CHECKLIST = join(
    process.cwd(),
    "tests",
    "golden",
    "v4",
    "fixtures",
    "banking-loan-agreement-minimal.txt",
  );
  const NDA = join(process.cwd(), "tests", "fixtures", "contracts", "pasted-mutual-nda.txt");
  const dirs: string[] = [];
  afterAll(async () => {
    for (const d of dirs) await rm(d, { recursive: true, force: true });
  });

  async function out(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-artifacts-"));
    dirs.push(dir);
    return dir;
  }

  it("writes the closing checklist as Markdown and CSV", async () => {
    const dir = await out();
    await runAnalyze([
      WITH_CHECKLIST,
      "--checklist",
      "--format",
      "checklist-md,checklist-csv",
      "--out",
      dir,
    ]);
    const md = await readFile(join(dir, "banking-loan-agreement-minimal.checklist.md"), "utf8");
    const csv = await readFile(join(dir, "banking-loan-agreement-minimal.checklist.csv"), "utf8");
    expect(md).toContain("Vaulytica closing checklist");
    // CRLF: the CSV exports use RFC-4180 line endings.
    expect(csv.split("\r\n")[0]).toBe("category,rule_id,item,section");
    expect(csv).toContain("STRUCT-003");
  }, 120_000);

  it("writes the critical-dates register as Markdown and a valid .ics", async () => {
    const dir = await out();
    await runAnalyze([NDA, "--critical-dates", "--format", "dates-md,dates-ics", "--out", dir]);
    const md = await readFile(join(dir, "pasted-mutual-nda.dates.md"), "utf8");
    const ics = await readFile(join(dir, "pasted-mutual-nda.dates.ics"), "utf8");
    expect(md).toContain("Vaulytica critical dates");
    expect(ics.startsWith("BEGIN:VCALENDAR")).toBe(true);
    expect(ics).toContain("BEGIN:VEVENT");
    expect(ics.trimEnd().endsWith("END:VCALENDAR")).toBe(true);
  }, 120_000);

  it("is a usage error to ask for a surface without the flag that computes it", async () => {
    // Rendering an empty-but-valid checklist would read as "nothing to do".
    await expect(
      runAnalyze([NDA, "--format", "checklist-md", "--out", await out()]),
    ).rejects.toThrow(/--checklist/);
    await expect(runAnalyze([NDA, "--format", "dates-ics", "--out", await out()])).rejects.toThrow(
      /--critical-dates/,
    );
  }, 120_000);

  it("warns and skips when the flag ran but the document has no such surface", async () => {
    // Same reason: an empty artifact is indistinguishable from a clean one.
    const dir = await out();
    const err: string[] = [];
    const se = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((c) => (err.push(String(c)), true));
    const so = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    try {
      await runAnalyze([NDA, "--checklist", "--format", "checklist-md", "--out", dir]);
    } finally {
      se.mockRestore();
      so.mockRestore();
    }
    expect(err.join("")).toContain("no closing checklist to render");
    await expect(readFile(join(dir, "pasted-mutual-nda.checklist.md"), "utf8")).rejects.toThrow();
  }, 120_000);
});

/**
 * The v6 findings-to-action exports and the v10 negotiation deliverables — the
 * rest of the same gap. Every builder is pure, shipped, and tested; nothing in
 * `tools/` called one.
 */
describe("analyze — obligations, deadlines, and the negotiation posture", () => {
  const NDA = join(process.cwd(), "tests", "fixtures", "contracts", "pasted-mutual-nda.txt");
  const LOAN = join(
    process.cwd(),
    "tests",
    "golden",
    "v4",
    "fixtures",
    "banking-loan-agreement-minimal.txt",
  );
  const LADDER = join(process.cwd(), "docs", "v6", "examples", "saas-buyer.playbook.json");
  const dirs: string[] = [];
  afterAll(async () => {
    for (const d of dirs) await rm(d, { recursive: true, force: true });
  });
  async function out(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-v6-exports-"));
    dirs.push(dir);
    return dir;
  }

  it("writes the obligations ledger and the deadlines calendar with no flag", async () => {
    const dir = await out();
    await runAnalyze([NDA, "--format", "obligations-csv,deadlines-ics", "--out", dir]);
    const csv = await readFile(join(dir, "pasted-mutual-nda.obligations.csv"), "utf8");
    const ics = await readFile(join(dir, "pasted-mutual-nda.deadlines.ics"), "utf8");
    expect(csv.split("\r\n")[0]).toBe("obligor,modal,action,trigger,qualifier,section,source_text");
    expect(ics.startsWith("BEGIN:VCALENDAR")).toBe(true);
  }, 120_000);

  it("writes the posture in all three forms against a real ladder", async () => {
    const dir = await out();
    await runAnalyze([
      LOAN,
      "--playbook-file",
      LADDER,
      "--posture",
      "--format",
      "posture-md,posture-csv,posture-sheet",
      "--out",
      dir,
    ]);
    const md = await readFile(join(dir, "banking-loan-agreement-minimal.posture.md"), "utf8");
    const csv = await readFile(join(dir, "banking-loan-agreement-minimal.posture.csv"), "utf8");
    const sheet = await readFile(
      join(dir, "banking-loan-agreement-minimal.negotiation-sheet.html"),
      "utf8",
    );
    expect(md).toContain("Vaulytica negotiation posture");
    expect(csv.split("\r\n")[0]).toContain("dimension,tier");
    expect(sheet).toContain("Negotiation sheet");
  }, 120_000);

  it("writes the defined-terms CSV, which only JSON and md could reach before", async () => {
    const dir = await out();
    await runAnalyze([NDA, "--definitions", "--format", "definitions-csv", "--out", dir]);
    const csv = await readFile(join(dir, "pasted-mutual-nda.definitions.csv"), "utf8");
    expect(csv.split("\r\n")[0]).toBe("bucket,term,detail,locations");
  }, 120_000);

  it("is a usage error to ask for a posture format without --posture", async () => {
    await expect(
      runAnalyze([NDA, "--format", "posture-sheet", "--out", await out()]),
    ).rejects.toThrow(/--posture/);
  }, 120_000);
});

/**
 * The secondary-family cap says how much it is not showing.
 *
 * `MAX_SECONDARY_FAMILIES` stops at four, and `selectSecondaryFamilies`' own
 * comment used to end "so a genuinely-present family is never silently
 * skipped" — which is exactly what a cap does when it bites. Measured: **22 of
 * the 312 specimens** clearly contain more families than are scanned, and
 * `dpa-controller-processor.txt` contains eight.
 *
 * The list is still four. What changed is that the line no longer reads as the
 * whole answer.
 */
describe("analyze — the secondary-family cap states its overflow", () => {
  const OVER_CAP = join(
    process.cwd(),
    "tests",
    "fixtures",
    "specimens",
    "dpa-controller-processor.txt",
  );
  const dirs: string[] = [];
  afterAll(async () => {
    for (const d of dirs) await rm(d, { recursive: true, force: true });
  });

  async function line(file: string): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-cap-"));
    dirs.push(dir);
    // Both streams: with a machine format active the stream contract sends
    // every human line to stderr, so capturing stdout alone reads as silence.
    const out: string[] = [];
    const so = vi
      .spyOn(process.stdout, "write")
      .mockImplementation((c) => (out.push(String(c)), true));
    const se = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((c) => (out.push(String(c)), true));
    try {
      await runAnalyze([file, "--format", "json", "--out", dir]);
      return out.join("");
    } finally {
      so.mockRestore();
      se.mockRestore();
    }
  }

  it("names the count it could not scan", async () => {
    const text = await line(OVER_CAP);
    // Positive first: the four it DID scan are listed.
    expect(text).toContain("vocabulary also matches:");
    expect(text).toMatch(/further clearly-present families were not scanned/);
  }, 120_000);

  it("says nothing extra when the cap did not bite", async () => {
    const text = await line(
      join(process.cwd(), "tests", "fixtures", "contracts", "pasted-mutual-nda.txt"),
    );
    expect(text).not.toContain("not scanned");
  }, 120_000);
});

/**
 * The pre-disclosure gate.
 *
 * `HANDOFF-005` is the "do not send this out" check — an SSN, a card number, a
 * direct line left in a draft about to be disclosed — and its findings live
 * OUTSIDE `run.findings`, behind their own `delivery_hash`. `--fail-on` reads
 * the run. So a document carrying an unmasked SSN produced
 * `HANDOFF-005: critical` and exited **0** under `--delivery --fail-on
 * critical`: the one combination whose entire purpose is to fail on exactly
 * that.
 *
 * The repair is a separate flag rather than a widening of `--fail-on` — the
 * same call `--fail-on-consistency` made, so switching a check on cannot change
 * the exit code of a job that was already passing — plus a loud warning on the
 * combination that used to be a silent no-op.
 */
describe("analyze — the pre-disclosure gate", () => {
  const dirs: string[] = [];
  afterAll(async () => {
    for (const d of dirs) await rm(d, { recursive: true, force: true });
  });

  /**
   * A memo with an SSN and nothing else wrong: no critical RUN finding, so the
   * exit code can only come from the delivery scan. The signature block is
   * load-bearing — without it `STRUCT-003` fires critical and the test would
   * pass for the wrong reason.
   */
  const MEMO = [
    "INTERNAL MEMO",
    "",
    "Please update the payroll record for the new hire. Their taxpayer identification number is 123-45-6789. File it with HR by Friday.",
    "",
    "Signed:",
    "",
    "By: /s/ Renata Oyelaran",
    "Name: Renata Oyelaran",
    "Title: Director of Finance",
    "Date: March 1, 2026",
  ].join("\n");

  async function memoDir(): Promise<{ dir: string; file: string }> {
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-handoff-"));
    dirs.push(dir);
    const file = join(dir, "memo.txt");
    await writeFile(file, MEMO);
    return { dir, file };
  }

  async function run(argv: string[]): Promise<{ err: string; code: number }> {
    const err: string[] = [];
    const se = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((c) => (err.push(String(c)), true));
    const so = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const before = process.exitCode;
    process.exitCode = 0;
    try {
      await runAnalyze(argv);
      return { err: err.join(""), code: Number(process.exitCode ?? 0) };
    } finally {
      process.exitCode = before;
      se.mockRestore();
      so.mockRestore();
    }
  }

  it("the fixture isolates the delivery scan (no critical run finding)", async () => {
    // Without this the exit codes below prove nothing about the gate.
    const { dir, file } = await memoDir();
    await run([file, "--delivery", "--format", "json", "--out", dir]);
    const report = JSON.parse(await readFile(join(dir, "memo.json"), "utf8")) as {
      run: { findings: { severity: string }[] };
      delivery?: { findings: { rule_id: string; severity: string }[] };
    };
    expect(report.run.findings.filter((f) => f.severity === "critical")).toEqual([]);
    expect(report.delivery?.findings.map((f) => `${f.rule_id}:${f.severity}`)).toContain(
      "HANDOFF-005:critical",
    );
  }, 120_000);

  it("--fail-on-delivery exits 2 on the SSN", async () => {
    const { dir, file } = await memoDir();
    const { code } = await run([
      file,
      "--delivery",
      "--format",
      "json",
      "--out",
      dir,
      "--fail-on-delivery",
      "critical",
    ]);
    expect(code).toBe(2);
  }, 120_000);

  it("--fail-on alone still does not gate, but no longer does so silently", async () => {
    // The exit code is deliberately unchanged — a job passing today keeps
    // passing — and the silence is what made it dangerous.
    const { dir, file } = await memoDir();
    const { err, code } = await run([
      file,
      "--delivery",
      "--format",
      "json",
      "--out",
      dir,
      "--fail-on",
      "critical",
    ]);
    expect(code).toBe(0);
    expect(err).toContain("does NOT gate on it");
    expect(err).toContain("--fail-on-delivery critical");
  }, 120_000);

  it("says nothing when the scan found nothing to warn about", async () => {
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-handoff-clean-"));
    dirs.push(dir);
    const file = join(dir, "clean.txt");
    await writeFile(file, MEMO.replace("123-45-6789", "on file with HR"));
    const { err } = await run([
      file,
      "--delivery",
      "--format",
      "json",
      "--out",
      dir,
      "--fail-on",
      "critical",
    ]);
    expect(err).not.toContain("does NOT gate on it");
  }, 120_000);

  it("rejects a bad severity rather than silently never gating", async () => {
    const { file } = await memoDir();
    await expect(runAnalyze([file, "--fail-on-delivery", "critcal"])).rejects.toThrow(
      /--fail-on-delivery must be/,
    );
  });
});

/**
 * The single-document posture gate.
 *
 * `--fail-on-divergence` asks whether the documents disagree with each OTHER;
 * `--fail-on-coherence-regression` whether the package moved against a
 * BASELINE. Neither answers the question a team actually gates a pull request
 * on — *does this draft sit below our floor?* — so the v10 ladder's most direct
 * CI use had no flag at all.
 *
 * The load-bearing detail is what CANNOT trip it. `unevaluable` ("not stated")
 * is unranked in `TIER_RANK` because it is not a point on the ideal→floor axis,
 * and a gate that fired on it would fail a document for saying nothing about a
 * dimension — the same rule `--fail-on-divergence` follows, where silence is
 * never a disagreement.
 */
describe("analyze — the single-document posture gate", () => {
  const LADDER = join(process.cwd(), "docs", "v6", "examples", "saas-buyer.playbook.json");
  const SPECIMENS = join(process.cwd(), "tests", "fixtures", "specimens");
  // 1 ideal, 1 acceptable, 1 below floor, 3 not stated — every rung represented.
  const BELOW_FLOOR = join(SPECIMENS, "api-terms.txt");
  // All six dimensions unevaluable: the fixture that proves silence is not a breach.
  const ALL_UNSTATED = join(
    process.cwd(),
    "tests",
    "golden",
    "v4",
    "fixtures",
    "banking-loan-agreement-minimal.txt",
  );
  const dirs: string[] = [];
  afterAll(async () => {
    for (const d of dirs) await rm(d, { recursive: true, force: true });
  });
  async function out(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-posture-gate-"));
    dirs.push(dir);
    return dir;
  }
  async function run(file: string, extra: string[]): Promise<{ err: string; code: number }> {
    const err: string[] = [];
    const se = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((c) => (err.push(String(c)), true));
    const so = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const before = process.exitCode;
    process.exitCode = 0;
    try {
      await runAnalyze([
        file,
        "--playbook-file",
        LADDER,
        "--posture",
        "--format",
        "json",
        "--out",
        await out(),
        ...extra,
      ]);
      return { err: err.join(""), code: Number(process.exitCode ?? 0) };
    } finally {
      process.exitCode = before;
      se.mockRestore();
      so.mockRestore();
    }
  }

  it("exits 2 and names the dimension that sits below the floor", async () => {
    const { err, code } = await run(BELOW_FLOOR, ["--fail-on-posture", "below-acceptable"]);
    expect(code).toBe(2);
    expect(err).toContain("--fail-on-posture below-acceptable");
    expect(err).toMatch(/api-terms\.txt: .+ \(below-acceptable\)/);
  }, 120_000);

  it("a stricter threshold catches the acceptable rung too", async () => {
    const { code } = await run(BELOW_FLOOR, ["--fail-on-posture", "acceptable"]);
    expect(code).toBe(2);
  }, 120_000);

  it("NEVER fires on a dimension the document says nothing about", async () => {
    // Six unevaluable dimensions and no stated rung: silence is not a breach,
    // and a gate that treated it as one would fail every quiet draft.
    const { err, code } = await run(ALL_UNSTATED, ["--fail-on-posture", "below-acceptable"]);
    expect(code).toBe(0);
    expect(err).not.toContain("--fail-on-posture");
  }, 120_000);

  it("refuses 'unevaluable' as a threshold", async () => {
    await expect(runAnalyze([BELOW_FLOOR, "--fail-on-posture", "unevaluable"])).rejects.toThrow(
      /--fail-on-posture must be/,
    );
  });

  it("requires --posture, rather than gating on a posture nobody computed", async () => {
    const err: string[] = [];
    const se = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((c) => (err.push(String(c)), true));
    const so = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const before = process.exitCode;
    process.exitCode = 0;
    try {
      await runAnalyze([
        BELOW_FLOOR,
        "--format",
        "json",
        "--out",
        await out(),
        "--fail-on-posture",
        "below-acceptable",
      ]);
      expect(Number(process.exitCode ?? 0)).toBe(1);
      expect(err.join("")).toContain("--fail-on-posture requires --posture");
    } finally {
      process.exitCode = before;
      se.mockRestore();
      so.mockRestore();
    }
  }, 120_000);
});
