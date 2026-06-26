import { describe, expect, it, afterEach, vi } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  parseCompareArgs,
  introducedBreaches,
  postureRegressed,
  formatCompareMarkdown,
  formatPostureMovementMarkdown,
  runCompare,
} from "./compare.js";
import { compareRuns } from "../../src/report/compare.js";
import { buildClauseDiff } from "../../src/report/clause-diff.js";
import { comparePosture } from "../../src/report/posture-movement.js";
import type {
  NegotiationPosture,
  NegotiationTier,
} from "../../src/playbooks/custom-interpreter.js";
import type { EngineRun, Finding, Severity } from "../../src/engine/index.js";
import type { DocumentTree } from "../../src/ingest/types.js";

// --- fixtures ---------------------------------------------------------------

function finding(rule_id: string, severity: Severity, position: number): Finding {
  return {
    id: `${rule_id}-s${position}-${position}`,
    rule_id,
    rule_version: "1.0.0",
    severity,
    title: `Issue with ${rule_id}`,
    description: "desc",
    excerpt: {
      text: "clause",
      section_id: `s${position}`,
      start_offset: position,
      end_offset: position + 5,
    },
    explanation: "Why.",
    source_citations: [],
    document_position: position,
  };
}

function makeRun(name: string, hash: string, findings: Finding[]): EngineRun {
  return {
    version: "0.1.0",
    dkb_version: "v1.0.0",
    playbook_id: "mutual-nda",
    source_file: { name, sha256: "a".repeat(64), size_bytes: 1024 },
    executed_at: "2026-06-09T00:00:00Z",
    findings,
    execution_log: findings.map((f) => ({
      rule_id: f.rule_id,
      rule_version: "1.0.0",
      fired: true,
      elapsed_ms: 0,
    })),
    result_hash: hash,
  };
}

function docTree(...paras: string[]): DocumentTree {
  return {
    type: "document",
    sections: [
      {
        id: "s0",
        heading: "Agreement",
        level: 1,
        paragraphs: paras.map((t, i) => ({
          id: `s0.p${i}`,
          runs: [{ id: `s0.p${i}.r0`, text: t, start: 0, end: t.length }],
        })),
        children: [],
      },
    ],
  };
}

// --- arg parsing ------------------------------------------------------------

describe("parseCompareArgs", () => {
  it("requires exactly two positionals", () => {
    expect(() => parseCompareArgs(["only-one.txt"])).toThrow(/usage/);
    expect(() => parseCompareArgs(["a", "b", "c"])).toThrow(/usage/);
  });

  it("parses positionals and flags", () => {
    const a = parseCompareArgs([
      "base.docx",
      "rev.docx",
      "--fail-on",
      "warning",
      "--format",
      "json",
      "--confirm-pairing",
    ]);
    expect(a.base).toBe("base.docx");
    expect(a.revised).toBe("rev.docx");
    expect(a.failOn).toBe("warning");
    expect(a.format).toBe("json");
    expect(a.confirmPairing).toBe(true);
  });

  it("defaults to markdown and no gate", () => {
    const a = parseCompareArgs(["a.txt", "b.txt"]);
    expect(a.format).toBe("markdown");
    expect(a.failOn).toBeUndefined();
    expect(a.confirmPairing).toBe(false);
  });

  it("rejects bad enum values and unknown flags", () => {
    expect(() => parseCompareArgs(["a", "b", "--format", "xml"])).toThrow(/--format/);
    expect(() => parseCompareArgs(["a", "b", "--fail-on", "fatal"])).toThrow(/--fail-on/);
    expect(() => parseCompareArgs(["a", "b", "--nope"])).toThrow(/unknown flag/);
  });

  it("parses --posture with --playbook-file (spec-v11)", () => {
    const a = parseCompareArgs([
      "base.docx",
      "rev.docx",
      "--playbook-file",
      "pb.json",
      "--posture",
    ]);
    expect(a.playbookFile).toBe("pb.json");
    expect(a.posture).toBe(true);
  });

  it("rejects --posture without --playbook-file (no silent no-op)", () => {
    expect(() => parseCompareArgs(["a", "b", "--posture"])).toThrow(
      /--posture requires --playbook-file/,
    );
  });

  it("defaults posture off", () => {
    expect(parseCompareArgs(["a", "b"]).posture).toBe(false);
  });

  it("parses --fail-on-regression with --posture (spec-v11 Thrust C)", () => {
    const a = parseCompareArgs([
      "a",
      "b",
      "--playbook-file",
      "pb.json",
      "--posture",
      "--fail-on-regression",
    ]);
    expect(a.failOnRegression).toBe(true);
  });

  it("rejects --fail-on-regression without --posture (no movement to gate)", () => {
    expect(() => parseCompareArgs(["a", "b", "--fail-on-regression"])).toThrow(
      /--fail-on-regression requires --posture/,
    );
  });

  it("defaults fail-on-regression off", () => {
    expect(parseCompareArgs(["a", "b"]).failOnRegression).toBe(false);
  });
});

// --- gate logic -------------------------------------------------------------

describe("introducedBreaches", () => {
  const counts = (critical: number, warning: number, info: number) => ({
    critical,
    warning,
    info,
    total: critical + warning + info,
  });
  it("critical threshold fires only on a critical", () => {
    expect(introducedBreaches(counts(1, 0, 0), "critical")).toBe(true);
    expect(introducedBreaches(counts(0, 5, 9), "critical")).toBe(false);
  });
  it("warning threshold fires on critical or warning", () => {
    expect(introducedBreaches(counts(0, 1, 0), "warning")).toBe(true);
    expect(introducedBreaches(counts(1, 0, 0), "warning")).toBe(true);
    expect(introducedBreaches(counts(0, 0, 3), "warning")).toBe(false);
  });
  it("info threshold fires on anything", () => {
    expect(introducedBreaches(counts(0, 0, 1), "info")).toBe(true);
    expect(introducedBreaches(counts(0, 0, 0), "info")).toBe(false);
  });
});

describe("postureRegressed (spec-v11 Thrust C)", () => {
  const mkPosture = (map: Record<string, NegotiationTier>): NegotiationPosture => ({
    positions: Object.entries(map).map(([dimension, tier]) => ({ dimension, tier })),
    counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
    posture_hash: "x",
  });

  it("trips when a dimension moved to a strictly worse rung", async () => {
    const pm = await comparePosture(
      mkPosture({ "Governing law": "ideal" }),
      mkPosture({ "Governing law": "below-acceptable" }),
    );
    expect(postureRegressed(pm)).toBe(true);
  });

  it("does not trip on improvement, unchanged, or newly-stated", async () => {
    const pm = await comparePosture(
      mkPosture({ Cap: "below-acceptable", Law: "ideal", New: "unevaluable" }),
      mkPosture({ Cap: "acceptable", Law: "ideal", New: "acceptable" }),
    );
    expect(postureRegressed(pm)).toBe(false);
  });

  it("does not trip on now-unstated (a dropped front is not a rung regression)", async () => {
    const pm = await comparePosture(
      mkPosture({ Indemnity: "ideal" }),
      mkPosture({ Indemnity: "unevaluable" }),
    );
    expect(pm.counts["now-unstated"]).toBe(1);
    expect(postureRegressed(pm)).toBe(false);
  });
});

// --- markdown rendering -----------------------------------------------------

describe("formatCompareMarkdown", () => {
  it("renders the delta table, introduced findings, and an inline word redline", async () => {
    const base = makeRun("v1.txt", "b".repeat(64), []);
    const revised = makeRun("v2.txt", "r".repeat(64), [finding("RISK-002", "critical", 3)]);
    const cmp = await compareRuns(base, revised);
    const clauseDiff = buildClauseDiff(
      docTree("Liability is capped at $1,000,000."),
      docTree("Liability is capped at $5,000,000."),
    );
    const md = formatCompareMarkdown(cmp, clauseDiff);
    expect(md).toContain("# Comparison: v1.txt → v2.txt");
    expect(md).toContain("| Introduced | 1 (1C 0W 0I) |");
    expect(md).toContain("### Introduced findings");
    expect(md).toContain("[CRITICAL] RISK-002");
    expect(md).toContain("## Document redline");
    expect(md).toContain("1 rewritten");
    // Inline redline: the changed amount is struck and re-added.
    expect(md).toContain("~~$1,000,000.~~");
    expect(md).toContain("**$5,000,000.**");
  });

  it("omits the introduced-findings section when none were introduced", async () => {
    const cmp = await compareRuns(
      makeRun("a", "b".repeat(64), []),
      makeRun("b", "r".repeat(64), []),
    );
    const md = formatCompareMarkdown(cmp, buildClauseDiff(docTree("Same."), docTree("Same.")));
    expect(md).not.toContain("### Introduced findings");
    expect(md).toContain("0 rewritten · 0 added · 0 removed");
  });

  it("appends a posture-movement section only when a movement is supplied (spec-v11)", async () => {
    const cmp = await compareRuns(
      makeRun("a", "b".repeat(64), []),
      makeRun("b", "r".repeat(64), []),
    );
    const diff = buildClauseDiff(docTree("Same."), docTree("Same."));
    expect(formatCompareMarkdown(cmp, diff)).not.toContain("Negotiation posture movement");

    const mkPosture = (map: Record<string, NegotiationTier>): NegotiationPosture => ({
      positions: Object.entries(map).map(([dimension, tier]) => ({ dimension, tier })),
      counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
      posture_hash: "x",
    });
    const movement = await comparePosture(
      mkPosture({ "Liability cap": "below-acceptable", "Governing law": "ideal" }),
      mkPosture({ "Liability cap": "acceptable", "Governing law": "acceptable" }),
    );
    const md = formatCompareMarkdown(cmp, diff, movement);
    expect(md).toContain("## Negotiation posture movement");
    expect(md).toContain(`Movement hash: \`${movement.movement_hash}\``);
    expect(md).toContain("| Liability cap | improved | below floor | acceptable |");
    expect(md).toContain("| Governing law | regressed | ideal | acceptable |");
  });
});

describe("formatPostureMovementMarkdown (spec-v11)", () => {
  it("renders the summary line, hash, and a per-dimension table", async () => {
    const mkPosture = (map: Record<string, NegotiationTier>): NegotiationPosture => ({
      positions: Object.entries(map).map(([dimension, tier]) => ({ dimension, tier })),
      counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
      posture_hash: "x",
    });
    const movement = await comparePosture(
      mkPosture({ Indemnity: "unevaluable" }),
      mkPosture({ Indemnity: "below-acceptable" }),
    );
    const md = formatPostureMovementMarkdown(movement);
    expect(md).toContain("## Negotiation posture movement");
    expect(md).toContain("1 newly stated");
    expect(md).toContain("| Indemnity | newly stated | not stated | below floor |");
  });
});

// --- end-to-end over the real engine ---------------------------------------

describe("runCompare (integration)", () => {
  const writes: string[] = [];
  let spy: ReturnType<typeof vi.spyOn>;

  afterEach(() => {
    spy?.mockRestore();
    writes.length = 0;
    process.exitCode = undefined;
  });

  it("emits a valid comparison JSON with a clause_diff over two real files", async () => {
    vi.setConfig({ testTimeout: 30_000 });
    const dir = await mkdtemp(join(tmpdir(), "vaulytica-compare-"));
    try {
      const baseText =
        "MUTUAL NONDISCLOSURE AGREEMENT\n\nThe term of this Agreement is one (1) year.\n";
      const revisedText =
        "MUTUAL NONDISCLOSURE AGREEMENT\n\nThe term of this Agreement is three (3) years.\n";
      const basePath = join(dir, "base.txt");
      const revPath = join(dir, "revised.txt");
      await writeFile(basePath, baseText);
      await writeFile(revPath, revisedText);

      spy = vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
        writes.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString());
        return true;
      });
      await runCompare([basePath, revPath, "--format", "json"]);
      spy.mockRestore();

      const parsed = JSON.parse(writes.join(""));
      expect(parsed.kind).toBe("vaulytica-comparison");
      expect(parsed.clause_diff).toBeDefined();
      // The term clause was rewritten "one (1) year" → "three (3) years".
      expect(parsed.clause_diff.changed.length).toBeGreaterThanOrEqual(1);
      expect(parsed.result_hash).toMatch(/^[0-9a-f]{64}$/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
