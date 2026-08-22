import { describe, expect, it } from "vitest";
import {
  computeScoreboard,
  precision,
  recall,
  f1,
  worstByPrecision,
  worstByRecall,
  type GradedDocument,
} from "./metrics.js";

function doc(
  id: string,
  fired: string[],
  gold: Record<string, "should_fire" | "should_not_fire">,
  opts: { high_confidence?: boolean; bootstrap?: boolean } = {},
): GradedDocument {
  return {
    corpus_doc_id: id,
    playbook_id: "pb",
    fired_rule_ids: new Set(fired),
    gold: new Map(Object.entries(gold)),
    high_confidence: opts.high_confidence ?? true,
    bootstrap: opts.bootstrap ?? false,
  };
}

describe("metric primitives (spec-v5 §8)", () => {
  it("precision/recall/f1 are null when their denominator is 0", () => {
    expect(precision({ tp: 0, fp: 0, fn: 3, tn: 1 })).toBeNull();
    expect(recall({ tp: 0, fp: 2, fn: 0, tn: 1 })).toBeNull();
    expect(f1({ tp: 0, fp: 0, fn: 0, tn: 5 })).toBeNull();
  });

  it("computes the textbook values", () => {
    const c = { tp: 8, fp: 2, fn: 4, tn: 6 };
    expect(precision(c)).toBeCloseTo(0.8, 10);
    expect(recall(c)).toBeCloseTo(8 / 12, 10);
    expect(f1(c)).toBeCloseTo((2 * 0.8 * (8 / 12)) / (0.8 + 8 / 12), 10);
  });
});

describe("computeScoreboard confusion model (spec-v5 §8)", () => {
  it("classifies TP / FP / FN / TN against gold", () => {
    const board = computeScoreboard([
      doc("d1", ["R1", "R2"], { R1: "should_fire", R2: "should_not_fire", R3: "should_fire" }),
      // d1: R1 fired+should → TP; R2 fired+should_not → FP; R3 not-fired+should → FN
    ]);
    const r1 = board.per_rule.find((r) => r.rule_id === "R1")!;
    const r2 = board.per_rule.find((r) => r.rule_id === "R2")!;
    const r3 = board.per_rule.find((r) => r.rule_id === "R3")!;
    expect(r1).toMatchObject({ tp: 1, fp: 0, fn: 0, tn: 0 });
    expect(r2).toMatchObject({ tp: 0, fp: 1, fn: 0, tn: 0 });
    expect(r3).toMatchObject({ tp: 0, fp: 0, fn: 1, tn: 0 });
    expect(board.totals).toEqual({ tp: 1, fp: 1, fn: 1, tn: 0 });
  });

  it("treats gold silence on a fired rule as a false positive (closed-world)", () => {
    const board = computeScoreboard([doc("d1", ["R9"], { R1: "should_fire" })]);
    // R9 fired but gold never mentions it → FP. R1 expected but not fired → FN.
    expect(board.per_rule.find((r) => r.rule_id === "R9")).toMatchObject({ fp: 1 });
    expect(board.per_rule.find((r) => r.rule_id === "R1")).toMatchObject({ fn: 1 });
  });

  it("ignores a rule that neither fired nor was annotated (out of scope)", () => {
    const board = computeScoreboard([doc("d1", ["R1"], { R1: "should_fire" })]);
    expect(board.per_rule.map((r) => r.rule_id)).toEqual(["R1"]);
  });

  it("excludes bootstrap docs from all counts but reports the pair count", () => {
    const board = computeScoreboard([
      doc("real", ["R1"], { R1: "should_fire" }),
      doc("boot", ["R1"], { R1: "should_not_fire" }, { bootstrap: true }),
    ]);
    expect(board.graded_pairs).toBe(1);
    expect(board.bootstrap_pairs).toBe(1);
    expect(board.totals).toEqual({ tp: 1, fp: 0, fn: 0, tn: 0 });
  });

  it("flags a rule graded only on low-confidence docs as unmeasured", () => {
    const board = computeScoreboard([
      doc("d1", ["R1"], { R1: "should_fire" }, { high_confidence: false }),
    ]);
    expect(board.unmeasured_rule_ids).toContain("R1");
    expect(board.per_rule.find((r) => r.rule_id === "R1")!.low_confidence).toBe(true);
  });

  it("computes macro and micro averages distinctly", () => {
    // R1: 1 TP (P=1). R2: 1 FP + 0 TP across two docs (P=0).
    const board = computeScoreboard([
      doc("d1", ["R1"], { R1: "should_fire" }),
      doc("d2", ["R2"], { R2: "should_not_fire" }),
    ]);
    // micro precision = TP/(TP+FP) = 1/(1+1) = 0.5
    expect(board.averages.micro.precision).toBeCloseTo(0.5, 10);
    // macro precision = mean(1, 0) = 0.5 here, but is computed over per-rule
    expect(board.averages.macro.precision).toBeCloseTo(0.5, 10);
  });

  it("is deterministic — two runs byte-identical", () => {
    const input = [doc("d1", ["R1", "R2"], { R1: "should_fire", R2: "should_not_fire" })];
    expect(JSON.stringify(computeScoreboard(input))).toBe(JSON.stringify(computeScoreboard(input)));
  });

  it("sorts worst-offenders deterministically", () => {
    const board = computeScoreboard([
      doc("d1", ["LOWP"], { LOWP: "should_not_fire" }), // P=0
      doc("d2", ["HIGHP"], { HIGHP: "should_fire" }), // P=1
      doc("d3", [], { MISS: "should_fire" }), // R=0
    ]);
    expect(worstByPrecision(board, 1)[0]?.rule_id).toBe("LOWP");
    expect(worstByRecall(board, 1)[0]?.rule_id).toBe("MISS");
  });
});

describe("computeScoreboard — an unmeasured rule stays out of the headline", () => {
  // `buildScoreboard`'s own note tells the reader that rules with no
  // κ-confident grading document are "excluded from the headline (reported as
  // unmeasured)". They were not: `totals` and the macro arrays were
  // accumulated before `low_confidence` was computed, so a single unverified
  // annotator's one false positive published a headline precision of 0%.
  // Publishing a number the evidence does not support is the dishonesty this
  // harness exists to prevent.
  it("excludes a low-confidence rule's counts from totals and the averages", () => {
    const docs: GradedDocument[] = [
      {
        corpus_doc_id: "d1",
        playbook_id: "p1",
        fired_rule_ids: new Set(["R1"]),
        gold: new Map([["R1", "should_not_fire"]]),
        high_confidence: false,
        bootstrap: false,
      },
    ];
    const board = computeScoreboard(docs);

    expect(board.unmeasured_rule_ids).toEqual(["R1"]);
    expect(board.totals).toEqual({ tp: 0, fp: 0, fn: 0, tn: 0 });
    expect(board.averages.micro.precision).toBeNull();
    expect(board.averages.macro.precision).toBeNull();

    // Still reported per-rule, with its counts intact and the flag set — the
    // point is that it is visible but not published as a headline number.
    const r1 = board.per_rule.find((r) => r.rule_id === "R1")!;
    expect(r1.low_confidence).toBe(true);
    expect(r1.fp).toBe(1);
  });

  it("still counts a κ-confident rule in the headline", () => {
    const docs: GradedDocument[] = [
      {
        corpus_doc_id: "d1",
        playbook_id: "p1",
        fired_rule_ids: new Set(["R1"]),
        gold: new Map([["R1", "should_fire"]]),
        high_confidence: true,
        bootstrap: false,
      },
    ];
    const board = computeScoreboard(docs);
    expect(board.unmeasured_rule_ids).toEqual([]);
    expect(board.totals.tp).toBe(1);
    expect(board.averages.micro.precision).toBe(1);
  });
});

describe("computeScoreboard — a mixed-confidence rule publishes only its confident counts", () => {
  // Excluding rules with ZERO κ-confident documents narrowed the leak without
  // closing it. Confidence is a property of the grading DOCUMENT, so a rule
  // with one verified document and one single-annotator document was treated
  // as measured and had BOTH documents' counts folded into the headline —
  // publishing exactly the unverified evidence the κ gate exists to hold back.
  it("drops the unverified document's counts from totals and the averages", () => {
    const docs: GradedDocument[] = [
      {
        corpus_doc_id: "d1",
        playbook_id: "p1",
        fired_rule_ids: new Set(["R1"]),
        gold: new Map([["R1", "should_fire"]]),
        high_confidence: true,
        bootstrap: false,
      },
      {
        corpus_doc_id: "d2",
        playbook_id: "p1",
        fired_rule_ids: new Set(["R1"]),
        gold: new Map([["R1", "should_not_fire"]]),
        high_confidence: false,
        bootstrap: false,
      },
    ];
    const board = computeScoreboard(docs);

    // The rule IS measured — it has a κ-confident document.
    expect(board.unmeasured_rule_ids).toEqual([]);
    // ...but only that document's counts reach the headline.
    expect(board.totals).toEqual({ tp: 1, fp: 0, fn: 0, tn: 0 });
    expect(board.averages.micro.precision).toBe(1);
    expect(board.averages.macro.precision).toBe(1);

    // per_rule still carries the FULL picture, including the unverified FP, so
    // the split is about what gets published — nothing is hidden.
    const r1 = board.per_rule.find((r) => r.rule_id === "R1")!;
    expect(r1.tp).toBe(1);
    expect(r1.fp).toBe(1);
    expect(r1.graded_docs).toBe(2);
  });
});
