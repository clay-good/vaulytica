/**
 * Attorney review queue generator (add-attorney-review-ledger, task 2).
 *
 * Unit tests pin the ranking contract (severity × firing frequency, signed
 * rules excluded, deterministic total order); the golden guard pins the
 * committed `docs/legal-basis/review-queue.md` to the generator, so a rule or
 * scoreboard change that isn't regenerated fails CI with `npm run queue:legal`.
 */

import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

import type { Rule, Severity } from "../../src/engine/index.js";
import { buildReviewQueue, generateReviewQueue, QUEUE_PATH, QUEUE_LIMIT } from "./queue.js";

/** Minimal Rule stub — only the fields the queue reads. */
function rule(id: string, severity: Severity, citations: string[] = []): Rule {
  return {
    id,
    version: "1.0.0",
    name: `Rule ${id}`,
    category: "test",
    default_severity: severity,
    description: "",
    dkb_citations: citations,
    check: () => null,
  };
}

describe("buildReviewQueue — severity × firing frequency", () => {
  it("ranks critical over warning over info when firing is uniform", () => {
    const rules = [rule("C1", "critical"), rule("W1", "warning"), rule("I1", "info")];
    const q = buildReviewQueue(rules, new Map(), new Set());
    expect(q.map((e) => e.rule_id)).toEqual(["C1", "W1", "I1"]);
    expect(q.map((e) => e.rank)).toEqual([1, 2, 3]);
  });

  it("firing frequency multiplies severity weight", () => {
    // A warning firing on 2 docs: 2×(1+2)=6, beats a critical firing on 0: 3×1=3.
    const rules = [rule("C0", "critical"), rule("W2", "warning")];
    const q = buildReviewQueue(rules, new Map([["W2", 2]]), new Set());
    expect(q.map((e) => e.rule_id)).toEqual(["W2", "C0"]);
    expect(q.find((e) => e.rule_id === "W2")?.score).toBe(6);
    expect(q.find((e) => e.rule_id === "C0")?.score).toBe(3);
  });

  it("breaks ties on rule_id ascending (deterministic total order)", () => {
    const rules = [rule("B", "warning"), rule("A", "warning"), rule("C", "warning")];
    const q = buildReviewQueue(rules, new Map(), new Set());
    expect(q.map((e) => e.rule_id)).toEqual(["A", "B", "C"]);
  });

  it("excludes rules already signed in the ledger", () => {
    const rules = [rule("C1", "critical"), rule("C2", "critical")];
    const q = buildReviewQueue(rules, new Map(), new Set(["C1"]));
    expect(q.map((e) => e.rule_id)).toEqual(["C2"]);
  });

  it("respects the top-N limit", () => {
    const rules = Array.from({ length: 250 }, (_, i) =>
      rule(`R${String(i).padStart(3, "0")}`, "warning"),
    );
    const q = buildReviewQueue(rules, new Map(), new Set());
    expect(q).toHaveLength(QUEUE_LIMIT);
    expect(q[q.length - 1]?.rank).toBe(QUEUE_LIMIT);
  });

  it("carries each rule's DKB citations through for the reviewer", () => {
    const q = buildReviewQueue([rule("X", "info", ["node-a", "node-b"])], new Map(), new Set());
    expect(q[0]?.citations).toEqual(["node-a", "node-b"]);
  });
});

describe("committed review-queue.md is current with the generator", () => {
  it("matches `npm run queue:legal` output (run it if this fails)", async () => {
    const committed = await readFile(QUEUE_PATH, "utf8");
    const generated = (await generateReviewQueue()) + "\n";
    expect(committed).toBe(generated);
  });

  it("is deterministic (same inputs → byte-identical)", async () => {
    const [a, b] = await Promise.all([generateReviewQueue(), generateReviewQueue()]);
    expect(a).toBe(b);
  });
});
