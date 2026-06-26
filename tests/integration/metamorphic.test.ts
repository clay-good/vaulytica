import { describe, expect, it } from "vitest";
import { LAUNCH_RULES } from "../../src/engine/rules/index.js";
import { runEngine } from "../../src/engine/runner.js";
import { buildContext } from "../../src/engine/_test-fixtures.js";

/**
 * spec-v7 Part XI (Step 119) — metamorphic invariants.
 *
 * The determinism guard proves "same input → same hash." These prove the
 * stronger, untested property: *which transformations of the input must NOT
 * change the output* — the metamorphic relations that encode what the engine
 * means. A document and a copy of it with non-semantic whitespace noise are
 * different bytes but the same document; the engine must treat them identically.
 * A violation here is not a flaky test — it is a normalizer or rule that has
 * started depending on formatting it should ignore, and the relation localizes
 * exactly which run/finding diverged.
 */

const SRC = { name: "demo.docx", sha256: "0".repeat(64), size_bytes: 100 } as const;

// Representative documents chosen to actually fire rules (placeholders, an
// uncapped-liability clause, a phantom cross-reference, auto-renewal), so the
// invariance is over a non-empty finding set, not a trivially-equal silent run.
const DOCS: [string, ...string[]][][] = [
  [
    [
      "Agreement",
      'This Agreement is between Acme Corp., a Delaware corporation ("Provider"), and Globex Industries, Inc., a New York corporation ("Customer"). Effective Date: 2025-01-01.',
      "Provider shall provide the Services. By: ___ Name: ___ Title: ___ Date: ___",
    ],
  ],
  [
    [
      "Master Services Agreement",
      "The fee is $1,500,000.00. Liability is unlimited and Provider shall indemnify Customer for all losses without limitation. This Agreement renews automatically. See Section 99.4.",
      "Governing law: California. [INSERT VENUE].",
    ],
  ],
];

function run(sections: [string, ...string[]][]) {
  return runEngine({ rules: LAUNCH_RULES, ctx: buildContext(...sections), source_file: SRC });
}

// Replace every space with collapsible whitespace the normalizer folds back to
// a single space (`[ \t\r\n]+` → " "). Internal-only: the fixture strings carry
// no leading/trailing spaces, so the *normalized* text is byte-identical to the
// clean input — only the pre-normalization bytes differ.
const noise = (s: string): string => s.replace(/ /g, "  \t ");
function noised(sections: [string, ...string[]][]): [string, ...string[]][] {
  return sections.map((sec) => sec.map(noise) as [string, ...string[]]);
}

describe("metamorphic invariants (spec-v7 Step 119)", () => {
  it("collapsible-whitespace noise changes neither the result_hash nor the finding set", async () => {
    for (const doc of DOCS) {
      const clean = await run(doc);
      const dirty = await run(noised(doc));
      expect(dirty.result_hash).toBe(clean.result_hash);
      expect(dirty.findings.map((f) => f.rule_id).sort()).toEqual(
        clean.findings.map((f) => f.rule_id).sort(),
      );
    }
  });

  it("inserting a whitespace-only paragraph (the normalizer drops it) changes nothing", async () => {
    for (const doc of DOCS) {
      const clean = await run(doc);
      const [head, ...paras] = doc[0]!;
      // A fully-whitespace paragraph normalizes to zero runs → dropped before it
      // can advance the offset cursor or consume a paragraph index, so the kept
      // paragraphs keep their exact ids and offsets.
      const withBlank: [string, ...string[]][] = [[head, "   \t  ", ...paras], ...doc.slice(1)];
      const augmented = await run(withBlank);
      expect(augmented.result_hash).toBe(clean.result_hash);
    }
  });

  it("a non-empty finding set exists (the invariance is meaningful, not vacuous)", async () => {
    // Guards against the relations above passing only because nothing fired.
    const total = (await Promise.all(DOCS.map(run))).reduce((n, r) => n + r.findings.length, 0);
    expect(total).toBeGreaterThan(0);
  });

  // ── position-only sensitivity (spec-v7 Step 119 follow-up) ──────────────
  //
  // Reordering independent clauses must change finding *positions* but not
  // *which rules fire* — except where order itself is the defect, in which
  // case the order-sensitive rule MUST flip (a positive relation, not just a
  // negative one). Two tests below cover both directions.

  // A document with no dates, so STRUCT-002 ("effective date present") fires
  // regardless of clause order, and whose other findings (uncapped liability,
  // an unfilled placeholder, an undefined defined-term use) are all
  // order-independent — a clean substrate for the invariance direction.
  const ORDER_INVARIANT: [string, ...string[]] = [
    "Services Agreement",
    "Liability is unlimited and Provider shall indemnify Customer for all losses without limitation.",
    "The vendor must complete the [INSERT SCOPE] before acceptance.",
    "All Confidential Information shall be protected at all times.",
  ];

  it("reordering independent clauses keeps the fired-rule set but moves positions", async () => {
    const clean = await run([ORDER_INVARIANT]);
    const [head, ...body] = ORDER_INVARIANT;
    const reversed: [string, ...string[]] = [head, ...body.reverse()];
    const shuffled = await run([reversed]);
    // Same rules fire (order is not the defect here)…
    expect(shuffled.findings.map((f) => f.rule_id).sort()).toEqual(
      clean.findings.map((f) => f.rule_id).sort(),
    );
    // …but the engine is position-aware, not order-blind: moving clauses of
    // different lengths shifts finding offsets, so the run is not identical.
    expect(shuffled.result_hash).not.toBe(clean.result_hash);
  });

  it("when order IS the defect, the order-sensitive rule flips (STRUCT-002)", async () => {
    // STRUCT-002 fires unless an Effective Date is named, defined, or appears
    // as an absolute date in the top 25% of the document. The ONLY date here
    // is "2025-01-01"; its position is the whole signal.
    const filler = [
      "The Provider shall perform the Services with reasonable care and skill.",
      "The Customer shall pay all undisputed fees within thirty days of invoice.",
      "Each party shall keep the other's Confidential Information secret.",
    ];
    const dateTop: [string, ...string[]] = [
      "Agreement",
      "This Agreement is dated 2025-01-01.",
      ...filler,
    ];
    const dateBottom: [string, ...string[]] = [
      "Agreement",
      ...filler,
      "This Agreement is dated 2025-01-01.",
    ];

    const top = await run([dateTop]);
    const bottom = await run([dateBottom]);
    const fired = (r: Awaited<ReturnType<typeof run>>): boolean =>
      r.findings.some((f) => f.rule_id === "STRUCT-002");
    // Date in the top quartile → satisfied → STRUCT-002 silent.
    expect(fired(top)).toBe(false);
    // Same content, date pushed past the quartile → STRUCT-002 fires. The
    // relation is positive: order is the defect, so the rule MUST flip.
    expect(fired(bottom)).toBe(true);
  });
});
