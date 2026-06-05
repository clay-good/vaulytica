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
});
