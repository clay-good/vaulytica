/**
 * A document that ADOPTS a standard form in full does not restate the form's
 * clauses, and is not missing them.
 *
 * An executed EU SCC Module Two set is a cover page, a list of option
 * selections, and three completed annexes. Re-running the Article 28(3)
 * ruleset against one found none of the words and reported ten of the clauses
 * missing at CRITICAL on a form that satisfies every one — the same shape of
 * false accusation `amendsParentAgreement` was written for, with the
 * Commission Implementing Decision as the parent.
 *
 * The gate is applied PER RULE, and these tests pin both halves of that: the
 * clauses the form supplies go quiet, and the checks for the form's own
 * annexes — the one thing it cannot supply about itself — still fire.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { DPA_GDPR_RULES } from "./dpa-gdpr/rules.js";
import { TRANSFER_RULES } from "./transfer/rules.js";
import type { RuleContext } from "../../finding.js";

const ADOPTION =
  "The parties named in Annex I.A adopt the standard contractual clauses annexed to Commission Implementing Decision (EU) 2021/914, Module Two, in full and without amendment other than the completion of the Annexes.";

function sccContext(body: string[]): RuleContext {
  const base = buildContext(["Standard Contractual Clauses", ...body] as [string, ...string[]]);
  return { ...base, playbook: { ...base.playbook, id: "scc-module-2" } };
}

const fired = (ctx: RuleContext, ids: string[]): string[] =>
  [...DPA_GDPR_RULES, ...TRANSFER_RULES]
    .filter((r) => ids.includes(r.id))
    .filter((r) => r.check(ctx) !== null)
    .map((r) => r.id);

/** The Article 28(3) clauses and the per-clause SCC checks the form supplies. */
const SUPPLIED = [
  "DPA-006",
  "DPA-007",
  "DPA-013",
  "DPA-017",
  "DPA-024",
  "DPA-041",
  "TRANSFER-001",
  "TRANSFER-002",
  "TRANSFER-008",
];

/** What the form cannot supply about itself. */
const NOT_SUPPLIED = ["DPA-039", "DPA-040"];

describe("a standard form adopted in full", () => {
  it("supplies the clauses it contains", () => {
    expect(fired(sccContext([ADOPTION, "ANNEX II", "ANNEX III"]), SUPPLIED)).toEqual([]);
  });

  it("still reports the annexes it does not carry", () => {
    expect(fired(sccContext([ADOPTION]), NOT_SUPPLIED).sort()).toEqual(NOT_SUPPLIED);
  });

  it("does not excuse a document that merely MENTIONS the clauses", () => {
    // "The parties will enter into the standard contractual clauses if a
    // transfer occurs" has adopted nothing. Without the in-full qualifier an
    // ordinary DPA that name-drops the SCCs for its transfer clause would be
    // excused from stating its own Article 28(3) terms.
    const ctx = sccContext([
      "If a transfer to a third country occurs, the parties will enter into the standard contractual clauses.",
    ]);
    expect(fired(ctx, SUPPLIED).length).toBeGreaterThan(0);
  });

  it("does not excuse a document routed to an ordinary DPA family", () => {
    const base = buildContext(["Data Processing Addendum", ADOPTION]);
    const ctx: RuleContext = {
      ...base,
      playbook: { ...base.playbook, id: "dpa-controller-processor" },
    };
    expect(fired(ctx, SUPPLIED).length).toBeGreaterThan(0);
  });
});

describe("the adoption sentence is read in either order", () => {
  // The Commission's wording puts the verb first — "the parties adopt the
  // standard contractual clauses … in full". The ICO's puts the NAME first —
  // "The Mandatory Clauses are incorporated in full and without amendment".
  // A single ordered pattern read one and not the other, so the UK IDTA
  // specimen was excused nothing.
  const supplied = ["TRANSFER-020"];
  it("reads the ICO's name-first wording", () => {
    const ctx = sccContext([
      "The Mandatory Clauses are incorporated in full and without amendment, and no Party may amend them other than as Section 18 permits.",
    ]);
    expect(fired(ctx, supplied)).toEqual([]);
  });

  it("reads the Commission's verb-first wording", () => {
    const ctx = sccContext([ADOPTION]);
    expect(fired(ctx, supplied)).toEqual([]);
  });
});
