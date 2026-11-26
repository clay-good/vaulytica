/**
 * CHOICE-004 — venue / governing-law mismatch.
 *
 * `wire-jurisdiction-id-resolution` task 6. CHOICE-004 had no test file of its
 * own; it was exercised only through CHOICE-003's and CHOICE-012's suites,
 * which is how its `jurisdiction_id` branch went unexamined.
 *
 * 🚨 **What this file records about that branch.** Until this change
 * `jurisdiction_id` was `undefined` on every reference the product produced, so
 * the branch could not fire at all. It is now populated — and it still fires on
 * no document in the corpus. Measured over the 363 specimens plus the 14
 * liveness fixtures: 149 documents carry both a governing-law and a venue
 * clause, 147 of them have IDENTICAL `raw_text` on the two (the venue capture
 * resolves to the state, not the courthouse city, so CHOICE-004 returns at the
 * raw compare before the ids are read), and the remaining 2 name genuinely
 * different states. **Zero documents reach the id branch.**
 *
 * So the branch is tested here at the unit level with a hand-built context,
 * and that is stated rather than disguised: a fixture engineered to reach it
 * would prove the fixture, not the product. This is the liveness-vs-calibration
 * line from `enforce-rule-liveness`, applied one level down — to a BRANCH
 * inside a live rule rather than to a rule inside the catalog.
 */
import { describe, expect, it } from "vitest";
import { rule as CHOICE_004 } from "./CHOICE-004.js";
import { buildContext } from "../../_test-fixtures.js";
import type { RuleContext } from "../../finding.js";
import type { JurisdictionReference } from "../../../extract/types.js";

const ref = (
  clause_kind: JurisdictionReference["clause_kind"],
  raw_text: string,
  jurisdiction_id?: string,
): JurisdictionReference => ({
  clause_kind,
  raw_text,
  ...(jurisdiction_id === undefined ? {} : { jurisdiction_id }),
  position: { section_id: "s1", start: 0, end: raw_text.length },
});

/** A context whose jurisdiction references are exactly `refs`. */
function withJurisdictions(refs: JurisdictionReference[]): RuleContext {
  const base = buildContext(["Governing Law", "Governed by Delaware law. Venue in Delaware."]);
  return { ...base, extracted: { ...base.extracted, jurisdictions: refs } };
}

describe("CHOICE-004 — venue / governing-law mismatch", () => {
  it("fires when the governing law and the venue name different states", () => {
    const f = CHOICE_004.check(
      withJurisdictions([
        ref("governing-law", "Delaware", "us-de"),
        ref("venue", "New York", "us-ny"),
      ]),
    );
    expect(f).not.toBeNull();
    expect(f!.title).toContain("Delaware");
    expect(f!.title).toContain("New York");
  });

  it("stands down when the two raw texts are identical", () => {
    expect(
      CHOICE_004.check(
        withJurisdictions([
          ref("governing-law", "Delaware", "us-de"),
          ref("venue", "Delaware", "us-de"),
        ]),
      ),
    ).toBeNull();
  });

  it("stands down when the raw texts differ but the ids agree", () => {
    // The branch this file exists for. Two spellings of one state is not a
    // law/forum split, and reporting it as one is a false positive. No corpus
    // document produces this shape — see the header.
    expect(
      CHOICE_004.check(
        withJurisdictions([
          ref("governing-law", "Delaware law", "us-de"),
          ref("venue", "the State of Delaware", "us-de"),
        ]),
      ),
    ).toBeNull();
  });

  it("still fires when the raw texts differ and only one id resolved", () => {
    // The honest-N/A path must not suppress: an unresolved id is "unknown",
    // never "the same". 🚨 Had the branch been written `gov.jurisdiction_id
    // === venue.jurisdiction_id` without the two presence checks, two
    // unresolved references would compare `undefined === undefined` and
    // silence every mismatch the resolver does not cover — which is every
    // non-US document the tool handles.
    expect(
      CHOICE_004.check(
        withJurisdictions([ref("governing-law", "England and Wales"), ref("venue", "Ireland")]),
      ),
    ).not.toBeNull();
    expect(
      CHOICE_004.check(
        withJurisdictions([ref("governing-law", "Delaware", "us-de"), ref("venue", "Ireland")]),
      ),
    ).not.toBeNull();
  });

  it("stands down when either clause is missing", () => {
    expect(
      CHOICE_004.check(withJurisdictions([ref("governing-law", "Delaware", "us-de")])),
    ).toBeNull();
    expect(CHOICE_004.check(withJurisdictions([ref("venue", "Delaware", "us-de")]))).toBeNull();
  });
});
