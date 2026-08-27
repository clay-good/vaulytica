/**
 * Nine presence rules whose own `missing_description` asserts a conjunction
 * while the implementation was a synonym OR.
 *
 * The boilerplate-reachability sweep in `v5/title-vacuity.test.ts` found the
 * same shape across the v5 and v6 packs; these are its v3/v4 counterparts,
 * narrowed by a signal the pack rules do not have — the rule's own
 * user-visible sentence. "No clause was found stating position, start date,
 * **and** base compensation" was satisfied by the word "Title" in a signature
 * block; "identifying the testator **and** domicile" by "State of Delaware" in
 * a governing-law clause; "identifying the assignor **and** assignee" by the
 * word "parties" in any recital. Each could be satisfied by a document made of
 * nothing but execution boilerplate, so it could never report the clause it
 * exists to require.
 *
 * The rest of the v3/v4 multi-pattern presence rules were left alone
 * deliberately: their `missing_description` reads "No signature / date /
 * statutory-form recital was found", and the slashes say what the code says —
 * those really are synonym sets. Widening them would invent findings.
 *
 * Both directions are pinned for each rule, because turning an OR into a
 * conjunction makes a check STRICTER, and a rule that fires on a compliant
 * document is worse than one that never fires.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { V3_RULES, V4_RULES } from "../../index.js";

const ALL = [...V3_RULES, ...V4_RULES];
const rule = (id: string) => {
  const r = ALL.find((x) => x.id === id);
  if (!r) throw new Error(`no rule ${id}`);
  return r;
};

/** Execution language every real document carries, and nothing substantive. */
const BOILERPLATE = [
  "This document constitutes the entire agreement between the parties and supersedes all prior discussions. It may be amended only by a written agreement signed by both parties.",
  "Any notice under this document must be in writing and is effective upon receipt.",
  "This document is governed by the laws of the State of Delaware.",
  "IN WITNESS WHEREOF, the parties have duly executed and signed this document by their authorized representatives.",
];

const doc = (...paras: string[]) =>
  buildContext(
    ["Agreement", ...paras],
    ["Signatures", "By: ____ Name: ____ Title: ____ Date: ____"],
  );

/** [rule id, a clause carrying every pillar, a clause carrying only one] */
const CASES: Array<[string, string, string]> = [
  [
    "BNK-019",
    "Debtor represents that it owns the Collateral and holds good title to it, free and clear of all liens, security interests, and encumbrances other than Permitted Liens.",
    "Debtor represents that it owns the Collateral.",
  ],
  [
    "POL-005",
    "Employees shall comply with all applicable laws, regulations, and rules governing the Company's business.",
    "Employees shall comply with the Company's internal handbook and its stated expectations.",
  ],
  [
    "EMP-001",
    "Your title is Director of Engineering. Your duties include leading the platform team, and you will report to the Chief Technology Officer.",
    "Your title is Director of Engineering.",
  ],
  [
    "EMP-009",
    "Your position is Director of Engineering, your start date is March 2, 2026, and your base salary is $210,000 per year.",
    "Your position is Director of Engineering.",
  ],
  [
    "INS-013",
    "For purposes of this Article, the Indemnitor is Halloran Precision Castings, LLC and the Indemnitee is Ridgeline Aerospace Components, Inc.",
    "The parties to this Article are named in the preamble.",
  ],
  [
    "INS-017",
    "The Indemnitee shall give the Indemnitor prompt written notice of any claim, shall tender the defense of the claim to the Indemnitor, and shall cooperate with the Indemnitor in the defense. The Indemnitor has the right to control the defense and the Indemnitee shall not settle without its consent to settle.",
    "The Indemnitee shall give the Indemnitor prompt written notice of any claim.",
  ],
  [
    "IPL-001",
    "Assignor is Northgate Instrument Company and Assignee is Cardinal Metrology, Inc.",
    "The parties to this assignment are named in the preamble.",
  ],
  [
    "EST-001",
    "I, Dermot Halloran, a resident of and domiciled in Franklin County, Ohio, declare this to be my Last Will and Testament.",
    "I am a resident of Franklin County.",
  ],
  [
    "EST-046",
    "This Agreement is made between the spouses, Priya Raghunathan and Soren Lindqvist, who are married to each other, and it governs property acquired during the marriage.",
    "This Agreement is made between the parties named above.",
  ],
];

describe("presence rules whose own text asserts a conjunction", () => {
  it.each(CASES)("%s stays silent when every pillar is present", (id, compliant) => {
    const finding = rule(id).check(doc(compliant, ...BOILERPLATE));
    expect(finding, `${id} flagged a compliant clause: ${finding?.title ?? ""}`).toBeNull();
  });

  it.each(CASES)("%s fires when only one pillar is present", (id, _compliant, partial) => {
    // No boilerplate here, deliberately. `require_all_present` is evaluated
    // over the WHOLE document, so a pillar can be satisfied from an unrelated
    // paragraph — POL-005's law-noun pillar is satisfied by the governing-law
    // clause several paragraphs away. That is the conjunction working as
    // designed (the clause it wants may legitimately be split across a
    // section), but it means the partial-clause direction has to be isolated
    // to test anything.
    const finding = rule(id).check(doc(partial));
    expect(finding, `${id} did not fire on a clause missing a pillar`).not.toBeNull();
  });

  it.each(CASES)("%s fires on execution boilerplate alone", (id) => {
    const finding = rule(id).check(doc(...BOILERPLATE));
    expect(finding, `${id} is satisfied by boilerplate, so it cannot fire`).not.toBeNull();
  });
});
